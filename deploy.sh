#!/bin/bash
# deploy.sh — opinionated top-level controller for a sing-rdp VPS deployment.
#
# Subcommands:
#
#   ./deploy.sh init           generate Windows-style identity (hostname,
#                              cert, cookie) and write .env. Idempotent —
#                              refuses to overwrite an existing .env unless
#                              FORCE=1.
#   ./deploy.sh up             build image and start the container.
#   ./deploy.sh down           stop the container.
#   ./deploy.sh status         show container state + /healthz JSON.
#   ./deploy.sh logs           tail container logs.
#   ./deploy.sh probe          run the probe sidecar against the running
#                              server (validates the handshake works
#                              end-to-end via a real CredSSP exchange).
#   ./deploy.sh client-config  print the client-side flags needed to
#                              connect to this server. Auto-detects the
#                              VPS's public IP (override with PUBLIC_HOST).
#   ./deploy.sh export-client  copy the linux/amd64 sing-rdp-client binary
#                              out of the runtime image to ./dist/. For
#                              other platforms, build from source.
#   ./deploy.sh build-clients  cross-compile all client binaries to ./dist/:
#                              - sing-rdp-cli.exe              (Windows)
#                              - sing-rdp-cli-macos-{arm64,amd64}
#                              - sing-rdp-cli-linux-amd64
#                              - sing-rdp-client-android-{arm64,armv7}
#                              The .exe / macOS / Linux variants are
#                              all-in-one (SOCKS5+VLESS+RDP, no companion
#                              sing-box needed). Android uses Termux +
#                              NekoBox per docs/mobile-android.md.
#   ./deploy.sh build-mobile   alias for build-clients (legacy).
#   ./deploy.sh rotate         generate a new identity + restart. The old
#                              cookie is invalidated; clients need the new
#                              cookie to reconnect.
#
# Environment overrides:
#   ENV_FILE     path to .env (default: ./.env)
#   CERT_DIR     where cert.pem / key.pem live (default: ./certs)
#   PUBLIC_HOST  the hostname/IP clients will connect to. Required for
#                client-config.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="${ENV_FILE:-./.env}"
CERT_DIR="${CERT_DIR:-./certs}"

# ---------- helpers ----------

die() { echo "deploy: $*" >&2; exit 1; }

# require_tool aborts with a helpful install hint if `name` is not on PATH.
# Optional pkg arg names the apt/dnf package (defaults to the tool name).
require_tool() {
    local name="$1" pkg="${2:-$1}"
    if ! command -v "$name" >/dev/null 2>&1; then
        echo "deploy: missing required tool: $name" >&2
        echo "        install with: apt install -y $pkg   (debian/ubuntu)" >&2
        echo "                  or: dnf install -y $pkg   (rhel/fedora)" >&2
        exit 127
    fi
}

# need_docker verifies both `docker` and the v2 compose plugin (the bundled
# `docker compose` subcommand, not the legacy `docker-compose` binary).
need_docker() {
    require_tool docker docker.io
    if ! docker compose version >/dev/null 2>&1; then
        echo "deploy: 'docker compose' (v2 plugin) is not available" >&2
        echo "        install with: apt install -y docker-compose-plugin" >&2
        echo "        or on older systems use the legacy 'docker-compose' binary" >&2
        echo "        (you'll need to edit this script's compose calls)" >&2
        exit 127
    fi
    # Confirm the daemon is reachable; common failure on first run is the
    # user not being in the docker group, or the daemon not running.
    if ! docker info >/dev/null 2>&1; then
        echo "deploy: docker daemon not reachable" >&2
        echo "        check:  systemctl status docker" >&2
        echo "        and:    groups | grep -q docker  (add user with: usermod -aG docker \$USER)" >&2
        exit 1
    fi
}

# need_http verifies curl is present (for /healthz polling).
need_http() {
    require_tool curl curl
}

# need_identity_tools is required by `init` and `rotate`. Same set the
# generate-identity.sh script needs internally, checked here so we fail
# fast instead of partway through cert generation.
need_identity_tools() {
    require_tool openssl openssl
    require_tool tr coreutils
    require_tool head coreutils
    require_tool sed coreutils
}

need_env() {
    [[ -f "$ENV_FILE" ]] || die "no $ENV_FILE — run './deploy.sh init' first"
    set -a; source "$ENV_FILE"; set +a
}

# detect_public_ip tries a few well-known IP-echo services. Returns the
# first valid IPv4 it gets, or empty if none responded. We try multiple
# providers because any one of them can be blocked or rate-limited from
# the VPS; the fallback chain keeps this working in awkward networks.
detect_public_ip() {
    local ip url
    for url in \
        "https://api.ipify.org" \
        "https://ifconfig.me" \
        "https://icanhazip.com" \
        "https://checkip.amazonaws.com"
    do
        ip=$(curl -fsS -4 --max-time 3 "$url" 2>/dev/null | tr -d '[:space:]')
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

# ---------- commands ----------

cmd_init() {
    need_identity_tools
    ENV_FILE="$ENV_FILE" CERT_DIR="$CERT_DIR" \
        bash docker/generate-identity.sh

    echo
    echo "Next:"
    echo "  1. ./deploy.sh up                     (builds + starts sing-rdp + sing-box)"
    echo "  2. ./deploy.sh status                 (wait until /healthz reports ok:true)"
    echo "  3. PUBLIC_HOST=<vps-ip> ./deploy.sh client-config"
    echo "     (paste the client-side bits into your local sing-box client)"
}

cmd_up() {
    need_docker
    need_env
    # The inner-proxy service mounts singbox-server.json read-only. If the
    # caller ran an old `init` that didn't produce one, fail loudly rather
    # than letting compose start a half-broken stack.
    if [[ ! -f ./singbox-server.json ]]; then
        die "missing ./singbox-server.json — run './deploy.sh rotate' (or './deploy.sh init' on a clean dir) to regenerate identity + inner-proxy config"
    fi
    if [[ -z "${VLESS_UUID:-}" ]]; then
        die "VLESS_UUID missing from .env — run './deploy.sh rotate' to regenerate"
    fi
    # Bring up BOTH services. depends_on ordering ensures sing-box starts first.
    docker compose up -d --build sing-box-inner sing-rdp
    echo
    echo "starting up; check './deploy.sh status' in ~15s"
}

cmd_down() {
    need_docker
    docker compose down
}

cmd_status() {
    need_docker
    need_http
    docker compose ps
    echo
    echo "--- /healthz ---"
    if curl -sf http://127.0.0.1:9180/healthz; then
        echo
    else
        echo "(health endpoint not reachable yet — container may still be starting)"
    fi
}

cmd_logs() {
    need_docker
    # Tails BOTH the transport wrapper and the inner proxy so users see
    # the full picture (auth failures in sing-box land here too).
    docker compose logs -f sing-rdp sing-box-inner
}

cmd_probe() {
    need_docker
    need_env
    docker compose --profile test run --rm sing-rdp-probe
}

cmd_client_config() {
    need_env
    : "${VLESS_UUID:?VLESS_UUID missing from .env; rerun ./deploy.sh init or rotate}"

    # Auto-detect the VPS's public IP when the user didn't override it.
    # Manual override is still respected (e.g. when using a domain name).
    if [[ -z "${PUBLIC_HOST:-}" ]]; then
        need_http
        echo "PUBLIC_HOST not set, auto-detecting via IP-echo services..." >&2
        if PUBLIC_HOST=$(detect_public_ip); then
            echo "detected: PUBLIC_HOST=${PUBLIC_HOST}" >&2
            echo "(override by setting PUBLIC_HOST=... explicitly if wrong)" >&2
            echo >&2
        else
            die "could not auto-detect public IP; set PUBLIC_HOST=<vps-ip-or-domain> explicitly"
        fi
    fi

    # --json emits ONLY the sing-rdp-cli config blob, suitable for piping
    # straight to a file on the client:
    #   ssh vps "./deploy.sh client-config --json" > sing-rdp.json
    if [[ "${1:-}" == "--json" ]]; then
        cat <<EOF
{
  "server":      "${PUBLIC_HOST}:3389",
  "cookie":      "${SING_RDP_COOKIE}",
  "sni":         "${SING_RDP_SNI}",
  "vless_uuid":  "${VLESS_UUID}",
  "local_socks": "127.0.0.1:1080",
  "hostname":    "DESKTOP-CLIENT0",
  "insecure":    true
}
EOF
        return 0
    fi

    cat <<EOF
###############################################################################
# QUICKEST PATH — single-binary Windows/macOS/Linux client (sing-rdp-cli)
###############################################################################
#
# 1. On the VPS, build the clients once:
#      ./deploy.sh build-clients
#    Then copy the right binary to your client device:
#      ./dist/sing-rdp-cli.exe              (Windows)
#      ./dist/sing-rdp-cli-macos-arm64      (Apple Silicon)
#      ./dist/sing-rdp-cli-macos-amd64      (Intel Mac)
#      ./dist/sing-rdp-cli-linux-amd64      (desktop Linux)
#
# 2. Copy this config to a file next to the binary, save as sing-rdp.json:

$(cmd_client_config --json)

# 3. Run the binary:
#      Windows:   sing-rdp-cli.exe -c sing-rdp.json
#      macOS/Lx:  ./sing-rdp-cli-... -c sing-rdp.json
#
# 4. Point your browser at SOCKS5 127.0.0.1:1080
#      Firefox: Settings -> Network -> Manual -> SOCKS v5 host=127.0.0.1 port=1080
#      Chrome:  --proxy-server=socks5://127.0.0.1:1080
#
# Done. One process, one port to remember.


###############################################################################
# ALTERNATE PATH — split mode (sing-rdp-client + your own sing-box)
###############################################################################
#
# Useful if you already run sing-box and want to chain through. The wrapper
# only does the RDP layer; you bring your own VLESS terminator.

# --- 1. start the RDP wrapper locally ---
sing-rdp-client \\
    --local 127.0.0.1:1081 \\
    --remote ${PUBLIC_HOST}:3389 \\
    --cookie ${SING_RDP_COOKIE} \\
    --sni ${SING_RDP_SNI} \\
    --hostname DESKTOP-CLIENT0 \\
    --insecure

# --- 2. paste this into your sing-box client config ---
#        (NekoBox / Streisand / v2rayN / sing-box CLI all accept this shape)
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "out",
      "server": "127.0.0.1",
      "server_port": 1081,
      "uuid": "${VLESS_UUID}",
      "flow": ""
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "inbound": "in", "outbound": "out" }
    ]
  }
}

# --- 3. point your apps at 127.0.0.1:1080 (SOCKS5 + HTTP) ---
#
# Firefox: Settings -> Network -> Manual proxy -> SOCKS v5, 127.0.0.1:1080
# Chrome:  start with --proxy-server=socks5://127.0.0.1:1080
# curl:    curl --socks5 127.0.0.1:1080 https://example.com/
#
# Once you have a patched sing-box client (transport/ behind 'singbox' build
# tag), you can collapse the two-step setup into a single config block —
# the transport: type=rdp wraps the dial natively. Until then this two-step
# is the path that works with off-the-shelf sing-box builds.
EOF
}

cmd_build_clients() {
    require_tool go golang-go
    mkdir -p ./dist

    # Each entry: name|GOOS|GOARCH|extra-env|output|cmd-path
    local targets=(
        # All-in-one Windows CLI (SOCKS5 + VLESS + RDP in one .exe).
        "windows-amd64|windows|amd64||sing-rdp-cli.exe|./cmd/sing-rdp-cli"
        # All-in-one macOS CLI (Apple Silicon + Intel).
        "macos-arm64|darwin|arm64||sing-rdp-cli-macos-arm64|./cmd/sing-rdp-cli"
        "macos-amd64|darwin|amd64||sing-rdp-cli-macos-amd64|./cmd/sing-rdp-cli"
        # All-in-one Linux desktop.
        "linux-amd64|linux|amd64||sing-rdp-cli-linux-amd64|./cmd/sing-rdp-cli"
        # Termux-on-Android (uses sing-rdp-client; pair with NekoBox).
        "android-arm64|linux|arm64||sing-rdp-client-android-arm64|./cmd/sing-rdp-client"
        "android-armv7|linux|arm|GOARM=7|sing-rdp-client-android-armv7|./cmd/sing-rdp-client"
    )

    local entry name os arch extra out cmd
    for entry in "${targets[@]}"; do
        IFS='|' read -r name os arch extra out cmd <<< "$entry"
        echo "building ${name}: $out"
        (
            export GOOS="$os" GOARCH="$arch" CGO_ENABLED=0
            [[ -n "$extra" ]] && eval "export $extra"
            go build -trimpath -ldflags="-s -w" -o "./dist/${out}" "$cmd"
        )
    done

    echo
    echo "built:"
    ls -lh ./dist/sing-rdp-* 2>/dev/null | awk '{print "  "$NF" ("$5")"}'
}

cmd_export_client() {
    need_docker
    if ! docker image inspect sing-rdp:latest >/dev/null 2>&1; then
        die "sing-rdp:latest image not built yet — run './deploy.sh up' first"
    fi
    mkdir -p ./dist
    # The runtime image is linux/amd64. Pull the binary out with a
    # short-lived container; works regardless of whether sing-rdp is
    # currently running.
    docker run --rm \
        -v "$(pwd)/dist:/host" \
        --entrypoint /bin/sh \
        sing-rdp:latest \
        -c 'cp /usr/local/bin/sing-rdp-client /host/sing-rdp-client && chmod +x /host/sing-rdp-client'
    echo
    echo "extracted: ./dist/sing-rdp-client   (linux/amd64)"
    echo
    echo "for other platforms, build from source on the client machine:"
    echo "  git clone <this repo>"
    echo "  cd vpnWrap && go build -o sing-rdp-client ./cmd/sing-rdp-client"
    echo
    echo "or cross-compile from this VPS for your target:"
    echo "  GOOS=darwin GOARCH=arm64 go build -o sing-rdp-client-mac ./cmd/sing-rdp-client"
    echo "  GOOS=windows GOARCH=amd64 go build -o sing-rdp-client.exe ./cmd/sing-rdp-client"
}

cmd_rotate() {
    need_docker
    need_identity_tools
    [[ -f "$ENV_FILE" ]] && {
        local backup="${ENV_FILE}.$(date +%Y%m%d-%H%M%S).bak"
        cp "$ENV_FILE" "$backup"
        echo "backed up old env to $backup"
    }
    FORCE=1 cmd_init
    cmd_down
    cmd_up
    echo
    echo "rotated. clients using the old cookie will need to re-fetch ./deploy.sh client-config"
}

# ---------- dispatch ----------

usage() {
    sed -n '/^# Subcommands:/,/^# Environment overrides:/p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

cmd="${1:-}"
shift || true

case "$cmd" in
    init)           cmd_init "$@" ;;
    up)             cmd_up "$@" ;;
    down)           cmd_down "$@" ;;
    status)         cmd_status "$@" ;;
    logs)           cmd_logs "$@" ;;
    probe)          cmd_probe "$@" ;;
    client-config)  cmd_client_config "$@" ;;
    export-client)  cmd_export_client "$@" ;;
    build-mobile)   cmd_build_clients "$@" ;;  # legacy alias
    build-clients)  cmd_build_clients "$@" ;;
    rotate)         cmd_rotate "$@" ;;
    ""|help|-h|--help) usage ;;
    *) die "unknown command: $cmd (try './deploy.sh help')" ;;
esac
