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
#                              connect to this server.
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
    : "${PUBLIC_HOST:?set PUBLIC_HOST to the IP/hostname clients will connect to}"
    : "${VLESS_UUID:?VLESS_UUID missing from .env; rerun ./deploy.sh init or rotate}"

    cat <<EOF
##
## Client-side setup (two processes: sing-rdp-client wraps RDP; sing-box
## speaks VLESS through the wrapper).
##

# --- 1. start the RDP wrapper locally (any platform with a Go binary) ---
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
    rotate)         cmd_rotate "$@" ;;
    ""|help|-h|--help) usage ;;
    *) die "unknown command: $cmd (try './deploy.sh help')" ;;
esac
