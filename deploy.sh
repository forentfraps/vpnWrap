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
#   ./deploy.sh fetch-tun2socks
#                              download tun2socks (xjasonlyu) prebuilt
#                              binaries + write sing-rdp-vpn.bat. Pairs with
#                              sing-rdp-cli.exe for a real TUN-mode VPN.
#                              Pragmatic alternative to sing-rdp-tun while
#                              that source stabilizes upstream.
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
#   ./deploy.sh doctor         run local checks: is sing-rdp listening on
#                              a public interface, is /healthz green, is
#                              UFW allowing 3389, are iptables rules
#                              dropping it. Prints the command for the
#                              external reachability test you should run
#                              from another machine.
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

    # --json emits the sing-rdp-cli (SOCKS5) config blob:
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
    # --json-tun emits the sing-rdp-tun (TUN-mode) config blob:
    #   ssh vps "./deploy.sh client-config --json-tun" > sing-rdp.json
    # auto_route=true: the binary will set the system default route to
    # the TUN device — this is what makes it a "real VPN".
    if [[ "${1:-}" == "--json-tun" ]]; then
        cat <<EOF
{
  "server":      "${PUBLIC_HOST}:3389",
  "cookie":      "${SING_RDP_COOKIE}",
  "sni":         "${SING_RDP_SNI}",
  "vless_uuid":  "${VLESS_UUID}",
  "hostname":    "DESKTOP-CLIENT0",
  "insecure":    true,
  "tun_name":    "singrdp0",
  "tun_address": "172.19.0.1/30",
  "tun_mtu":     1500,
  "auto_route":  true
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

    # Bundle wintun.dll alongside the Windows binaries so the TUN client
    # works out of the box. We pull it from the official WireGuard source.
    # Skip silently if curl isn't available or the download fails — the
    # SOCKS5 .exe still works without wintun.
    if command -v curl >/dev/null 2>&1 && [[ ! -f ./dist/wintun.dll ]]; then
        echo "fetching wintun.dll (for sing-rdp-tun on Windows)..."
        if curl -fsSL -o /tmp/wintun.zip 'https://www.wintun.net/builds/wintun-0.14.1.zip' 2>/dev/null; then
            unzip -p /tmp/wintun.zip 'wintun/bin/amd64/wintun.dll' > ./dist/wintun.dll 2>/dev/null || rm -f ./dist/wintun.dll
            rm -f /tmp/wintun.zip
        fi
    fi

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

    # sing-rdp-tun (Go-native TUN binary) is parked: the sing-tun upstream
    # has been thrashing namespaces (sagernet <-> metacubex) and can't be
    # reliably pinned to a coherent version. The source stays in the repo
    # for future revival; we use tun2socks as the practical bridge instead.
    # See cmd_fetch_tun2socks below.
    :

    # Drop a tiny launcher beside the Windows .exe so users can
    # double-click instead of opening PowerShell. It also pauses on
    # error so a misconfigured json isn't a flash-then-gone console.
    cat > ./dist/sing-rdp-cli.bat <<'BATEOF'
@echo off
REM Tiny launcher for sing-rdp-cli.exe. Place this file next to the .exe
REM and your sing-rdp.json, then double-click to run.

setlocal
cd /d "%~dp0"
if not exist sing-rdp.json (
    echo sing-rdp.json not found in %CD%
    echo Place the config file next to this script and try again.
    pause
    exit /b 1
)
sing-rdp-cli.exe -c sing-rdp.json
echo.
echo (process exited — press any key to close)
pause >nul
BATEOF

    # Note: the launcher for system-wide TUN-mode VPN (sing-rdp-vpn.bat)
    # is written by `./deploy.sh fetch-tun2socks` because it depends on
    # the tun2socks binary being fetched first.
    echo
    echo "built:"
    ls -lh ./dist/sing-rdp-* 2>/dev/null | awk '{print "  "$NF" ("$5")"}'
    echo "  ./dist/sing-rdp-cli.bat  (Windows launcher)"
}

cmd_fetch_tun2socks() {
    require_tool curl curl
    require_tool unzip unzip
    mkdir -p ./dist

    # xjasonlyu/tun2socks is the practical TUN<->SOCKS5 bridge. Stable
    # binaries, MIT licensed, no Go-build hassles on our side. We pull
    # the latest release for each platform we care about.
    #
    # Pin to a known-good tag so builds are reproducible; bump as needed
    # when upstream tags a new release.
    local tag="v2.5.2"
    local base="https://github.com/xjasonlyu/tun2socks/releases/download/${tag}"

    local targets=(
        # platform-suffix in our dist/ | upstream-asset-name
        "windows-amd64.exe|tun2socks-windows-amd64.zip"
        "linux-amd64|tun2socks-linux-amd64.zip"
        "macos-arm64|tun2socks-darwin-arm64.zip"
        "macos-amd64|tun2socks-darwin-amd64.zip"
    )

    local entry suffix asset url tmp
    for entry in "${targets[@]}"; do
        IFS='|' read -r suffix asset <<< "$entry"
        url="${base}/${asset}"
        tmp=$(mktemp -d)
        echo "fetching tun2socks ${tag} for ${suffix}..."
        if ! curl -fsSL -o "$tmp/asset.zip" "$url"; then
            echo "  download failed: $url" >&2
            rm -rf "$tmp"
            continue
        fi
        # Extract; the .zip contains a single binary named like
        # tun2socks-<os>-<arch>[.exe].
        unzip -q -j "$tmp/asset.zip" -d "$tmp"
        local extracted
        extracted=$(find "$tmp" -maxdepth 1 -name 'tun2socks-*' -not -name '*.zip' | head -1)
        if [[ -z "$extracted" ]]; then
            echo "  could not find binary in archive" >&2
            rm -rf "$tmp"
            continue
        fi
        mv "$extracted" "./dist/tun2socks-${suffix}"
        chmod +x "./dist/tun2socks-${suffix}"
        rm -rf "$tmp"
    done

    # Write the Windows launcher that chains sing-rdp-cli + tun2socks.
    # Self-elevates because TUN/Wintun + routing require admin.
    cat > ./dist/sing-rdp-vpn.bat <<'BATEOF'
@echo off
REM Full TUN-mode VPN launcher. Starts sing-rdp-cli (SOCKS5 listener) and
REM tun2socks (TUN<->SOCKS5 bridge) together. Closing the window stops
REM the VPN.

setlocal
cd /d "%~dp0"

REM Self-elevate to administrator (TUN + routing both require it).
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM Sanity checks.
for %%F in (sing-rdp-cli.exe tun2socks-windows-amd64.exe wintun.dll sing-rdp.json) do (
    if not exist %%F (
        echo missing %%F  -- copy it next to this script
        pause
        exit /b 1
    )
)

REM Start the SOCKS5 listener in the background.
echo Starting sing-rdp-cli (SOCKS5 on 127.0.0.1:1080)...
start /b "" sing-rdp-cli.exe -c sing-rdp.json

REM Give it ~2s to bind the socket before tun2socks dials it.
timeout /t 2 /nobreak >nul

REM Start tun2socks. -device wintun creates the TUN interface, -proxy
REM is the SOCKS5 endpoint sing-rdp-cli is listening on.
echo Starting tun2socks (TUN device + system route)...
tun2socks-windows-amd64.exe -device wintun -proxy socks5://127.0.0.1:1080 -loglevel info

REM tun2socks runs in the foreground; when it exits (Ctrl+C / close),
REM tear down sing-rdp-cli too.
echo Stopping sing-rdp-cli...
taskkill /im sing-rdp-cli.exe /f >nul 2>&1
BATEOF

    echo
    echo "fetched:"
    ls -lh ./dist/tun2socks-* ./dist/sing-rdp-vpn.bat 2>/dev/null | awk '{print "  "$NF" ("$5")"}'
    echo
    echo "Combined with the existing sing-rdp-cli.exe + wintun.dll + sing-rdp.json,"
    echo "users now have a one-click TUN VPN. See docs/tun-mode.md for setup."
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

cmd_doctor() {
    need_env
    local port="${SING_RDP_PORT:-3389}"
    local health_port=9180
    local exit_code=0
    local ok="\033[32m✓\033[0m" bad="\033[31m✗\033[0m" warn="\033[33m!\033[0m"

    say() { printf "  %b  %s\n" "$1" "$2"; }

    echo "=== sing-rdp doctor ==="
    echo

    # --- 1. Is the service listening? ---
    echo "[1/5] listener state"
    if ! command -v ss >/dev/null 2>&1; then
        say "$warn" "'ss' not installed — install iproute2 for this check"
    else
        local listen_line
        listen_line=$(ss -tlnH "sport = :${port}" 2>/dev/null | head -1)
        if [[ -z "$listen_line" ]]; then
            say "$bad" "nothing listening on :${port}"
            say "" "  fix: ./deploy.sh up"
            exit_code=1
        elif echo "$listen_line" | grep -qE '127\.0\.0\.1|\[::1\]'; then
            say "$bad" "listening on loopback only — external clients can't reach it"
            say "" "  fix: check SING_RDP_LISTEN env / docker-compose.yml"
            exit_code=1
        else
            say "$ok"  "listening on $(echo "$listen_line" | awk '{print $4}')"
        fi
    fi

    # --- 2. Local handshake works? ---
    echo "[2/5] in-process /healthz"
    if curl -sf --max-time 3 "http://127.0.0.1:${health_port}/healthz" >/dev/null 2>&1; then
        local body; body=$(curl -s "http://127.0.0.1:${health_port}/healthz")
        if echo "$body" | grep -q '"ok":true'; then
            say "$ok" "healthz reports ok:true"
        else
            say "$bad" "healthz reports failure: $body"
            exit_code=1
        fi
    else
        say "$bad" "healthz unreachable on 127.0.0.1:${health_port}"
        exit_code=1
    fi

    # --- 3. UFW status ---
    echo "[3/5] UFW"
    if ! command -v ufw >/dev/null 2>&1; then
        say "$warn" "ufw not installed (probably fine — but no local firewall check)"
    else
        local ufw_state; ufw_state=$(ufw status 2>/dev/null | head -1)
        if echo "$ufw_state" | grep -q "inactive"; then
            say "$ok" "ufw inactive (nothing blocking locally)"
        elif ufw status 2>/dev/null | grep -qE "^${port}/tcp +ALLOW"; then
            say "$ok" "ufw allows ${port}/tcp"
        else
            say "$bad" "ufw is active and no rule allows ${port}/tcp"
            say "" "  fix: ufw allow ${port}/tcp"
            exit_code=1
        fi
    fi

    # --- 4. iptables / Docker chain ---
    echo "[4/5] iptables raw view"
    if command -v iptables >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
        local drops; drops=$(iptables -L INPUT -n 2>/dev/null | grep -E "dpt:${port} *$" | grep -E "DROP|REJECT" || true)
        if [[ -n "$drops" ]]; then
            say "$bad" "INPUT chain rejects ${port}:"
            echo "$drops" | sed 's/^/      /'
            exit_code=1
        else
            say "$ok" "no INPUT-chain DROP/REJECT for ${port}"
        fi
    else
        say "$warn" "skipped (need root + iptables)"
    fi

    # --- 5. External reachability hint ---
    echo "[5/5] external reachability"
    local pub_ip; pub_ip=$(detect_public_ip 2>/dev/null || echo "")
    if [[ -n "$pub_ip" ]]; then
        say "$ok" "public IP = ${pub_ip}"
        echo
        echo "Test from outside (a machine that isn't this VPS):"
        echo "    nc -zv ${pub_ip} ${port}"
        echo "    # or in PowerShell:"
        echo "    Test-NetConnection -ComputerName ${pub_ip} -Port ${port}"
        echo "    # or via web:"
        echo "    https://portchecker.io  (ip=${pub_ip} port=${port})"
    else
        say "$warn" "could not detect public IP"
    fi

    echo
    if [[ $exit_code -eq 0 ]]; then
        echo "verdict: local checks pass."
        echo "         if external probes still fail, the block is one of:"
        echo "           - cloud-provider security group / firewall above the VPS"
        echo "           - upstream ISP / transit blocking"
        echo "           - wrong PUBLIC_HOST"
    else
        echo "verdict: local issues found — fix them and re-run doctor"
    fi
    return $exit_code
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
    fetch-tun2socks) cmd_fetch_tun2socks "$@" ;;
    doctor)         cmd_doctor "$@" ;;
    rotate)         cmd_rotate "$@" ;;
    ""|help|-h|--help) usage ;;
    *) die "unknown command: $cmd (try './deploy.sh help')" ;;
esac
