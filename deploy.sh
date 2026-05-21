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

need_env() {
    [[ -f "$ENV_FILE" ]] || die "no $ENV_FILE — run './deploy.sh init' first"
    set -a; source "$ENV_FILE"; set +a
}

need_docker() {
    command -v docker >/dev/null || die "docker not in PATH"
    docker compose version >/dev/null 2>&1 || die "docker compose plugin not available"
}

# ---------- commands ----------

cmd_init() {
    ENV_FILE="$ENV_FILE" CERT_DIR="$CERT_DIR" \
        bash docker/generate-identity.sh

    echo
    echo "Next:"
    echo "  1. ensure an inner proxy is running on \$SING_RDP_UPSTREAM"
    echo "     (default 127.0.0.1:1080 — point this at a sing-box / xray /"
    echo "      shadowsocks inbound listening on loopback)"
    echo "  2. ./deploy.sh up"
    echo "  3. ./deploy.sh status"
    echo "  4. ./deploy.sh client-config   (then plug into your local client)"
}

cmd_up() {
    need_docker
    need_env
    docker compose up -d --build sing-rdp
    echo
    echo "starting up; check './deploy.sh status' in ~15s"
}

cmd_down() {
    need_docker
    docker compose down
}

cmd_status() {
    need_docker
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
    docker compose logs -f sing-rdp
}

cmd_probe() {
    need_docker
    need_env
    docker compose --profile test run --rm sing-rdp-probe
}

cmd_client_config() {
    need_env
    : "${PUBLIC_HOST:?set PUBLIC_HOST to the IP/hostname clients will connect to}"

    cat <<EOF
# sing-rdp-client connection parameters:
sing-rdp-client \\
    --local 127.0.0.1:1081 \\
    --remote ${PUBLIC_HOST}:3389 \\
    --cookie ${SING_RDP_COOKIE} \\
    --sni ${SING_RDP_SNI} \\
    --hostname DESKTOP-CLIENT0 \\
    --insecure

# Then point your local proxy client (sing-box outbound, browser SOCKS,
# etc.) at 127.0.0.1:1081.

# To save space inside a sing-box config:
#
# "outbounds": [{
#   "type": "vless",
#   "server": "${PUBLIC_HOST}",
#   "server_port": 3389,
#   "uuid": "<your VLESS uuid>",
#   "tls": { "enabled": true, "server_name": "${SING_RDP_SNI}", "insecure": true },
#   "transport": {
#     "type": "rdp",
#     "cookie": "${SING_RDP_COOKIE}",
#     "fingerprint": "mstsc-win11",
#     "hostname": "${SING_RDP_HOSTNAME}"
#   }
# }]
EOF
}

cmd_rotate() {
    need_docker
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
