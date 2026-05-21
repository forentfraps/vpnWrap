#!/bin/bash
# Generates a Windows-like identity for the sing-rdp server:
#
#   - hostname:  DESKTOP-XXXXXXX (7 uppercase alphanumerics, NetBIOS-fitting)
#   - cert:      self-signed, CN matching hostname, 180-day validity,
#                no SAN, sha256WithRSAEncryption — same shape as the
#                cert Windows generates for its built-in RDP service
#   - cookie:    pseudo-username, e.g. "user-1234"
#
# Outputs (env vars exported into stdout when sourced, or written to
# files when invoked):
#
#   $CERT_DIR/cert.pem
#   $CERT_DIR/key.pem
#   $ENV_FILE     (SING_RDP_HOSTNAME, SING_RDP_COOKIE, etc.)

set -euo pipefail

CERT_DIR="${CERT_DIR:-./certs}"
ENV_FILE="${ENV_FILE:-./.env}"
SINGBOX_CONFIG="${SINGBOX_CONFIG:-./singbox-server.json}"
SINGBOX_TEMPLATE="${SINGBOX_TEMPLATE:-$(dirname "$0")/singbox-server.json.tmpl}"
FORCE="${FORCE:-0}"

# require_tool aborts with a helpful message if `name` is not on PATH.
# Optional second arg is the package name to suggest (defaults to the
# tool name itself).
require_tool() {
    local name="$1"
    local pkg="${2:-$1}"
    if ! command -v "$name" >/dev/null 2>&1; then
        echo "missing required tool: $name" >&2
        echo "  install with: apt install -y $pkg   (debian/ubuntu)" >&2
        echo "           or:  dnf install -y $pkg   (rhel/fedora)" >&2
        exit 127
    fi
}

preflight() {
    require_tool tr coreutils
    require_tool head coreutils
    require_tool openssl openssl
    require_tool mkdir coreutils
    require_tool chmod coreutils
    require_tool date coreutils
    require_tool sed sed
    [[ -r /dev/urandom ]] || { echo "no /dev/urandom" >&2; exit 1; }
    # /proc/sys/kernel/random/uuid is a Linux kernel facility; on any Linux
    # build (including the Ubuntu VPSes this targets) it's always present
    # and saves us a dependency on uuid-runtime / python.
    if [[ ! -r /proc/sys/kernel/random/uuid ]]; then
        echo "missing /proc/sys/kernel/random/uuid (not running on Linux?)" >&2
        echo "  install uuid-runtime and edit this script to use 'uuidgen' instead" >&2
        exit 1
    fi
    [[ -f "$SINGBOX_TEMPLATE" ]] || {
        echo "missing sing-box template: $SINGBOX_TEMPLATE" >&2
        exit 1
    }
}

random_hostname() {
    # Windows uses [A-Z0-9] but excludes ambiguous chars (0/O/1/I) on
    # newer builds. We follow that convention.
    #
    # Implementation note: the obvious form
    #     tr -dc '...' </dev/urandom | head -c 7
    # gives `tr` SIGPIPE the instant head closes after 7 bytes — ugly on
    # stderr, fatal under `set -o pipefail`. Fix: use `head -c N` as the
    # *producer* so it terminates naturally; tr reads to EOF and filters;
    # bash slices the result. We can't first store raw bytes in a shell
    # variable (NULs would truncate), so we filter on the stream.
    local filtered
    filtered=$(head -c 256 /dev/urandom | LC_ALL=C tr -dc 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789')
    # 256 random bytes through a 31-char alphabet yields ~31 valid chars
    # on average; <7 is statistically impossible.
    if [[ ${#filtered} -lt 7 ]]; then
        echo "random_hostname: not enough entropy (got ${#filtered} chars)" >&2
        exit 1
    fi
    echo "DESKTOP-${filtered:0:7}"
}

random_cookie() {
    # Common in-the-wild username patterns:
    #   user-1234, svc-rdp, jumpbox, admin
    # We use "user-NNNN" because it's the most generic.
    local n=$((1000 + RANDOM % 9000))
    echo "user-${n}"
}

random_uuid() {
    # Kernel-provided UUIDv4. Always present on Linux, no dep on uuid-runtime.
    cat /proc/sys/kernel/random/uuid
}

render_singbox_config() {
    local uuid="$1"
    # Use sed with a # delimiter to avoid clashes with the / in URLs / paths.
    sed "s#__VLESS_UUID__#${uuid}#g" "$SINGBOX_TEMPLATE" > "$SINGBOX_CONFIG"
    chmod 644 "$SINGBOX_CONFIG"
}

generate_cert() {
    local hostname="$1"
    mkdir -p "$CERT_DIR"
    # Match Windows RDP cert shape:
    #   - sha256WithRSAEncryption  (-sha256 -newkey rsa:2048)
    #   - 180-day validity         (-days 180)
    #   - no SAN, just CN          (-subj "/CN=...", no -addext)
    #   - basicConstraints CA:FALSE is the openssl default when -extensions
    #     isn't passed
    #
    # We suppress openssl's normal progress chatter on stdout but KEEP
    # stderr — when this fails (missing libssl config, permissions, etc.)
    # the user needs to see what went wrong.
    if ! openssl req -x509 \
        -newkey rsa:2048 \
        -sha256 \
        -days 180 \
        -nodes \
        -subj "/CN=${hostname}" \
        -keyout "${CERT_DIR}/key.pem" \
        -out "${CERT_DIR}/cert.pem" \
        >/dev/null
    then
        echo "openssl req failed; cert was not generated" >&2
        return 1
    fi
    chmod 600 "${CERT_DIR}/key.pem"
}

main() {
    preflight

    if [[ -f "$ENV_FILE" && "$FORCE" != "1" ]]; then
        echo "$ENV_FILE already exists; refusing to overwrite (set FORCE=1 to override)" >&2
        exit 1
    fi

    local hostname cookie uuid
    hostname=$(random_hostname)
    cookie=$(random_cookie)
    uuid=$(random_uuid)

    generate_cert "$hostname"
    render_singbox_config "$uuid"

    cat > "$ENV_FILE" <<EOF
# Generated by generate-identity.sh on $(date -u +%FT%TZ)
# Do NOT check this file into source control — it contains secrets that
# gate tunnel access (cookie + VLESS UUID).
SING_RDP_HOSTNAME=${hostname}
SING_RDP_COOKIE=${cookie}
SING_RDP_SNI=${hostname}
SING_RDP_NETBIOS_DOMAIN=WORKGROUP
VLESS_UUID=${uuid}
EOF
    chmod 600 "$ENV_FILE"

    echo "generated identity:"
    echo "  hostname:    ${hostname}"
    echo "  cookie:      ${cookie}"
    echo "  vless uuid:  ${uuid}"
    echo "  cert:        ${CERT_DIR}/cert.pem (CN=${hostname}, 180-day, sha256RSA)"
    echo "  env file:    ${ENV_FILE}"
    echo "  sing-box:    ${SINGBOX_CONFIG}"
}

main "$@"
