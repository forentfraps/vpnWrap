#!/bin/bash
# Container entrypoint for sing-rdp + xrdp.
#
# Responsibilities:
#   1. Generate a self-signed cert if /etc/sing-rdp/cert.pem doesn't exist
#      (operators should mount a real cert in production).
#   2. Start xrdp on the internal port (3390).
#   3. Start sing-rdp-server on the public port (3389), splicing
#      non-tunnel traffic to xrdp.
#   4. Forward signals to children so docker stop is clean.

set -euo pipefail

CERT=/etc/sing-rdp/cert.pem
KEY=/etc/sing-rdp/key.pem
COOKIE="${SING_RDP_COOKIE:-svc-jumpbox}"
UPSTREAM="${SING_RDP_UPSTREAM:-127.0.0.1:1080}"
LISTEN="${SING_RDP_LISTEN:-:3389}"
HOSTNAME_VAL="${SING_RDP_HOSTNAME:-DESKTOP-UNKNOWN}"
NETBIOS_DOMAIN="${SING_RDP_NETBIOS_DOMAIN:-WORKGROUP}"
DNS_DOMAIN="${SING_RDP_DNS_DOMAIN:-}"

if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
    echo "[entrypoint] no cert mounted; generating Windows-style self-signed"
    mkdir -p /etc/sing-rdp
    # Match Windows-built-in RDP cert: 180-day, sha256RSA, CN only, no SAN.
    # Keep stderr so a failing openssl reports its actual reason instead
    # of leaving us with a half-generated key file and no diagnostic.
    if ! openssl req -x509 -newkey rsa:2048 -sha256 -days 180 -nodes \
        -subj "/CN=${HOSTNAME_VAL}" \
        -keyout "$KEY" -out "$CERT" >/dev/null
    then
        echo "[entrypoint] openssl req failed — cannot continue" >&2
        exit 1
    fi
fi

# xrdp needs /var/run/xrdp.
mkdir -p /var/run/xrdp/sockdir
chown -R xrdp:xrdp /var/run/xrdp

echo "[entrypoint] starting xrdp on 127.0.0.1:3390"
# sesman handles the X server side; xrdp handles the protocol side.
/usr/sbin/xrdp-sesman --nodaemon &
SESMAN_PID=$!

# Give sesman a moment to come up before xrdp tries to talk to it.
sleep 1

/usr/sbin/xrdp --nodaemon &
XRDP_PID=$!

echo "[entrypoint] starting sing-rdp-server on $LISTEN (hostname=${HOSTNAME_VAL} cookie=${COOKIE} upstream=${UPSTREAM})"
/usr/local/bin/sing-rdp-server \
    --listen "$LISTEN" \
    --upstream "$UPSTREAM" \
    --xrdp "127.0.0.1:3390" \
    --cookie "$COOKIE" \
    --hostname "$HOSTNAME_VAL" \
    --netbios-domain "$NETBIOS_DOMAIN" \
    --dns-domain "$DNS_DOMAIN" \
    --cert "$CERT" \
    --key "$KEY" \
    --health "127.0.0.1:9180" &
SING_PID=$!

# Forward TERM/INT to all children.
trap 'kill -TERM $SESMAN_PID $XRDP_PID $SING_PID 2>/dev/null; wait' TERM INT

# Wait on the sing-rdp process specifically — if it dies the container should exit.
wait $SING_PID
exit_code=$?
echo "[entrypoint] sing-rdp-server exited with $exit_code"
kill -TERM $SESMAN_PID $XRDP_PID 2>/dev/null || true
exit $exit_code
