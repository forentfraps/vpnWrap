# syntax=docker/dockerfile:1.6

# ---------- builder ----------
FROM golang:1.22-alpine AS builder
WORKDIR /src

# Cache module downloads first.
COPY go.mod ./
RUN go mod download || true

# Then sources.
COPY . .

# Build statically-linked binaries. CGO off so the binary runs on any libc.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/sing-rdp-server ./cmd/sing-rdp-server \
 && go build -trimpath -ldflags="-s -w" -o /out/sing-rdp-client ./cmd/sing-rdp-client \
 && go build -trimpath -ldflags="-s -w" -o /out/sing-rdp-probe  ./cmd/sing-rdp-probe

# ---------- test stage (runs `go test ./...`) ----------
# Build the test image with: docker build --target test -t sing-rdp:test .
FROM builder AS test
RUN go test -count=1 ./rdp/... ./health/... ./shape/...

# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# xrdp + a minimal X stack + openssl for cert generation.
# `xorgxrdp` is the X11 backend xrdp uses for live sessions.
# `openbox` + `xterm` give us a renderable desktop so a probing client
# sees actual screen updates rather than a blank session.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        xrdp xorgxrdp \
        openbox xterm xclock \
        dbus-x11 \
        ca-certificates openssl tini \
        wget \
 && rm -rf /var/lib/apt/lists/* \
 # Create an unprivileged "cover" user that probes log into.
 && useradd -m -s /bin/bash rdpuser \
 && echo 'rdpuser:rdpuser' | chpasswd \
 # xrdp on its internal port; sing-rdp owns the public one.
 && sed -i 's/^port=.*/port=3390/' /etc/xrdp/xrdp.ini \
 # Don't listen on 3350 sesman publicly either.
 && sed -i 's/^ListenAddress=.*/ListenAddress=127.0.0.1/' /etc/xrdp/sesman.ini

# Idle-cover X session: minimal openbox with a clock so the screen has
# subtle motion (clock seconds tick). This gives a probing observer
# realistic-looking screen updates if they log in.
COPY docker/xsession.sh /home/rdpuser/.xsession
RUN chown rdpuser:rdpuser /home/rdpuser/.xsession \
 && chmod +x /home/rdpuser/.xsession

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

COPY --from=builder /out/sing-rdp-server /usr/local/bin/sing-rdp-server
COPY --from=builder /out/sing-rdp-probe  /usr/local/bin/sing-rdp-probe

# Volumes for certs (mount real cert here in production).
RUN mkdir -p /etc/sing-rdp
VOLUME ["/etc/sing-rdp"]

# 3389 = sing-rdp (public). 9180 = health (bind to loopback inside).
EXPOSE 3389

# Docker-native health check: probe /healthz which runs both a TCP probe
# to xrdp and an in-process RDP handshake against ourselves.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- --tries=1 http://127.0.0.1:9180/healthz | grep -q '"ok":true' || exit 1
# /healthz now reports every component (xrdp, upstream, loopback). The grep
# above checks the aggregate flag; for component-level diagnostics from the
# host:  curl http://127.0.0.1:9180/healthz | jq .

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
