# Convenience targets for development and CI.

.PHONY: build test docker docker-test docker-up docker-probe clean

# Native Go build (cmd binaries only — does not include the sing-box transport,
# which is gated behind the singbox build tag).
build:
	go build -trimpath -o bin/sing-rdp-server ./cmd/sing-rdp-server
	go build -trimpath -o bin/sing-rdp-client ./cmd/sing-rdp-client
	go build -trimpath -o bin/sing-rdp-probe  ./cmd/sing-rdp-probe

test:
	go test -count=1 -race ./rdp/... ./health/... ./shape/...

# Build the runtime image.
docker:
	docker build -t sing-rdp:latest --target runtime .

# Run the in-image unit + handshake tests (builder stage runs them).
docker-test:
	docker build -t sing-rdp:test --target test .

# Bring up the server in compose mode.
docker-up: docker
	docker compose up -d sing-rdp

# Run the probe sidecar against the live server.
docker-probe:
	docker compose --profile test run --rm sing-rdp-probe

clean:
	rm -rf bin/ certs/
