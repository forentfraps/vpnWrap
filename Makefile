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

# Cross-compile against every target deploy.sh build-clients ships, so 32-bit
# constant-overflow bugs and similar platform-specific issues fail loudly in
# CI instead of waiting until the user runs build-clients.
test-cross:
	@for t in linux/amd64 linux/arm64 linux/arm/7 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$$(echo $$t | cut -d/ -f1); arch=$$(echo $$t | cut -d/ -f2); arm=$$(echo $$t | cut -d/ -f3); \
		echo "==> $$os/$$arch$${arm:+/v$$arm}"; \
		GOOS=$$os GOARCH=$$arch GOARM=$$arm CGO_ENABLED=0 \
			go vet ./cmd/sing-rdp-client ./cmd/sing-rdp-cli ./rdp/... ./health/... ./shape/... || exit 1; \
	done
	@echo "all platforms vet cleanly"

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
