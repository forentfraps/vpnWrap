module github.com/vpnwrap/sing-rdp

go 1.22

// The transport/ package integrates with sing-box and uTLS. It is gated
// behind the `singbox` build tag so the standalone binaries in cmd/ can
// build without pulling those dependencies. To work on transport/:
//
//   go get github.com/sagernet/sing-box@latest
//   go get github.com/sagernet/sing@latest
//   go get github.com/refraction-networking/utls@latest
//   go build -tags singbox ./...
