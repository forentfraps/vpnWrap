// Separate go.mod so the heavy gVisor + sing-tun dependencies don't pollute
// the root module (which the other cmd binaries share). To work on this
// binary in isolation:
//
//   cd cmd/sing-rdp-tun
//   go mod tidy
//   go build .
//
// For cross-compiles, deploy.sh handles GOOS / GOARCH overrides.
module github.com/vpnwrap/sing-rdp/cmd/sing-rdp-tun

go 1.22

require (
	github.com/sagernet/sing-tun v0.4.4
	github.com/sagernet/sing v0.5.1
	github.com/vpnwrap/sing-rdp v0.0.0
)

// Use the parent repo's rdp/ and credssp/ packages locally.
replace github.com/vpnwrap/sing-rdp => ../..
