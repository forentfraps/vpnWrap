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

// sing-tun is in a strange period — v0.4.4 has an internal compile error
// ("o.InterfaceScope undefined") and the API has shifted between minor
// versions. v0.5.4 + the matching sing v0.5.x has been the most stable
// pairing in our testing. If you hit fresh sing-tun build issues here, the
// usual fix is to align both versions to whatever the current sing-box
// release uses — see https://github.com/SagerNet/sing-box/blob/main/go.mod
require (
	github.com/sagernet/sing-tun v0.5.4
	github.com/sagernet/sing v0.5.4
	github.com/vpnwrap/sing-rdp v0.0.0
)

// Use the parent repo's rdp/ and credssp/ packages locally.
replace github.com/vpnwrap/sing-rdp => ../..
