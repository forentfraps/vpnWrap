//go:build singbox

package transport

import (
	"context"
	"errors"
	"net"
)

// openEmbeddedSVC, on the client side, drives CredSSP/NLA over `tlsConn` and
// then negotiates an MCS Connect / channel join that includes a static virtual
// channel named (by default) "VPNW". The returned net.Conn carries SVC payload
// bytes only.
//
// This file is a stub: the CredSSP implementation is substantial (SPNEGO +
// NTLMv2 or Kerberos), and we keep it in a separate sub-package once it lands.
// Until then, embed mode requires the operator to use a server that accepts
// no-auth on the SVC channel (we run xrdp behind nginx with cert auth instead).
func openEmbeddedSVC(ctx context.Context, tlsConn net.Conn, opts EmbedOptions) (net.Conn, error) {
	return nil, errors.New("rdp: embed mode CredSSP not yet implemented; use standalone mode")
}

// acceptEmbeddedSVC is the server-side counterpart: forward post-NLA traffic
// to a local xrdp instance, while sniffing for the SVC where our payload lives.
func acceptEmbeddedSVC(ctx context.Context, tlsConn net.Conn, opts *EmbedOptions) (net.Conn, error) {
	return nil, errors.New("rdp: embed mode SVC acceptance not yet implemented")
}
