//go:build singbox

package transport

import (
	"io"
	"net"
	"time"

	"github.com/vpnwrap/sing-rdp/rdp"
)

// xrdpSplice forwards `client` to a real RDP server on `upstream`. The
// caller has already consumed some bytes from `client` (typically the
// X.224 CR); pass them in `replay` to be re-played to xrdp first so the
// downstream server sees the connection exactly as the client sent it.
//
// On dial failure, we close the client cleanly. We deliberately don't
// synthesize an RDP_NEG_FAILURE response from scratch because Windows
// servers emit slightly different bytes depending on patch level; a
// reset is more authentic-looking than a wrong-shaped failure response.
func xrdpSplice(client net.Conn, upstream string, replay []byte) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	up, err := net.DialTimeout("tcp", upstream, 2*time.Second)
	if err != nil {
		return
	}
	defer up.Close()

	// Replay the bytes we already consumed before splicing.
	if len(replay) > 0 {
		if _, err := up.Write(replay); err != nil {
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}

// serveHoneypot is kept for callers (e.g. the sing-box transport server)
// that don't yet route through the cookie gate. Default upstream is
// 127.0.0.1:3390 (xrdp's internal port in our container layout).
func serveHoneypot(client net.Conn) {
	xrdpSplice(client, "127.0.0.1:3390", nil)
}

var _ = rdp.WithReplay // keep import even if local helpers move
