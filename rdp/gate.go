package rdp

import (
	"bytes"
	"errors"
	"io"
	"net"
)

// PeekConnectionRequest reads the X.224 Connection Request from `raw` and
// returns both the parsed structure and the original wire bytes. Callers
// can choose to:
//
//   - Continue with WriteConnectionConfirm + TLS for our handshake, OR
//   - Wrap the connection with WithReplay(raw, rawCR) and splice it to a
//     downstream RDP server (xrdp) which then sees the CR as if it had
//     never been intercepted.
//
// This is the gate that lets a single TCP listener serve both tunnel
// traffic (clients sending our magic cookie) and real RDP probes (which
// should be transparently relayed to xrdp).
func PeekConnectionRequest(raw net.Conn) (*ConnectionRequest, []byte, error) {
	var buf bytes.Buffer
	tee := io.TeeReader(raw, &buf)
	cr, err := ReadConnectionRequest(tee)
	if err != nil {
		// Even on error, return what we managed to read so the caller can
		// replay it to a downstream (probes that send malformed CRs still
		// look more authentic if xrdp gets to respond).
		return nil, buf.Bytes(), err
	}
	return cr, buf.Bytes(), nil
}

// MatchesCookie returns true if the connection-request cookie carries
// exactly the magic value (case-sensitive). The cookie field in the CR is
// the part after "Cookie: mstshash=" without the trailing CRLF.
func (cr *ConnectionRequest) MatchesCookie(magic string) bool {
	if cr == nil || len(cr.Cookie) == 0 {
		return magic == ""
	}
	const prefix = "Cookie: mstshash="
	if !bytes.HasPrefix(cr.Cookie, []byte(prefix)) {
		return false
	}
	got := bytes.TrimSpace(cr.Cookie[len(prefix):])
	return string(got) == magic
}

// ErrCookieMismatch signals that the CR was structurally valid but did not
// carry our expected magic cookie. Callers use this to decide between
// tunnel-path and xrdp-splice.
var ErrCookieMismatch = errors.New("rdp: cookie does not match tunnel magic")
