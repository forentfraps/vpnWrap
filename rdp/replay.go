package rdp

import (
	"net"
	"time"
)

// replayConn is a net.Conn that yields `prefix` bytes from Read() before
// reading from the underlying conn. Used when we've already consumed bytes
// (e.g. an X.224 CR) but need to forward them to a downstream service like
// xrdp that expects to see them.
type replayConn struct {
	net.Conn
	prefix []byte
}

// WithReplay returns a net.Conn that emits prefix on Read before falling
// through to inner. The prefix slice is consumed in place; callers should
// not modify it after passing it in.
func WithReplay(inner net.Conn, prefix []byte) net.Conn {
	return &replayConn{Conn: inner, prefix: prefix}
}

func (r *replayConn) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	return r.Conn.Read(p)
}

// Methods are inherited from embedded net.Conn (Write, Close, addrs, deadlines).
var _ net.Conn = (*replayConn)(nil)
var _ = time.Time{}
