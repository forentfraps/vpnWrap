package rdp

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// fastPathConn adapts a TLS connection (or any net.Conn) post-handshake into
// a stream-oriented net.Conn whose Read/Write methods speak Fast-Path PDUs.
//
// Wire shape: every Write is encapsulated as one or more Fast-Path Output
// PDUs (server -> client direction) or Fast-Path Input PDUs (the same wire
// format with action bits differing — we use Output bytes both ways since,
// post-handshake, intermediaries can't distinguish without parsing). Read
// strips PDU headers and returns the inner payload bytes.
type fastPathConn struct {
	inner net.Conn
	br    *bufio.Reader

	writeMu sync.Mutex
	readMu  sync.Mutex

	// readBuf holds payload bytes that arrived in a Fast-Path frame but were
	// not yet consumed by Read().
	readBuf []byte

	isClient bool

	// Maximum payload bytes per Fast-Path frame. Real RDP screen updates vary;
	// we pick a number that produces plausible MSS-aligned packets.
	maxFrame int
}

func newFastPathConn(inner net.Conn, isClient bool) *fastPathConn {
	return &fastPathConn{
		inner:    inner,
		br:       bufio.NewReaderSize(inner, 32*1024),
		isClient: isClient,
		maxFrame: 1400, // keep below typical Ethernet MSS
	}
}

func (c *fastPathConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) == 0 {
		payload, err := ReadFastPath(c.br)
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			// Heartbeat / chaff frame — recurse by looping.
			return c.Read(p)
		}
		c.readBuf = payload
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *fastPathConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > c.maxFrame {
			chunk = chunk[:c.maxFrame]
		}
		if err := WriteFastPath(c.inner, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Heartbeat writes an empty Fast-Path PDU. Should be called every ~5s on idle
// to match real RDP's keep-alive cadence.
func (c *fastPathConn) Heartbeat() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return WriteFastPath(c.inner, nil)
}

func (c *fastPathConn) Close() error                       { return c.inner.Close() }
func (c *fastPathConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *fastPathConn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *fastPathConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *fastPathConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *fastPathConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// Heartbeater starts a goroutine that emits idle-heartbeats every interval.
// Returns a stop function. Safe to call on any *fastPathConn.
func Heartbeater(c net.Conn, interval time.Duration) func() {
	fpc, ok := c.(*fastPathConn)
	if !ok {
		return func() {}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if err := fpc.Heartbeat(); err != nil {
					return
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

var _ net.Conn = (*fastPathConn)(nil)
var _ io.ReadWriteCloser = (*fastPathConn)(nil)
var _ = errors.New // keep import; used by Heartbeater clients
