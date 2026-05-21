package main

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeDialer routes every Dial() to a fixed in-process echo server, capturing
// the dst string for assertions.
type fakeDialer struct {
	mu      sync.Mutex
	target  net.Listener
	lastDst string
}

func newFakeDialer(t *testing.T) *fakeDialer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Echo loop.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return &fakeDialer{target: ln}
}

func (f *fakeDialer) Dial(dst string) (net.Conn, error) {
	f.mu.Lock()
	f.lastDst = dst
	f.mu.Unlock()
	return net.Dial("tcp", f.target.Addr().String())
}

func (f *fakeDialer) Close() { f.target.Close() }

func TestSOCKS5ConnectIPv4Echo(t *testing.T) {
	fake := newFakeDialer(t)
	defer fake.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		_ = ServeSOCKS5(ln, fake, func(string, ...any) {})
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	// SOCKS5 greeting: ver=5, nmethods=1, methods=[NoAuth]
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greetReply [2]byte
	if _, err := io.ReadFull(c, greetReply[:]); err != nil {
		t.Fatal(err)
	}
	if greetReply[0] != 5 || greetReply[1] != 0 {
		t.Fatalf("greeting reply: %v", greetReply)
	}

	// Request: ver=5, cmd=CONNECT, rsv=0, atyp=IPv4, 1.2.3.4, port=80
	if _, err := c.Write([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80}); err != nil {
		t.Fatal(err)
	}
	// Reply: ver=5, rep=0, rsv=0, atyp=IPv4, 0.0.0.0, 0
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("CONNECT reply rep=%d (want 0)", reply[1])
	}

	// Echo through the tunnel.
	msg := []byte("hello over SOCKS")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("echo mismatch: got %q want %q", got, msg)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.lastDst != "1.2.3.4:80" {
		t.Errorf("dst captured wrong: %q", fake.lastDst)
	}
}

func TestSOCKS5ConnectDomain(t *testing.T) {
	fake := newFakeDialer(t)
	defer fake.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = ServeSOCKS5(ln, fake, func(string, ...any) {}) }()

	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))

	// CONNECT example.com:443 via domain atyp
	domain := "example.com"
	req := []byte{5, 1, 0, 3, byte(len(domain))}
	req = append(req, domain...)
	req = append(req, 0x01, 0xBB) // port 443
	c.Write(req)
	io.ReadFull(c, make([]byte, 10))

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.lastDst != "example.com:443" {
		t.Errorf("dst: %q", fake.lastDst)
	}
}

func TestSOCKS5RejectsNonV5(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { _ = ServeSOCKS5(ln, &fakeDialer{}, func(string, ...any) {}) }()

	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))

	// SOCKS4 greeting — should be rejected.
	c.Write([]byte{4, 1, 0, 80, 1, 2, 3, 4, 0})
	buf := make([]byte, 2)
	n, _ := c.Read(buf)
	// Server should close without replying or reply with NO_ACCEPTABLE.
	// We accept either: a closed conn (n=0) OR a reply that isn't a valid
	// SOCKS5 acceptance.
	if n == 2 && buf[0] == 5 && buf[1] == 0 {
		t.Errorf("SOCKS4 client should not get a successful SOCKS5 reply")
	}
}
