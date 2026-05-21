package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestParseUUID(t *testing.T) {
	good := "11111111-2222-3333-4444-555555555555"
	u, err := parseUUID(good)
	if err != nil {
		t.Fatalf("parse %q: %v", good, err)
	}
	want := [16]byte{
		0x11, 0x11, 0x11, 0x11,
		0x22, 0x22,
		0x33, 0x33,
		0x44, 0x44,
		0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	}
	if u != want {
		t.Errorf("got % x, want % x", u, want)
	}
}

func TestParseUUIDRejectsBad(t *testing.T) {
	cases := []string{
		"",
		"not-a-uuid",
		"1111111122223333444455555555555555", // no dashes
		"11111111-2222-3333-4444-55555555555g",
	}
	for _, c := range cases {
		if _, err := parseUUID(c); err == nil {
			t.Errorf("parseUUID(%q) should fail", c)
		}
	}
}

func TestVLESSRequestIPv4(t *testing.T) {
	var u [16]byte
	for i := range u {
		u[i] = byte(i)
	}
	var buf bytes.Buffer
	if err := writeVLESSRequest(&buf, u, "1.2.3.4", 443); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()

	// Expected layout:
	//   version (1)         = 0
	//   uuid (16)
	//   addons len (1)      = 0
	//   cmd (1)             = 1
	//   port (2 BE)         = 0x01 0xBB
	//   atyp (1)            = 1 (IPv4)
	//   addr (4)            = 1.2.3.4
	wantLen := 1 + 16 + 1 + 1 + 2 + 1 + 4
	if len(got) != wantLen {
		t.Fatalf("len: got %d want %d", len(got), wantLen)
	}
	if got[0] != 0 {
		t.Errorf("version: %d", got[0])
	}
	if !bytes.Equal(got[1:17], u[:]) {
		t.Errorf("uuid mismatch")
	}
	if got[17] != 0 || got[18] != 1 {
		t.Errorf("addons/cmd: %d %d", got[17], got[18])
	}
	if got[19] != 0x01 || got[20] != 0xBB {
		t.Errorf("port: %02x %02x", got[19], got[20])
	}
	if got[21] != 1 {
		t.Errorf("atyp: %d", got[21])
	}
	if !bytes.Equal(got[22:26], []byte{1, 2, 3, 4}) {
		t.Errorf("addr: % x", got[22:26])
	}
}

func TestVLESSRequestDomain(t *testing.T) {
	var u [16]byte
	var buf bytes.Buffer
	if err := writeVLESSRequest(&buf, u, "example.com", 80); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	// Domain layout: ... atyp=2, len=11, "example.com"
	atypIdx := 1 + 16 + 1 + 1 + 2
	if got[atypIdx] != 2 {
		t.Errorf("atyp: %d", got[atypIdx])
	}
	if got[atypIdx+1] != 11 {
		t.Errorf("domain length: %d", got[atypIdx+1])
	}
	if string(got[atypIdx+2:atypIdx+2+11]) != "example.com" {
		t.Errorf("domain: %q", got[atypIdx+2:atypIdx+2+11])
	}
}

func TestVLESSResponseRoundtrip(t *testing.T) {
	// Server response: version=0, addons_len=0
	buf := bytes.NewBuffer([]byte{0, 0})
	v, err := readVLESSResponse(buf)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0 {
		t.Errorf("version: %d", v)
	}
}

func TestVLESSResponseSkipsAddons(t *testing.T) {
	// version=0, addons_len=3, three junk bytes
	buf := bytes.NewBuffer([]byte{0, 3, 'x', 'y', 'z'})
	if _, err := readVLESSResponse(buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("addons not drained: %d bytes left", buf.Len())
	}
}

// TestLazyResponseStripper regresses the deadlock where readVLESSResponse
// was called before SOCKS5 success was sent, leaving the browser silent
// and sing-box's wait-for-data optimization holding the response.
func TestLazyResponseStripper(t *testing.T) {
	// Simulate a server-side stream: 2-byte VLESS response + app data.
	stream := []byte{
		0, 0, // version=0, addons_len=0  (the response we want stripped)
		'H', 'e', 'l', 'l', 'o', // application data
	}
	lazy := NewLazyResponseStripper(&fakeConn{r: bytes.NewReader(stream)})

	// First read should hide the response prefix and surface app data.
	buf := make([]byte, 32)
	n, err := lazy.Read(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if string(buf[:n]) != "Hello" {
		t.Errorf("got %q want %q", buf[:n], "Hello")
	}

	// Second read should hit EOF on the inner reader.
	_, err = lazy.Read(buf)
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestLazyResponseStripperWithAddons(t *testing.T) {
	stream := []byte{
		0, 3, 'a', 'b', 'c', // version + addons_len=3 + 3 addon bytes
		'O', 'K',
	}
	lazy := NewLazyResponseStripper(&fakeConn{r: bytes.NewReader(stream)})

	buf := make([]byte, 32)
	n, err := lazy.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "OK" {
		t.Errorf("got %q want %q", buf[:n], "OK")
	}
}

// fakeConn is a minimal net.Conn adaptor over a Reader for these tests.
type fakeConn struct {
	r io.Reader
}

func (f *fakeConn) Read(p []byte) (int, error)        { return f.r.Read(p) }
func (f *fakeConn) Write(p []byte) (int, error)       { return len(p), nil }
func (f *fakeConn) Close() error                      { return nil }
func (f *fakeConn) LocalAddr() net.Addr               { return nil }
func (f *fakeConn) RemoteAddr() net.Addr              { return nil }
func (f *fakeConn) SetDeadline(time.Time) error       { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error   { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error  { return nil }
