package rdp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestHandshakeEndToEnd brings up a server and client on a loopback
// listener, completes a standalone handshake, and exchanges bytes
// through the Fast-Path tunnel.
func TestHandshakeEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cert := selfSignedCert(t)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	clientTLS := &tls.Config{InsecureSkipVerify: true}

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := Server(ctx, c, ServerConfig{
			TLSConfig:     serverTLS,
			Mode:          ModeStandalone,
			CookieMatched: true, // tests bypass the cookie gate
		})
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		// Echo loop.
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				done <- nil
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				done <- err
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cc, err := Client(ctx, net.Dialer{Timeout: 3 * time.Second}, ClientConfig{
		Address:   ln.Addr().String(),
		Cookie:    "test-cookie",
		Mode:      ModeStandalone,
		TLSConfig: clientTLS,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	msg := []byte("hello over RDP fast-path")
	if _, err := cc.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
	cc.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server didn't return")
	}
}

// TestCookieGateRejectsBadCookie verifies the gate path is wired up:
// a connection without the magic cookie should be flagged for splice.
func TestCookieGateRejectsBadCookie(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go func() {
		_ = WriteConnectionRequest(a, "wrong", ProtoSSL)
	}()

	cr, replay, err := PeekConnectionRequest(b)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if cr.MatchesCookie("svc-jumpbox") {
		t.Error("expected cookie mismatch")
	}
	if len(replay) == 0 {
		t.Error("expected replay bytes captured")
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sing-rdp-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
