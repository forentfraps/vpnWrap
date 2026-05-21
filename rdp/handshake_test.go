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

// TestHeartbeatInterleavedWithData regresses a bug where Fast-Path Read
// recursed while holding readMu when an empty (heartbeat) PDU arrived,
// deadlocking on the reentrant Lock(). Symptom in production: every
// connection silently froze ~5s after the handshake and the browser
// timed out ~11.6s later.
func TestHeartbeatInterleavedWithData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cert := selfSignedCert(t)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	clientTLS := &tls.Config{InsecureSkipVerify: true}

	srvDone := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := Server(ctx, c, ServerConfig{
			TLSConfig:     serverTLS,
			Mode:          ModeStandalone,
			CookieMatched: true,
		})
		if err != nil {
			srvDone <- err
			return
		}
		defer conn.Close()

		// Emit a heartbeat between two real data writes. The client must
		// transparently skip the heartbeat and read both data chunks.
		stop := Heartbeater(conn, 50*time.Millisecond)
		defer stop()

		if _, err := conn.Write([]byte("first")); err != nil {
			srvDone <- err
			return
		}
		// Sleep > heartbeat interval so at least one fires between writes.
		time.Sleep(150 * time.Millisecond)
		if _, err := conn.Write([]byte("second")); err != nil {
			srvDone <- err
			return
		}
		// Read echo so client write completes before we tear down.
		buf := make([]byte, 16)
		_, _ = conn.Read(buf)
		srvDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cc, err := Client(ctx, net.Dialer{Timeout: 3 * time.Second}, ClientConfig{
		Address:   ln.Addr().String(),
		Cookie:    "test",
		Mode:      ModeStandalone,
		TLSConfig: clientTLS,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cc.Close()

	got1 := make([]byte, 5)
	_ = cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cc, got1); err != nil {
		t.Fatalf("read1: %v (heartbeat deadlock regression?)", err)
	}
	if string(got1) != "first" {
		t.Fatalf("got %q", got1)
	}

	got2 := make([]byte, 6)
	_ = cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cc, got2); err != nil {
		t.Fatalf("read2: %v (heartbeat between reads?)", err)
	}
	if string(got2) != "second" {
		t.Fatalf("got %q", got2)
	}

	_, _ = cc.Write([]byte("ack"))

	select {
	case err := <-srvDone:
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
