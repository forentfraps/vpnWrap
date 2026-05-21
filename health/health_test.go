package health

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHealthHappyPath(t *testing.T) {
	// Stub TCP target.
	stub, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	go acceptAndDrop(stub)

	hc := New(Config{
		ListenAddr:   "127.0.0.1:0",
		TCPCheck:     stub.Addr().String(),
		LoopProbe:    func(context.Context) error { return nil },
		CheckTimeout: 500 * time.Millisecond,
	})
	addr := startChecker(t, hc)
	defer hc.Close()

	resp := getJSON(t, "http://"+addr+"/healthz")
	if !resp.OK {
		t.Fatalf("expected ok, got %+v", resp)
	}
	if !hc.LastOK() {
		t.Error("LastOK should be true")
	}
}

func TestHealthFailsWhenXrdpDown(t *testing.T) {
	hc := New(Config{
		ListenAddr:   "127.0.0.1:0",
		TCPCheck:     "127.0.0.1:1", // nothing listening
		LoopProbe:    func(context.Context) error { return nil },
		CheckTimeout: 200 * time.Millisecond,
	})
	addr := startChecker(t, hc)
	defer hc.Close()

	r, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status: got %d want 503", r.StatusCode)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), "\"ok\":false") {
		t.Errorf("body: %s", body)
	}
}

func TestHealthFailsWhenLoopProbeFails(t *testing.T) {
	stub, _ := net.Listen("tcp", "127.0.0.1:0")
	defer stub.Close()
	go acceptAndDrop(stub)

	hc := New(Config{
		ListenAddr:   "127.0.0.1:0",
		TCPCheck:     stub.Addr().String(),
		LoopProbe:    func(context.Context) error { return errors.New("handshake busted") },
		CheckTimeout: 200 * time.Millisecond,
	})
	addr := startChecker(t, hc)
	defer hc.Close()

	resp := getJSON(t, "http://"+addr+"/healthz")
	if resp.OK {
		t.Error("expected not ok")
	}
	if !strings.Contains(resp.Loopback, "handshake busted") {
		t.Errorf("loopback: %s", resp.Loopback)
	}
}

func TestLivezIsCheapTCPOnly(t *testing.T) {
	stub, _ := net.Listen("tcp", "127.0.0.1:0")
	defer stub.Close()
	go acceptAndDrop(stub)

	hc := New(Config{
		ListenAddr: "127.0.0.1:0",
		TCPCheck:   stub.Addr().String(),
		LoopProbe: func(context.Context) error {
			t.Error("/livez must not invoke LoopProbe")
			return nil
		},
		CheckTimeout: 200 * time.Millisecond,
	})
	addr := startChecker(t, hc)
	defer hc.Close()

	r, err := http.Get("http://" + addr + "/livez")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Errorf("status: got %d want 200", r.StatusCode)
	}
}

// startChecker uses an ephemeral port by listening explicitly and replacing
// the server's listener — Config.ListenAddr was 127.0.0.1:0 only as a marker.
func startChecker(t *testing.T, hc *Checker) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = hc.server.Serve(ln) }()
	// Wait briefly for the server to be ready.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ln.Addr().String()
}

func getJSON(t *testing.T, url string) report {
	t.Helper()
	r, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var rep report
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rep
}

func acceptAndDrop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}
