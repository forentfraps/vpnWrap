// Package health exposes an HTTP endpoint that reports the readiness of
// the sing-rdp server. Two signals are combined:
//
//  1. TCP liveness of the downstream xrdp service (so probes spliced to it
//     will actually succeed).
//  2. A loopback handshake against our own listener (so the full RDP +
//     TLS stack is verified end to end, not just port liveness).
//
// /healthz returns 200 with a JSON body when both pass, 503 otherwise.
// Bind the listener to loopback or a private interface — it intentionally
// leaks the magic cookie validity (it would 503 if our handshake stopped
// working) and shouldn't be reachable from the public internet.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Config holds the wiring for the health endpoint.
type Config struct {
	// ListenAddr is the HTTP bind address (e.g. 127.0.0.1:9180).
	ListenAddr string

	// TCPCheck is a host:port that must accept a TCP connection within
	// CheckTimeout. Typically xrdp's address.
	TCPCheck string

	// LoopProbe runs a full client-side RDP handshake against our own
	// listener. Returns nil on success.
	LoopProbe func(context.Context) error

	// CheckTimeout bounds each individual probe. Defaults to 3s.
	CheckTimeout time.Duration
}

// Checker is a running health endpoint.
type Checker struct {
	cfg    Config
	server *http.Server

	// lastOK records whether the most recent probe was good. Updated by
	// /healthz; useful for callers that want to expose the same state
	// elsewhere (e.g. Prometheus).
	lastOK atomic.Bool
}

// New constructs a Checker but does not start serving.
func New(cfg Config) *Checker {
	if cfg.CheckTimeout == 0 {
		cfg.CheckTimeout = 3 * time.Second
	}
	c := &Checker{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", c.handleHealth)
	mux.HandleFunc("/livez", c.handleLive)

	c.server = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	return c
}

// Serve runs the HTTP server until Close().
func (c *Checker) Serve() error {
	return c.server.ListenAndServe()
}

// Close stops the HTTP server.
func (c *Checker) Close() error { return c.server.Close() }

// LastOK reports the most recent /healthz result (initially false).
func (c *Checker) LastOK() bool { return c.lastOK.Load() }

type report struct {
	OK        bool   `json:"ok"`
	XRDP      string `json:"xrdp"`
	Loopback  string `json:"loopback"`
	CheckedAt string `json:"checked_at"`
}

func (c *Checker) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), c.cfg.CheckTimeout*2)
	defer cancel()

	xerr := c.checkTCP(ctx, c.cfg.TCPCheck)
	lerr := c.checkLoop(ctx)

	rep := report{
		OK:        xerr == nil && lerr == nil,
		XRDP:      stringErr(xerr, "ok"),
		Loopback:  stringErr(lerr, "ok"),
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
	c.lastOK.Store(rep.OK)

	w.Header().Set("Content-Type", "application/json")
	if !rep.OK {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(rep)
}

// /livez is a cheaper check: TCP probe only, no in-process handshake.
// Useful for orchestrator liveness probes that should restart on hangs
// rather than transient handshake failures.
func (c *Checker) handleLive(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), c.cfg.CheckTimeout)
	defer cancel()
	if err := c.checkTCP(ctx, c.cfg.TCPCheck); err != nil {
		http.Error(w, fmt.Sprintf("xrdp: %v", err), http.StatusServiceUnavailable)
		return
	}
	_, _ = fmt.Fprintln(w, "ok")
}

func (c *Checker) checkTCP(ctx context.Context, addr string) error {
	if addr == "" {
		return nil
	}
	d := net.Dialer{Timeout: c.cfg.CheckTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (c *Checker) checkLoop(ctx context.Context) error {
	if c.cfg.LoopProbe == nil {
		return nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, c.cfg.CheckTimeout)
	defer cancel()
	return c.cfg.LoopProbe(probeCtx)
}

func stringErr(err error, ok string) string {
	if err == nil {
		return ok
	}
	return err.Error()
}
