// Package health exposes an HTTP endpoint that reports the readiness of
// the sing-rdp server. Three classes of signal are combined:
//
//  1. TCP liveness of arbitrary named services (xrdp, the inner proxy
//     upstream, etc.) — fast and side-effect-free.
//  2. A loopback handshake against our own listener that runs the entire
//     RDP+TLS+CredSSP stack end to end (so it catches handshake-layer
//     regressions that pure port liveness wouldn't).
//
// /healthz returns 200 with a JSON body when every component is green,
// 503 otherwise. /livez is a cheap subset — TCP checks only, no
// loopback handshake — appropriate for orchestrator liveness probes
// that should restart on hangs rather than transient handshake hiccups.
//
// Bind to loopback or a private interface only — it intentionally reveals
// whether your handshake works (and therefore implies cookie validity).
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync/atomic"
	"time"
)

// TCPCheck is a single labeled TCP probe.
type TCPCheck struct {
	// Name appears in the JSON output (e.g. "xrdp", "upstream").
	Name string
	// Addr is the host:port to dial.
	Addr string
}

// Config holds the wiring for the health endpoint.
type Config struct {
	// ListenAddr is the HTTP bind address (e.g. 127.0.0.1:9180).
	ListenAddr string

	// TCPChecks are dialed in parallel on every /healthz hit. An empty
	// list is allowed.
	TCPChecks []TCPCheck

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

// report is the JSON shape /healthz returns. Components is keyed by check
// name so callers (and ops dashboards) can see exactly which probe failed
// without grepping a free-form message.
type report struct {
	OK         bool              `json:"ok"`
	Components map[string]string `json:"components"`
	CheckedAt  string            `json:"checked_at"`
}

func (c *Checker) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), c.cfg.CheckTimeout*2)
	defer cancel()

	results := make(map[string]string, len(c.cfg.TCPChecks)+1)
	allOK := true

	// Run TCP checks in parallel; aggregate by name.
	type tcpResult struct {
		name string
		err  error
	}
	resultsCh := make(chan tcpResult, len(c.cfg.TCPChecks))
	for _, chk := range c.cfg.TCPChecks {
		chk := chk
		go func() {
			resultsCh <- tcpResult{name: chk.Name, err: c.checkTCP(ctx, chk.Addr)}
		}()
	}
	for range c.cfg.TCPChecks {
		r := <-resultsCh
		results[r.name] = stringErr(r.err, "ok")
		if r.err != nil {
			allOK = false
		}
	}

	// Loop probe last (it's the expensive one).
	if lerr := c.checkLoop(ctx); lerr != nil {
		results["loopback"] = lerr.Error()
		allOK = false
	} else if c.cfg.LoopProbe != nil {
		results["loopback"] = "ok"
	}

	rep := report{
		OK:         allOK,
		Components: results,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	c.lastOK.Store(rep.OK)

	w.Header().Set("Content-Type", "application/json")
	if !rep.OK {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(rep)
}

// /livez is a cheaper check: TCP probes only, no in-process handshake.
// Returns 200 only if every configured TCP check passes.
func (c *Checker) handleLive(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), c.cfg.CheckTimeout)
	defer cancel()

	// Sort by name so error output is stable across runs.
	checks := append([]TCPCheck(nil), c.cfg.TCPChecks...)
	sort.Slice(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })

	for _, chk := range checks {
		if err := c.checkTCP(ctx, chk.Addr); err != nil {
			http.Error(w, fmt.Sprintf("%s: %v", chk.Name, err), http.StatusServiceUnavailable)
			return
		}
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
