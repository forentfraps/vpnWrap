package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// udpRelay is the SOCKS5 UDP ASSOCIATE backend. tun2socks (or any SOCKS5
// UDP client) sends datagrams here; we forward them through the existing
// RDP+VLESS tunnel using packetaddr framing, and ferry responses back.
//
// Design:
//
//   - One persistent UDP listener (bound at startup) is the SOCKS5 relay
//     port. Its host:port is returned in every UDP ASSOCIATE reply.
//
//   - NAT map keyed by (client_src) — each client source (an addr:port that
//     tun2socks NATs internally) gets its own VLESS UDP connection. A
//     single VLESS connection multiplexes multiple destinations via
//     packetaddr, so one client_src can talk to many remotes simultaneously.
//
//   - Idle sessions get reaped after `idleTimeout` so we don't accumulate
//     dead tunnels.
//
// Why per-client-src instead of per-dst: responses on the VLESS side come
// back with the remote's address (as packetaddr source). We need to ship
// the response to the right client_src. If we keyed on dst, multiple
// clients hitting the same DNS server would cross-talk. Keying on
// client_src is the natural NAT model and matches what SOCKS5 expects.
type udpRelay struct {
	dialer *rdpDialer

	ln      *net.UDPConn
	bindIP  string
	bindPort uint16

	mu       sync.Mutex
	sessions map[string]*udpSession // key = client_src.String()

	idleTimeout time.Duration
}

type udpSession struct {
	vlessConn  net.Conn   // VLESS-UDP-mode connection (carrier for packetaddr)
	clientSrc  *net.UDPAddr
	lastActive time.Time
	once       sync.Once
}

// newUDPRelay creates the listener but doesn't start the read loop —
// caller must call Run() in a goroutine.
func newUDPRelay(dialer *rdpDialer, bindHost string) (*udpRelay, error) {
	// Bind to an ephemeral UDP port on the requested host. We pass the
	// concrete port back to SOCKS5 clients in the ASSOCIATE reply.
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bindHost, "0"))
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", bindHost, err)
	}
	ln, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	la := ln.LocalAddr().(*net.UDPAddr)

	r := &udpRelay{
		dialer:      dialer,
		ln:          ln,
		bindIP:      bindHost,
		bindPort:    uint16(la.Port),
		sessions:    make(map[string]*udpSession),
		idleTimeout: 90 * time.Second,
	}
	return r, nil
}

// BindAddr satisfies the UDPRelay interface for the SOCKS5 handler.
func (r *udpRelay) BindAddr() (string, uint16) { return r.bindIP, r.bindPort }

// Close stops the relay and closes every session.
func (r *udpRelay) Close() error {
	r.mu.Lock()
	for k, s := range r.sessions {
		s.vlessConn.Close()
		delete(r.sessions, k)
	}
	r.mu.Unlock()
	return r.ln.Close()
}

// Run is the listener loop. Reads SOCKS5-wrapped UDP datagrams from
// tun2socks, forwards them through VLESS using packetaddr framing, and
// kicks off a reader goroutine per session for the response direction.
func (r *udpRelay) Run() {
	go r.reaper()
	buf := make([]byte, 65535)
	for {
		n, src, err := r.ln.ReadFromUDP(buf)
		if err != nil {
			// Listener closed; exit.
			return
		}
		dstHost, dstPort, payload, err := DecodeSOCKSUDPPacket(buf[:n])
		if err != nil {
			log.Printf("udp: bad SOCKS5 envelope from %s: %v", src, err)
			continue
		}
		if err := r.forward(src, dstHost, dstPort, payload); err != nil {
			log.Printf("udp: forward to %s:%d: %v", dstHost, dstPort, err)
		}
	}
}

// forward sends one UDP packet to the destination via the appropriate
// VLESS session for the given client source, creating the session if
// needed.
func (r *udpRelay) forward(src *net.UDPAddr, dstHost string, dstPort uint16, payload []byte) error {
	sess, isNew, err := r.getOrCreateSession(src, dstHost, dstPort)
	if err != nil {
		return err
	}
	if isNew {
		// Spin up the response reader for this session.
		go r.responseLoop(sess)
	}
	sess.lastActive = time.Now()
	return writePacketAddr(sess.vlessConn, dstHost, dstPort, payload)
}

func (r *udpRelay) getOrCreateSession(src *net.UDPAddr, dstHost string, dstPort uint16) (*udpSession, bool, error) {
	key := src.String()

	r.mu.Lock()
	if s, ok := r.sessions[key]; ok {
		r.mu.Unlock()
		return s, false, nil
	}
	r.mu.Unlock()

	// Open a fresh VLESS UDP-mode connection. The initial dst is the
	// caller's first destination — packetaddr can switch dst per packet
	// after that, but sing-box still expects something here.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := r.dialer.dialUDP(ctx, dstHost, dstPort)
	if err != nil {
		return nil, false, err
	}

	sess := &udpSession{
		vlessConn:  conn,
		clientSrc:  src,
		lastActive: time.Now(),
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check in case a concurrent goroutine created one for the same src.
	if existing, ok := r.sessions[key]; ok {
		conn.Close()
		return existing, false, nil
	}
	r.sessions[key] = sess
	return sess, true, nil
}

// responseLoop reads packetaddr-encoded responses from a session's VLESS
// conn and writes them back to the SOCKS5 client as SOCKS5 UDP envelopes.
func (r *udpRelay) responseLoop(sess *udpSession) {
	defer r.dropSession(sess)
	for {
		srcAddr, srcDomain, payload, err := readPacketAddr(sess.vlessConn)
		if err != nil {
			// EOF or any error closes the session.
			return
		}
		sess.lastActive = time.Now()

		// Build the SOCKS5 UDP response envelope. The "destination" in the
		// SOCKS5 wrapper is the SOURCE on the response direction — that's
		// where the packet came from, which the client uses to demux.
		var host string
		if srcDomain != "" {
			host = srcDomain
		} else {
			host = srcAddr.Addr().String()
		}
		envelope, err := EncodeSOCKSUDPPacket(host, srcAddr.Port(), payload)
		if err != nil {
			log.Printf("udp: encode response: %v", err)
			continue
		}
		if _, err := r.ln.WriteToUDP(envelope, sess.clientSrc); err != nil {
			log.Printf("udp: write to client %s: %v", sess.clientSrc, err)
			return
		}
	}
}

func (r *udpRelay) dropSession(sess *udpSession) {
	sess.once.Do(func() {
		sess.vlessConn.Close()
		r.mu.Lock()
		delete(r.sessions, sess.clientSrc.String())
		r.mu.Unlock()
	})
}

// reaper closes idle sessions. Without it, every distinct tun2socks
// source port permanently leaks a VLESS connection.
func (r *udpRelay) reaper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		var stale []*udpSession
		r.mu.Lock()
		for _, s := range r.sessions {
			if now.Sub(s.lastActive) > r.idleTimeout {
				stale = append(stale, s)
			}
		}
		r.mu.Unlock()
		for _, s := range stale {
			r.dropSession(s)
		}
	}
}
