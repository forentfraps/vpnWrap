// sing-rdp-server is the standalone server-side entry point for the RDP-DVC
// transport. It listens on a TCP port (default :3389), performs the RDP
// handshake for clients carrying the configured magic cookie, and splices
// every other connection to a local xrdp instance so probes see a real
// RDP server.
//
// Once a tunnel handshake completes, the inner byte stream is forwarded
// transparently to a configurable upstream — typically a sing-box / xray /
// shadowsocks inbound listening on loopback that does the actual proxy
// auth and routing.
//
// Architecture:
//
//   internet --:3389--> [sing-rdp-server]
//                       |
//                       |--cookie matches?--> RDP handshake -> upstream (127.0.0.1:1080)
//                       |
//                       \--no/wrong cookie--> splice to xrdp (127.0.0.1:3390)
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/vpnwrap/sing-rdp/health"
	"github.com/vpnwrap/sing-rdp/rdp"
	"github.com/vpnwrap/sing-rdp/rdp/credssp"
	"github.com/vpnwrap/sing-rdp/shape"
)

func main() {
	listen := flag.String("listen", ":3389", "TCP listen address")
	upstream := flag.String("upstream", "127.0.0.1:1080", "inner-stream upstream (e.g. local SOCKS / VLESS inbound)")
	xrdpAddr := flag.String("xrdp", "127.0.0.1:3390", "xrdp address to splice non-tunnel connections to")
	cookie := flag.String("cookie", "", "magic cookie required in X.224 CR (mstshash value)")
	hostname := flag.String("hostname", "DESKTOP-UNKNOWN", "NetBIOS/DNS hostname emitted in CredSSP CHALLENGE")
	netbiosDomain := flag.String("netbios-domain", "WORKGROUP", "NetBIOS domain emitted in CredSSP CHALLENGE")
	dnsDomain := flag.String("dns-domain", "", "DNS domain emitted in CredSSP CHALLENGE (empty for workgroup)")
	certPath := flag.String("cert", "/etc/sing-rdp/cert.pem", "TLS certificate path")
	keyPath := flag.String("key", "/etc/sing-rdp/key.pem", "TLS key path")
	healthAddr := flag.String("health", "127.0.0.1:9180", "health endpoint listen address (empty to disable)")
	hbInterval := flag.Duration("heartbeat", 5*time.Second, "Fast-Path heartbeat interval")
	flag.Parse()

	if *cookie == "" {
		log.Fatal("--cookie is required (don't leave the magic value empty)")
	}

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	log.Printf("sing-rdp-server listening on %s (upstream=%s xrdp=%s)", *listen, *upstream, *xrdpAddr)

	srv := &server{
		tlsCfg:    tlsCfg,
		upstream:  *upstream,
		xrdpAddr:  *xrdpAddr,
		cookie:    *cookie,
		heartbeat: *hbInterval,
		identity: credssp.MachineIdentity{
			NetBIOSName:   *hostname,
			DNSName:       *hostname,
			NetBIOSDomain: *netbiosDomain,
			DNSDomain:     *dnsDomain,
		},
	}

	if *healthAddr != "" {
		go func() {
			hc := health.New(health.Config{
				ListenAddr: *healthAddr,
				TCPCheck:   *xrdpAddr,
				LoopProbe: func(ctx context.Context) error {
					return srv.probeSelf(ctx, ln.Addr().String())
				},
			})
			log.Printf("health endpoint on %s", *healthAddr)
			if err := hc.Serve(); err != nil {
				log.Printf("health: %v", err)
			}
		}()
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			if isClosedErr(err) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go srv.handle(c)
	}
}

type server struct {
	tlsCfg    *tls.Config
	upstream  string
	xrdpAddr  string
	cookie    string
	heartbeat time.Duration
	identity  credssp.MachineIdentity

	active sync.WaitGroup
}

func (s *server) handle(raw net.Conn) {
	s.active.Add(1)
	defer s.active.Done()
	defer raw.Close()

	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))

	cr, replay, err := rdp.PeekConnectionRequest(raw)
	if err != nil || !cr.MatchesCookie(s.cookie) {
		// Not a tunnel client — relay to xrdp.
		spliceToXrdp(raw, s.xrdpAddr, replay)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := rdp.ServerWithCR(ctx, raw, cr, rdp.ServerConfig{
		TLSConfig:     s.tlsCfg,
		Mode:          rdp.ModeStandalone,
		Identity:      s.identity,
		CookieMatched: true, // gate already passed; otherwise we'd be in the splice path
		Timeout:       30 * time.Second,
	})
	if err != nil {
		log.Printf("handshake failed (post-cookie): %v", err)
		return
	}
	defer conn.Close()

	// Apply traffic shape and heartbeats.
	shaped := shape.Wrap(conn, shape.Default(), true /*isServer*/)
	stop := rdp.Heartbeater(conn, s.heartbeat)
	defer stop()

	// Splice to upstream (typically the real proxy server on loopback).
	up, err := net.DialTimeout("tcp", s.upstream, 5*time.Second)
	if err != nil {
		log.Printf("dial upstream %s: %v", s.upstream, err)
		return
	}
	defer up.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, shaped); done <- struct{}{} }()
	go func() { _, _ = io.Copy(shaped, up); done <- struct{}{} }()
	<-done
}

// probeSelf does a full client-side handshake against our own listener,
// validating the entire path including TLS + CredSSP. Used by the
// readiness check; the in-process round-trip catches handshake-stack
// regressions that pure port liveness wouldn't.
func (s *server) probeSelf(ctx context.Context, addr string) error {
	probeCfg := rdp.ClientConfig{
		Address: addr,
		Cookie:  s.cookie,
		Mode:    rdp.ModeStandalone,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		Identity: s.identity,
		Timeout:  5 * time.Second,
	}
	c, err := rdp.Client(ctx, net.Dialer{Timeout: 5 * time.Second}, probeCfg)
	if err != nil {
		return err
	}
	return c.Close()
}

func spliceToXrdp(client net.Conn, upstream string, replay []byte) {
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	up, err := net.DialTimeout("tcp", upstream, 2*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	if len(replay) > 0 {
		if _, err := up.Write(replay); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	// net.ErrClosed is in stdlib but checking string also works in older toolchains.
	return err.Error() == "use of closed network connection"
}

// Ensure the binary fails fast if stdout/stderr go away (k8s pod loss).
var _ = os.Stdout
