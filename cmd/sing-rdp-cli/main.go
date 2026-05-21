// sing-rdp-cli is the all-in-one user-side CLI client. It exposes a
// SOCKS5 listener on the local machine and tunnels every connection out
// through the full stack:
//
//   browser/app -> SOCKS5 -> [sing-rdp-cli]
//                              | speaks VLESS over an RDP-wrapped TLS
//                              | connection to the VPS, all in-process
//                              v
//                          RDP/TLS+CredSSP on TCP/3389 -> VPS
//                          -> sing-rdp-server (unwrap)
//                          -> sing-box-inner (VLESS auth + direct outbound)
//                          -> the real destination
//
// Distribution form is a single static .exe. No companion sing-box needed.
//
// Usage:
//
//   sing-rdp-cli -c sing-rdp.json
//
// Generate sing-rdp.json on the VPS with: ./deploy.sh client-config --json
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vpnwrap/sing-rdp/rdp"
	"github.com/vpnwrap/sing-rdp/rdp/credssp"
)

// runTUN is defined per-platform in tun_windows.go and tun_other.go.
// It blocks until ctx is cancelled or the spawned tun2socks exits.

var (
	flagConfig  = flag.String("c", "sing-rdp.json", "path to JSON config file")
	flagVerbose = flag.Bool("v", false, "verbose logging")
	flagTUN     = flag.Bool("tun", false, "enable system-wide TUN mode (Windows: needs admin + tun2socks.exe + wintun.dll alongside)")
)

const version = "0.1.0"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "sing-rdp-cli %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [-c sing-rdp.json] [-v]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Reads sing-rdp.json (see ./deploy.sh client-config --json on the VPS)")
		fmt.Fprintln(os.Stderr, "and starts a local SOCKS5 listener. Point your browser at it.")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
	}
	flag.Parse()

	cfg, err := LoadConfig(*flagConfig)
	if err != nil {
		fatal("config: %v", err)
	}

	uuid, err := parseUUID(cfg.VLESSUUID)
	if err != nil {
		fatal("config: %v", err) // already validated; defensive
	}

	logf := func(format string, args ...any) { log.Printf(format, args...) }
	if !*flagVerbose {
		// Quiet down per-connection chatter; keep startup + error messages.
		logf = func(string, ...any) {}
	}

	dialer := &rdpDialer{
		server:    cfg.Server,
		cookie:    cfg.Cookie,
		sni:       cfg.SNI,
		hostname:  cfg.Hostname,
		insecure:  cfg.Insecure,
		uuid:      uuid,
	}

	ln, err := net.Listen("tcp", cfg.LocalSOCKS)
	if err != nil {
		fatal("listen %s: %v", cfg.LocalSOCKS, err)
	}

	// Bring up the UDP relay on the same host as the TCP listener.
	// We resolve the TCP listen host (probably 127.0.0.1) and bind UDP
	// on an ephemeral port there. tun2socks gets that port back via the
	// SOCKS5 UDP ASSOCIATE reply.
	udpHost, _, _ := net.SplitHostPort(cfg.LocalSOCKS)
	if udpHost == "" {
		udpHost = "127.0.0.1"
	}
	udpRelay, err := newUDPRelay(dialer, udpHost)
	if err != nil {
		fatal("udp relay listen: %v", err)
	}
	defer udpRelay.Close()
	go udpRelay.Run()

	udpHostBind, udpPortBind := udpRelay.BindAddr()
	log.Printf("sing-rdp-cli %s", version)
	log.Printf("SOCKS5 (TCP) listening on %s", cfg.LocalSOCKS)
	log.Printf("SOCKS5 (UDP) listening on %s:%d", udpHostBind, udpPortBind)
	log.Printf("upstream:                 %s (cookie=%s sni=%s)", cfg.Server, cfg.Cookie, cfg.SNI)
	log.Printf("point apps at:            socks5://%s", cfg.LocalSOCKS)

	// Single cancellable context drives shutdown of everything that
	// might be running — the SOCKS5 listener, the TUN orchestration,
	// the spawned tun2socks subprocess.
	ctx, cancel := context.WithCancel(context.Background())

	// Clean shutdown on Ctrl+C / Windows close. On Windows os.Interrupt
	// fires for both Ctrl+C and Ctrl+Break.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Printf("shutting down")
		cancel()
		ln.Close()
	}()

	// If TUN mode requested, run the orchestration in a goroutine. It
	// returns when ctx is cancelled (signal) or tun2socks dies; either
	// way we close the SOCKS5 listener after it to bring the process
	// down fully.
	if *flagTUN {
		go func() {
			if err := runTUN(ctx, cfg); err != nil {
				log.Printf("[tun] %v", err)
			}
			cancel()
			ln.Close()
		}()
	}

	if err := ServeSOCKS5(ln, dialer, udpRelay, logf); err != nil {
		// Listener Close() returns an error here; ignore quietly.
		if isClosed(err) {
			return
		}
		fatal("socks5: %v", err)
	}
}

// rdpDialer is the SOCKS5 Dialer that wraps each outbound connection in
// the full sing-rdp + VLESS stack. We open a fresh RDP tunnel per SOCKS
// connection because the inner VLESS protocol carries the destination
// address in its first request — no mux. This is simple and correct;
// performance can be improved later with sing-box-style connection mux.
type rdpDialer struct {
	server   string
	cookie   string
	sni      string
	hostname string
	insecure bool
	uuid     [16]byte
}

// dialUDP is the UDP analogue of Dial. It opens a VLESS connection in
// UDP-mode (cmd=2) addressed to the packetaddr magic FQDN, which
// triggers sing-box's packetaddr-multiplexing path on the server. After
// that, every datagram on the stream carries its own destination via
// packetaddr framing, so one VLESS conn can fan out to many remotes.
func (d *rdpDialer) dialUDP(ctx context.Context) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	conn, err := rdp.Client(dialCtx, net.Dialer{Timeout: 10 * time.Second}, rdp.ClientConfig{
		Address: d.server,
		Cookie:  d.cookie,
		Mode:    rdp.ModeStandalone,
		TLSConfig: &tls.Config{
			ServerName:         d.sni,
			InsecureSkipVerify: d.insecure,
			MinVersion:         tls.VersionTLS12,
		},
		Identity: credssp.MachineIdentity{
			NetBIOSName:   d.hostname,
			DNSName:       d.hostname,
			NetBIOSDomain: "WORKGROUP",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("rdp: %w", err)
	}
	if err := writeVLESSRequestUDP(conn, d.uuid); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless udp request: %w", err)
	}
	return NewLazyResponseStripper(conn), nil
}

func (d *rdpDialer) Dial(dst string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, fmt.Errorf("bad dst %q: %w", dst, err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := rdp.Client(ctx, net.Dialer{Timeout: 10 * time.Second}, rdp.ClientConfig{
		Address: d.server,
		Cookie:  d.cookie,
		Mode:    rdp.ModeStandalone,
		TLSConfig: &tls.Config{
			ServerName:         d.sni,
			InsecureSkipVerify: d.insecure,
			MinVersion:         tls.VersionTLS12,
		},
		Identity: credssp.MachineIdentity{
			NetBIOSName:   d.hostname,
			DNSName:       d.hostname,
			NetBIOSDomain: "WORKGROUP",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("rdp: %w", err)
	}

	// Speak VLESS on the inner stream. Critical: do NOT block waiting for
	// the response before returning. sing-box's VLESS server holds the
	// 2-byte response until application data flows from either side; the
	// SOCKS5 layer (our caller) holds its success reply until Dial()
	// returns; the browser holds application data until it sees SOCKS5
	// success. Three-way deadlock. Symptom: every connection sat idle for
	// ~15s with up=36B down=0B in the server logs.
	//
	// Fix: send the request, wrap the conn so the first Read lazily
	// strips the VLESS response, return immediately. SOCKS5 success goes
	// out, browser sends data, sing-box-inner's optimization triggers,
	// response + initial data come back, the stripper consumes the
	// 2-byte response transparently.
	if err := writeVLESSRequest(conn, d.uuid, host, port); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless request: %w", err)
	}
	return NewLazyResponseStripper(conn), nil
}

func parsePort(s string) (uint16, error) {
	var p uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad port %q", s)
		}
		p = p*10 + uint64(c-'0')
		if p > 0xFFFF {
			return 0, fmt.Errorf("port out of range: %s", s)
		}
	}
	if p == 0 {
		return 0, fmt.Errorf("port zero")
	}
	return uint16(p), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sing-rdp-cli: "+format+"\n", args...)
	os.Exit(1)
}

func isClosed(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "use of closed network connection" ||
		err.Error() == "accept tcp: use of closed network connection"
}
