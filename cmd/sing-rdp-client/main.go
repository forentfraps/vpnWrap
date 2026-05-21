// sing-rdp-client is the standalone client-side entry point. It accepts
// local TCP connections (typically from a sing-box / xray outbound dialing
// 127.0.0.1:<local>), wraps each one in the RDP transport, and forwards to
// a remote sing-rdp-server.
//
// Usage on the user side:
//
//   sing-rdp-client \
//     --local :1081 \
//     --remote vps.example.com:3389 \
//     --cookie svc-jumpbox \
//     --sni vps.example.com
//
// Then point a normal SOCKS/HTTP client at 127.0.0.1:1081 (or chain
// sing-box's outbound through this address).
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"time"

	"github.com/vpnwrap/sing-rdp/rdp"
	"github.com/vpnwrap/sing-rdp/rdp/credssp"
	"github.com/vpnwrap/sing-rdp/shape"
)

func main() {
	local := flag.String("local", "127.0.0.1:1081", "local listen address")
	remote := flag.String("remote", "", "remote sing-rdp-server (host:3389)")
	cookie := flag.String("cookie", "", "magic cookie value")
	sni := flag.String("sni", "", "TLS SNI / ServerName (default: host of --remote)")
	hostname := flag.String("hostname", "DESKTOP-CLIENT0", "machine name emitted in CredSSP AUTHENTICATE")
	insecure := flag.Bool("insecure", false, "skip TLS verification (testing only)")
	hbInterval := flag.Duration("heartbeat", 5*time.Second, "Fast-Path heartbeat interval")
	flag.Parse()

	if *remote == "" || *cookie == "" {
		log.Fatal("--remote and --cookie are required")
	}
	serverName := *sni
	if serverName == "" {
		h, _, err := net.SplitHostPort(*remote)
		if err != nil {
			log.Fatalf("parse remote: %v", err)
		}
		serverName = h
	}

	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: *insecure,
		MinVersion:         tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", *local)
	if err != nil {
		log.Fatalf("listen %s: %v", *local, err)
	}
	log.Printf("sing-rdp-client local=%s remote=%s", *local, *remote)

	identity := credssp.MachineIdentity{
		NetBIOSName:   *hostname,
		DNSName:       *hostname,
		NetBIOSDomain: "WORKGROUP",
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleClient(c, *remote, *cookie, tlsCfg, *hbInterval, identity)
	}
}

func handleClient(local net.Conn, remote, cookie string, tlsCfg *tls.Config, hb time.Duration, identity credssp.MachineIdentity) {
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rconn, err := rdp.Client(ctx, net.Dialer{Timeout: 10 * time.Second}, rdp.ClientConfig{
		Address:   remote,
		Cookie:    cookie,
		Mode:      rdp.ModeStandalone,
		TLSConfig: tlsCfg,
		Identity:  identity,
		Timeout:   30 * time.Second,
	})
	if err != nil {
		log.Printf("dial %s: %v", remote, err)
		return
	}
	defer rconn.Close()

	shaped := shape.Wrap(rconn, shape.Default(), false /*isClient*/)
	stop := rdp.Heartbeater(rconn, hb)
	defer stop()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(shaped, local); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, shaped); done <- struct{}{} }()
	<-done
}
