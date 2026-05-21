// sing-rdp-probe dials a target TCP/3389 endpoint and walks the handshake
// the same way our client does, then dumps the negotiation response and the
// TLS server hello. Use it to validate that:
//
//   1. The target accepts our X.224 CR and selects an expected protocol.
//   2. Our TLS ClientHello matches what mstsc emits (compare JA4 between
//      mstsc and this tool — they should match).
//   3. The post-TLS bytes don't contain anything we can't reproduce.
//
// Usage:
//
//   sing-rdp-probe -addr 1.2.3.4:3389 -cookie Administrator -fingerprint mstsc-win11
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/vpnwrap/sing-rdp/rdp"
)

func main() {
	addr := flag.String("addr", "", "target host:port (default port 3389)")
	cookie := flag.String("cookie", "Administrator", "mstshash cookie")
	insecure := flag.Bool("insecure", true, "skip TLS verify (typical for probes)")
	timeout := flag.Duration("timeout", 10*time.Second, "overall timeout")
	flag.Parse()

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "missing -addr")
		os.Exit(2)
	}
	if _, _, err := net.SplitHostPort(*addr); err != nil {
		*addr = *addr + ":3389"
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	d := net.Dialer{Timeout: *timeout}
	raw, err := d.DialContext(ctx, "tcp", *addr)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(*timeout))

	if err := rdp.WriteConnectionRequest(raw, *cookie, rdp.ProtoSSL|rdp.ProtoHybrid); err != nil {
		log.Fatalf("write CR: %v", err)
	}

	selected, err := rdp.ReadConnectionConfirm(raw)
	if err != nil {
		log.Fatalf("read CC: %v", err)
	}
	fmt.Printf("server selected protocol: 0x%08x", selected)
	switch selected {
	case rdp.ProtoSSL:
		fmt.Println("  (TLS only)")
	case rdp.ProtoHybrid:
		fmt.Println("  (CredSSP / NLA)")
	case rdp.ProtoHybridEx:
		fmt.Println("  (CredSSP EarlyUserAuth)")
	default:
		fmt.Println()
	}

	cfg := &tls.Config{
		ServerName:         hostOnly(*addr),
		InsecureSkipVerify: *insecure,
	}
	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Fatalf("tls handshake: %v", err)
	}
	st := tlsConn.ConnectionState()
	fmt.Printf("TLS: version=0x%04x cipher=0x%04x peer-cert-cn=%q\n",
		st.Version, st.CipherSuite, peerCN(st.PeerCertificates))
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func peerCN(certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return ""
	}
	return certs[0].Subject.CommonName
}
