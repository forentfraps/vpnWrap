package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/vpnwrap/sing-rdp/rdp"
	"github.com/vpnwrap/sing-rdp/rdp/credssp"
)

// rdpVlessDialer dials a destination through our RDP+VLESS tunnel. Reused
// from sing-rdp-cli, but with a method signature that fits sing-tun's
// upstream-dial expectations.
type rdpVlessDialer struct {
	server   string
	cookie   string
	sni      string
	hostname string
	insecure bool
	uuid     [16]byte
}

func newDialer(cfg *Config) (*rdpVlessDialer, error) {
	uuid, err := parseUUID(cfg.VLESSUUID)
	if err != nil {
		return nil, fmt.Errorf("uuid: %w", err)
	}
	return &rdpVlessDialer{
		server:   cfg.Server,
		cookie:   cfg.Cookie,
		sni:      cfg.SNI,
		hostname: cfg.Hostname,
		insecure: cfg.Insecure,
		uuid:     uuid,
	}, nil
}

// DialContext opens a new RDP tunnel, writes a VLESS request for `addr`
// (host:port), and returns a conn whose Reads transparently strip the
// 2-byte VLESS response. Suitable for direct splice with sing-tun's
// connection handler.
func (d *rdpVlessDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split %q: %w", addr, err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

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

	if err := writeVLESSRequest(conn, d.uuid, host, port); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless request: %w", err)
	}
	return newLazyResponseStripper(conn), nil
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
