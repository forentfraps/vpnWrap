package rdp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/vpnwrap/sing-rdp/rdp/credssp"
)

// HandshakeMode determines how much of the RDP stack we actually perform.
type HandshakeMode int

const (
	// ModeStandalone: we are both client and server of this transport. We
	// always request PROTOCOL_HYBRID (matching mstsc) and perform a
	// bytewise-correct CredSSP exchange — even though we don't validate
	// the credentials. The cookie in the X.224 CR gates real access; the
	// CredSSP dance is camouflage for active probes.
	ModeStandalone HandshakeMode = iota

	// ModeEmbed: client opens a real RDP session to xrdp/Windows, completes
	// NLA, then opens the "VPNW" static virtual channel and tunnels through
	// it. Survives active probing because the server *is* a real RDP server.
	ModeEmbed
)

// ClientConfig configures the client-side handshake.
type ClientConfig struct {
	// Target server address ("host:3389").
	Address string
	// Cookie that goes in "Cookie: mstshash=..." line. Mimics mstsc.
	Cookie string
	// Mode selects standalone vs embed.
	Mode HandshakeMode
	// TLSConfig is required. For best fingerprint use a utls-cloned ClientHello
	// of mstsc.exe — see transport/utls_dialer.go.
	TLSConfig *tls.Config
	// Identity sent in the AUTHENTICATE message. Should look like a normal
	// Windows machine. Default values are filled in if zero.
	Identity credssp.MachineIdentity
	// SkipCredSSP disables the post-TLS CredSSP exchange. Useful for tests;
	// production should leave this false.
	SkipCredSSP bool
	// Deadline for the whole handshake.
	Timeout time.Duration
}

// Client performs the client-side handshake and returns a net.Conn whose
// Read/Write methods carry Fast-Path PDU payloads as raw bytes.
func Client(ctx context.Context, dialer net.Dialer, cfg ClientConfig) (net.Conn, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("rdp: ClientConfig.TLSConfig is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	dialCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	raw, err := dialer.DialContext(dialCtx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("rdp: dial: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(cfg.Timeout))

	// 1) X.224 CR — always request HYBRID + SSL so we match what modern mstsc
	//    emits. (Older clients also sent ProtoStandardRDP but it's deprecated
	//    enough that requesting it now is itself a fingerprint signal.)
	requested := uint32(ProtoSSL | ProtoHybrid)
	if err := WriteConnectionRequest(raw, cfg.Cookie, requested); err != nil {
		raw.Close()
		return nil, fmt.Errorf("rdp: write CR: %w", err)
	}

	// 2) X.224 CC — server picks the protocol.
	selected, err := ReadConnectionConfirm(raw)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("rdp: read CC: %w", err)
	}
	if selected&(ProtoSSL|ProtoHybrid) == 0 {
		raw.Close()
		return nil, fmt.Errorf("rdp: server selected unsupported protocol 0x%x", selected)
	}

	// 3) TLS handshake on the existing connection.
	tlsConn := tls.Client(raw, cfg.TLSConfig)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("rdp: TLS handshake: %w", err)
	}

	// 4) CredSSP (NLA) — runs over the TLS tunnel. We send a bytewise-correct
	//    exchange so any TLS-MITM observer sees the same protocol flow Windows
	//    would emit. Skipped for tests via SkipCredSSP.
	if selected&ProtoHybrid != 0 && !cfg.SkipCredSSP {
		identity := cfg.Identity
		if identity.NetBIOSName == "" {
			identity.NetBIOSName = "DESKTOP-UNKNOWN"
			identity.DNSName = identity.NetBIOSName
			identity.NetBIOSDomain = "WORKGROUP"
		}
		userName := cfg.Cookie
		if userName == "" {
			userName = "Administrator"
		}
		if err := credssp.RunClient(tlsConn, credssp.ClientConfig{
			Identity: identity,
			UserName: userName,
		}); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("rdp: CredSSP: %w", err)
		}
	}

	if cfg.Mode == ModeEmbed {
		_ = tlsConn.SetDeadline(time.Time{})
		return tlsConn, nil
	}

	// Standalone: emit a tiny "ready" marker so the server knows the client
	// considers the handshake complete and can begin Fast-Path framing.
	if err := WriteTPKT(tlsConn, []byte{0x02, cotpData, 0x80, 0x00}); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("rdp: write ready: %w", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})

	return newFastPathConn(tlsConn, true /*isClient*/), nil
}

// ServerConfig configures the server-side handshake.
type ServerConfig struct {
	// TLSConfig is required (cert presented to the client).
	TLSConfig *tls.Config
	// Mode is usually ModeStandalone here. ModeEmbed on the server side means
	// "forward to local xrdp" — see transport/embed_server.go.
	Mode HandshakeMode
	// Identity controls the machine name etc. emitted in the CredSSP
	// CHALLENGE. Should match the TLS cert CN.
	Identity credssp.MachineIdentity
	// CookieMatched tells the server whether the client passed the cookie
	// gate. When false, CredSSP completes with a STATUS_LOGON_FAILURE so
	// active probers see a normal "wrong credentials" outcome and stop.
	CookieMatched bool
	// SkipCredSSP disables CredSSP server-side (test-only).
	SkipCredSSP bool
	// Timeout for the handshake portion.
	Timeout time.Duration
}

// Server runs the server-side handshake on `raw` and returns the established
// transport. The connection passed in should be a freshly-accepted TCP conn.
func Server(ctx context.Context, raw net.Conn, cfg ServerConfig) (net.Conn, error) {
	return ServerWithCR(ctx, raw, nil, cfg)
}

// ServerWithCR is like Server but accepts a pre-parsed ConnectionRequest.
// Pass non-nil cr when you've used PeekConnectionRequest to gate on the
// cookie before continuing. Pass nil to have the function read the CR
// itself.
//
// IMPORTANT: When called via the cookie-gate path, set CookieMatched to
// reflect the gate result. The CredSSP server-side branches on it.
func ServerWithCR(ctx context.Context, raw net.Conn, cr *ConnectionRequest, cfg ServerConfig) (net.Conn, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("rdp: ServerConfig.TLSConfig is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	_ = raw.SetDeadline(time.Now().Add(cfg.Timeout))

	if cr == nil {
		var err error
		cr, err = ReadConnectionRequest(raw)
		if err != nil {
			return nil, fmt.Errorf("rdp: read CR: %w", err)
		}
	}

	// Pick HYBRID if the client offered it (matches Windows server defaults).
	var selected uint32
	switch {
	case cr.RequestedProtocols&ProtoHybrid != 0:
		selected = ProtoHybrid
	case cr.RequestedProtocols&ProtoSSL != 0:
		selected = ProtoSSL
	default:
		return nil, errors.New("rdp: client offered no acceptable protocol")
	}

	if err := WriteConnectionConfirm(raw, selected); err != nil {
		return nil, fmt.Errorf("rdp: write CC: %w", err)
	}

	tlsConn := tls.Server(raw, cfg.TLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("rdp: TLS handshake: %w", err)
	}

	// CredSSP — accept for cookie-matched tunnel clients, reject for everyone
	// else (so probers see STATUS_LOGON_FAILURE just like a real Windows box).
	if selected&ProtoHybrid != 0 && !cfg.SkipCredSSP {
		identity := cfg.Identity
		if identity.NetBIOSName == "" {
			identity.NetBIOSName = "DESKTOP-UNKNOWN"
			identity.DNSName = identity.NetBIOSName
			identity.NetBIOSDomain = "WORKGROUP"
		}
		mode := credssp.ServerModeReject
		if cfg.CookieMatched {
			mode = credssp.ServerModeAccept
		}
		if err := credssp.RunServer(tlsConn, credssp.ServerConfig{
			Identity: identity,
			Mode:     mode,
		}); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("rdp: CredSSP: %w", err)
		}
		if !cfg.CookieMatched {
			// We rejected the prober; don't return a tunnel.
			tlsConn.Close()
			return nil, errors.New("rdp: prober rejected (cookie absent)")
		}
	}

	if cfg.Mode == ModeEmbed {
		_ = tlsConn.SetDeadline(time.Time{})
		return tlsConn, nil
	}

	// Drain client's "ready" marker.
	if _, err := ReadTPKT(tlsConn); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("rdp: read client ready: %w", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})

	return newFastPathConn(tlsConn, false /*isClient*/), nil
}
