//go:build singbox

package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/vpnwrap/sing-rdp/rdp"
	"github.com/vpnwrap/sing-rdp/shape"
)

// Client is a sing-box V2RayClientTransport. It dials a TCP/3389 endpoint,
// performs the RDP handshake (and optionally CredSSP for embed mode), and
// returns a net.Conn carrying tunnel bytes inside Fast-Path PDUs.
type Client struct {
	dialer    N.Dialer
	server    metadata.Socksaddr
	opts      Options
	tlsConfig *tls.Config
}

// NewClient constructs a Client. tlsConfig should use a uTLS-cloned ClientHello
// to match the requested fingerprint; see fingerprint.go.
func NewClient(
	ctx context.Context,
	dialer N.Dialer,
	server metadata.Socksaddr,
	tlsOpt option.OutboundTLSOptions,
	opts Options,
) (*Client, error) {
	tlsCfg, err := buildTLSConfig(tlsOpt, opts.Fingerprint, server.AddrString())
	if err != nil {
		return nil, err
	}
	return &Client{
		dialer:    dialer,
		server:    server,
		opts:      opts,
		tlsConfig: tlsCfg,
	}, nil
}

// DialContext is the sing-box V2RayClientTransport entry point. It returns
// a net.Conn carrying the inner proxy protocol.
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	d := singDialerToNetDialer(c.dialer)

	mode := rdp.ModeStandalone
	if c.opts.Mode == "embed" {
		mode = rdp.ModeEmbed
	}

	conn, err := rdp.Client(ctx, d, rdp.ClientConfig{
		Address:   c.server.String(),
		Cookie:    c.opts.Cookie,
		Mode:      mode,
		TLSConfig: c.tlsConfig,
		Timeout:   30 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	if mode == rdp.ModeEmbed {
		if c.opts.Embed == nil {
			conn.Close()
			return nil, errors.New("rdp: embed mode requires embed options")
		}
		conn, err = openEmbeddedSVC(ctx, conn, *c.opts.Embed)
		if err != nil {
			return nil, err
		}
	}

	// Apply traffic shaping (client side).
	prof := shape.Default()
	if c.opts.Shape != nil {
		applyShapeOverrides(&prof, c.opts.Shape)
	}
	shaped := shape.Wrap(conn, prof, false /*isServer*/)

	// Heartbeats keep idle flows looking like real RDP. Only meaningful on
	// fastPathConn; harmless otherwise.
	hbInt := time.Duration(c.opts.HeartbeatInterval) * time.Second
	if hbInt == 0 {
		hbInt = 5 * time.Second
	}
	stop := rdp.Heartbeater(conn, hbInt)

	return &stopOnClose{Conn: shaped, stop: stop}, nil
}

// V2RayClientTransport interface methods that sing-box expects.

// Network reports the underlying network — always tcp.
func (c *Client) Network() string { return "tcp" }

// RoundTrip is unused for plain stream transports; we satisfy the interface
// only because some sing-box versions probe it.
func (c *Client) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("rdp: RoundTrip not supported")
}

// Close releases any persistent resources. The transport itself holds no
// connections — they live on the outbound conn.
func (c *Client) Close() error { return nil }

var _ adapter.V2RayClientTransport = (*Client)(nil)

type stopOnClose struct {
	net.Conn
	stop func()
}

func (s *stopOnClose) Close() error {
	if s.stop != nil {
		s.stop()
	}
	return s.Conn.Close()
}

// applyShapeOverrides mutates `p` in place based on user-supplied overrides.
func applyShapeOverrides(p *shape.Profile, o *ShapeOptions) {
	if o.TargetDownRatio > 0 {
		p.TargetDownRatio = o.TargetDownRatio
	}
	if o.MaxClientBurst > 0 {
		p.MaxClientBurst = o.MaxClientBurst
	}
	if o.BurstWindowMillis > 0 {
		p.BurstWindow = time.Duration(o.BurstWindowMillis) * time.Millisecond
	}
	if o.ChaffIntervalMs > 0 {
		p.ChaffInterval = time.Duration(o.ChaffIntervalMs) * time.Millisecond
	}
}
