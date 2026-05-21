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
	N "github.com/sagernet/sing/common/network"

	"github.com/vpnwrap/sing-rdp/rdp"
	"github.com/vpnwrap/sing-rdp/shape"
)

// Server is a sing-box V2RayServerTransport. It accepts TCP connections,
// performs the server-side RDP handshake, and hands the resulting net.Conn
// to the inbound proxy handler.
type Server struct {
	handler   adapter.V2RayServerTransportHandler
	tlsConfig *tls.Config
	opts      Options
	listener  net.Listener
}

// NewServer constructs a Server bound to the given handler.
func NewServer(
	ctx context.Context,
	tlsOpt option.InboundTLSOptions,
	opts Options,
	handler adapter.V2RayServerTransportHandler,
) (*Server, error) {
	tlsCfg, err := buildServerTLSConfig(tlsOpt)
	if err != nil {
		return nil, err
	}
	return &Server{
		handler:   handler,
		tlsConfig: tlsCfg,
		opts:      opts,
	}, nil
}

func (s *Server) Network() []string { return []string{N.NetworkTCP} }

// Serve runs the accept loop on listener.
func (s *Server) Serve(listener net.Listener) error {
	s.listener = listener
	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

// ServePacket is required by the interface but RDP is TCP-only.
func (s *Server) ServePacket(listener net.PacketConn) error {
	return errors.New("rdp: packet transport not supported")
}

func (s *Server) handle(raw net.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mode := rdp.ModeStandalone
	if s.opts.Mode == "embed" {
		mode = rdp.ModeEmbed
	}

	conn, err := rdp.Server(ctx, raw, rdp.ServerConfig{
		TLSConfig: s.tlsConfig,
		Mode:      mode,
		Timeout:   30 * time.Second,
	})
	if err != nil {
		// On any handshake failure, fall through to the active-probing
		// honeypot: serve a real RDP login screen so probers see what they
		// expect. See honeypot.go.
		serveHoneypot(raw)
		return
	}

	if mode == rdp.ModeEmbed {
		conn, err = acceptEmbeddedSVC(ctx, conn, s.opts.Embed)
		if err != nil {
			conn.Close()
			return
		}
	}

	prof := shape.Default()
	if s.opts.Shape != nil {
		applyShapeOverrides(&prof, s.opts.Shape)
	}
	shaped := shape.Wrap(conn, prof, true /*isServer*/)

	hbInt := time.Duration(s.opts.HeartbeatInterval) * time.Second
	if hbInt == 0 {
		hbInt = 5 * time.Second
	}
	stop := rdp.Heartbeater(conn, hbInt)
	wrapped := &stopOnClose{Conn: shaped, stop: stop}

	// Pass to sing-box inbound handler. Source = raw.RemoteAddr().
	s.handler.NewConnection(ctx, wrapped, adapter.InboundContext{
		Source: toSocksaddr(raw.RemoteAddr()),
	})
}

func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// RoundTrip is unused server-side but kept for interface parity.
func (s *Server) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("rdp: RoundTrip not supported")
}

var _ adapter.V2RayServerTransport = (*Server)(nil)
