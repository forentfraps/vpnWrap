// sing-rdp-tun is a system-wide TUN-mode VPN client. It creates a TUN
// interface (Wintun on Windows, /dev/net/tun on Linux/macOS) and forwards
// every TCP connection that arrives there through the existing RDP+VLESS
// tunnel.
//
// Compared to sing-rdp-cli (SOCKS5-only), this gives you a "real VPN"
// experience — every application's traffic goes through the tunnel
// without per-app proxy config.
//
// Requirements:
//
//   - Windows: wintun.dll alongside the .exe. Run as Administrator.
//   - Linux:   root or CAP_NET_ADMIN. /dev/net/tun must exist.
//   - macOS:   root (utun device creation requires it).
//
// Usage:
//
//   sing-rdp-tun -c sing-rdp.json
//
// The config schema is documented in config.go — it's a superset of the
// sing-rdp-cli config with tun_* fields added.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	flagConfig = flag.String("c", "sing-rdp.json", "path to JSON config file")
)

const version = "0.1.0"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "sing-rdp-tun %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [-c sing-rdp.json]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Creates a TUN interface and routes all TCP through an RDP+VLESS tunnel.")
		fmt.Fprintln(os.Stderr, "Run as administrator (Windows) or root (Linux/macOS).")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
	}
	flag.Parse()

	cfg, err := LoadConfig(*flagConfig)
	if err != nil {
		fatal("config: %v", err)
	}

	dialer, err := newDialer(cfg)
	if err != nil {
		fatal("dialer: %v", err)
	}

	prefix, err := netip.ParsePrefix(cfg.TunAddress)
	if err != nil {
		fatal("tun_address %q: %v", cfg.TunAddress, err)
	}

	tunOptions := tun.Options{
		Name:         cfg.TunName,
		MTU:          uint32(cfg.TunMTU),
		Inet4Address: []netip.Prefix{prefix},
		AutoRoute:    cfg.AutoRoute,
		// Excluded addresses: the VPS itself must be reachable via the
		// original physical route, otherwise we'd loop. AutoRoute=true on
		// sing-tun handles this automatically when AutoRedirect is set —
		// see docs for details. For safety, also tell the OS not to
		// route loopback through us.
		Inet4RouteExcludeAddress: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
		},
	}

	tunIf, err := tun.New(tunOptions)
	if err != nil {
		fatal("create tun (need admin/root + wintun.dll on Windows): %v", err)
	}
	defer tunIf.Close()

	log.Printf("sing-rdp-tun %s", version)
	log.Printf("tun:      %s %s mtu=%d", cfg.TunName, cfg.TunAddress, cfg.TunMTU)
	log.Printf("upstream: %s (cookie=%s sni=%s)", cfg.Server, cfg.Cookie, cfg.SNI)
	log.Printf("autoroute=%v", cfg.AutoRoute)

	stkLogger := newStackLogger()

	stack, err := tun.NewStack("gvisor", tun.StackOptions{
		Context:    context.Background(),
		Tun:        tunIf,
		TunOptions: tunOptions,
		Logger:     stkLogger,
		Handler:    &handler{dialer: dialer},
	})
	if err != nil {
		fatal("stack: %v", err)
	}
	if err := stack.Start(); err != nil {
		fatal("stack start: %v", err)
	}
	defer stack.Close()

	log.Printf("stack started; routing all TCP through tunnel")
	log.Printf("apps should now reach the internet via %s — Ctrl+C to stop", cfg.Server)

	// Block on signal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
}

// handler implements sing-tun's connection handler interface. For each TCP
// connection that the netstack accepts off the TUN, we dial through the
// VLESS+RDP tunnel and splice the bytes.
type handler struct {
	dialer *rdpVlessDialer
}

// NewConnection is called by sing-tun whenever the netstack accepts a TCP
// connection destined for one of our TUN-routed addresses.
func (h *handler) NewConnection(ctx context.Context, local net.Conn, metadata M.Metadata) error {
	defer local.Close()

	dst := metadata.Destination.String() // "host:port"
	log.Printf("conn -> %s", dst)

	upstream, err := h.dialer.DialContext(ctx, "tcp", dst)
	if err != nil {
		log.Printf("dial %s: %v", dst, err)
		return err
	}
	defer upstream.Close()

	// Bidirectional copy. sing-box uses N.CopyEarlyConn but for our
	// simple two-conn splice the stdlib io.Copy via goroutines is fine.
	return bidirectionalCopy(local, upstream)
}

// NewPacketConnection is called for UDP. We don't support UDP yet — the
// VLESS+RDP path is TCP-only. DNS will fall through if it goes via TCP
// (DoT, DoH), otherwise the user needs to configure system DNS to use
// TCP queries or run their own DoT/DoH resolver.
func (h *handler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	log.Printf("udp -> %s (UDP not supported, dropping)", metadata.Destination.String())
	return conn.Close()
}

func bidirectionalCopy(a, b net.Conn) error {
	errCh := make(chan error, 2)
	go func() { _, err := buf.Copy(a, b); errCh <- err }()
	go func() { _, err := buf.Copy(b, a); errCh <- err }()
	return <-errCh
}

// stackLogger adapts our log.Printf to sing's logger interface so sing-tun
// can report internal events through the same output stream as the rest
// of the binary.
func newStackLogger() logger.ContextLogger {
	return &stkLogger{}
}

type stkLogger struct{}

func (s *stkLogger) Trace(args ...any)                                       {}
func (s *stkLogger) Debug(args ...any)                                       {}
func (s *stkLogger) Info(args ...any)                                        { log.Println(args...) }
func (s *stkLogger) Warn(args ...any)                                        { log.Println(args...) }
func (s *stkLogger) Error(args ...any)                                       { log.Println(args...) }
func (s *stkLogger) Fatal(args ...any)                                       { log.Fatalln(args...) }
func (s *stkLogger) Panic(args ...any)                                       { log.Panicln(args...) }
func (s *stkLogger) TraceContext(ctx context.Context, args ...any)           {}
func (s *stkLogger) DebugContext(ctx context.Context, args ...any)           {}
func (s *stkLogger) InfoContext(ctx context.Context, args ...any)            { log.Println(args...) }
func (s *stkLogger) WarnContext(ctx context.Context, args ...any)            { log.Println(args...) }
func (s *stkLogger) ErrorContext(ctx context.Context, args ...any)           { log.Println(args...) }
func (s *stkLogger) FatalContext(ctx context.Context, args ...any)           { log.Fatalln(args...) }
func (s *stkLogger) PanicContext(ctx context.Context, args ...any)           { log.Panicln(args...) }

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sing-rdp-tun: "+format+"\n", args...)
	os.Exit(1)
}

// Force linter to keep `net` imported when only its package is referenced.
var _ = (*net.Conn)(nil)
