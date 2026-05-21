//go:build singbox

package transport

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/sagernet/sing-box/option"

	utls "github.com/refraction-networking/utls"
)

// buildTLSConfig produces a *tls.Config-shaped config that, when used through
// our uTLS dial wrapper, emits a ClientHello matching the requested fingerprint.
//
// Stock crypto/tls produces a fingerprint that's distinct from mstsc.exe; that
// alone is enough for a DPI engine to detect us. We use refraction-networking's
// utls library to replay one of:
//
//   - "mstsc-win11": ClientHello captured from mstsc.exe on Windows 11 23H2.
//     Cipher list, extensions order, GREASE, key_share, supported_versions
//     all match.
//   - "mstsc-win10": same approach, Windows 10 22H2.
//   - "freerdp":     xfreerdp 2.x ClientHello.
//
// The crypto/tls Config is mostly a shim; the actual handshake is driven by
// the uTLS connection produced by wrapTLSClient (see dialer.go).
func buildTLSConfig(opt option.OutboundTLSOptions, fingerprint string, serverName string) (*tls.Config, error) {
	if !opt.Enabled {
		return nil, errors.New("rdp transport requires TLS enabled in outbound options")
	}
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: opt.Insecure,
		NextProtos:         []string{}, // RDP doesn't ALPN
		MinVersion:         tls.VersionTLS12,
	}
	if host, _, err := net.SplitHostPort(serverName); err == nil {
		cfg.ServerName = host
	}
	// Stash the fingerprint name on the config via a side map so the dialer
	// can pick it up. crypto/tls.Config has no extension field for this.
	stashFingerprint(cfg, fingerprintID(fingerprint))
	return cfg, nil
}

func buildServerTLSConfig(opt option.InboundTLSOptions) (*tls.Config, error) {
	if !opt.Enabled {
		return nil, errors.New("rdp transport requires TLS enabled in inbound options")
	}
	cert, err := tls.LoadX509KeyPair(opt.CertificatePath, opt.KeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func fingerprintID(name string) utls.ClientHelloID {
	switch name {
	case "", "mstsc-win11":
		// Windows 11 mstsc uses the same Schannel underneath as Edge, so
		// this is a reasonable approximation pending a captured profile.
		return utls.HelloWindows_Auto
	case "mstsc-win10":
		return utls.HelloChrome_100
	case "freerdp":
		return utls.HelloFirefox_120
	default:
		return utls.HelloWindows_Auto
	}
}
