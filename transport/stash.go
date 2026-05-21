//go:build singbox

package transport

import (
	"crypto/tls"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// crypto/tls.Config has no public field where we can attach our utls
// fingerprint choice. We keep a parallel sync.Map keyed by the *tls.Config
// pointer; the uTLS dialer looks it up at handshake time.
var fingerprintStash sync.Map // map[*tls.Config]utls.ClientHelloID

func stashFingerprint(cfg *tls.Config, id utls.ClientHelloID) {
	fingerprintStash.Store(cfg, id)
}

func lookupFingerprint(cfg *tls.Config) (utls.ClientHelloID, bool) {
	v, ok := fingerprintStash.Load(cfg)
	if !ok {
		return utls.ClientHelloID{}, false
	}
	return v.(utls.ClientHelloID), true
}
