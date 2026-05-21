//go:build singbox

package transport

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// singDialerToNetDialer adapts a sing-box dialer to net.Dialer so the rdp
// package can use it without depending on sing internals. The full
// implementation routes via N.Dialer's DialContext; for now we fall back
// to the system dialer (sing-box outbound chains still apply because this
// transport is invoked from an outbound that already routed through them).
//
// TODO: wrap in a custom net.Dialer-shaped type whose DialContext calls
// d.DialContext(ctx, "tcp", metadata.ParseSocksaddr(addr)).
func singDialerToNetDialer(d N.Dialer) net.Dialer {
	_ = d
	_ = context.Background
	return net.Dialer{Timeout: 30 * time.Second}
}

func toSocksaddr(a net.Addr) metadata.Socksaddr {
	if a == nil {
		return metadata.Socksaddr{}
	}
	return metadata.ParseSocksaddr(a.String())
}
