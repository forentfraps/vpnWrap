//go:build singbox

package transport

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TransportType is the value sing-box looks up in its V2Ray transport
// registry. Reference it from configs as "transport": { "type": "rdp" }.
const TransportType = "rdp"

// RegisterV2RayTransport installs the RDP transport into a sing-box transport
// registry. Call this from your sing-box build's init() (e.g. a custom
// patched binary, or via the experimental plugin API).
//
// sing-box upstream doesn't yet expose a fully-stable plugin entrypoint for
// V2Ray transports; in practice integrators add a one-line patch to
// transport/v2ray.go's switch statement to route TransportType -> NewClient/
// NewServer. The functions below are designed to drop straight into that
// switch.
func NewClientFromConfig(
	ctx context.Context,
	dialer N.Dialer,
	server metadata.Socksaddr,
	tlsOpt option.OutboundTLSOptions,
	raw json.RawMessage,
) (adapter.V2RayClientTransport, error) {
	var opts Options
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &opts); err != nil {
			return nil, err
		}
	}
	if opts.Mode == "" {
		opts.Mode = "standalone"
	}
	if opts.Mode != "standalone" && opts.Mode != "embed" {
		return nil, errors.New("rdp: mode must be standalone or embed")
	}
	return NewClient(ctx, dialer, server, tlsOpt, opts)
}

func NewServerFromConfig(
	ctx context.Context,
	tlsOpt option.InboundTLSOptions,
	raw json.RawMessage,
	handler adapter.V2RayServerTransportHandler,
) (adapter.V2RayServerTransport, error) {
	var opts Options
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &opts); err != nil {
			return nil, err
		}
	}
	if opts.Mode == "" {
		opts.Mode = "standalone"
	}
	return NewServer(ctx, tlsOpt, opts, handler)
}
