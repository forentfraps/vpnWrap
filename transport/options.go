//go:build singbox

// Package transport provides the sing-box V2RayClientTransport /
// V2RayServerTransport adapters for the rdp-dvc transport.
//
// Wire-up under VLESS / Trojan looks like:
//
//   "transport": {
//     "type": "rdp",
//     "mode": "standalone" | "embed",
//     "cookie": "Administrator",
//     "fingerprint": "mstsc-win11",
//     "embed": {
//       "upstream": "127.0.0.1:3389",
//       "username": "rdpuser",
//       "password": "..."
//     }
//   }
package transport

// Options are the JSON-decoded transport options as sing-box passes them in.
type Options struct {
	// Mode: "standalone" (default) or "embed".
	Mode string `json:"mode,omitempty"`

	// Cookie placed in the X.224 mstshash field. Some networks key on this
	// being present and looking corporate ("rdpuser", "Administrator").
	Cookie string `json:"cookie,omitempty"`

	// Fingerprint selects a TLS ClientHello profile. Supported:
	//   - "mstsc-win11" (default)
	//   - "mstsc-win10"
	//   - "freerdp"
	Fingerprint string `json:"fingerprint,omitempty"`

	// HeartbeatInterval (seconds) for idle chaff. 0 = default (5s).
	HeartbeatInterval int `json:"heartbeat_interval,omitempty"`

	// Embed contains options for ModeEmbed.
	Embed *EmbedOptions `json:"embed,omitempty"`

	// Shape overrides the default traffic-shape profile.
	Shape *ShapeOptions `json:"shape,omitempty"`
}

// EmbedOptions configure passing through a real RDP server.
type EmbedOptions struct {
	// Upstream is the real RDP server (xrdp / Windows RDS) to forward through.
	Upstream string `json:"upstream"`
	// Username / Password authenticate via CredSSP/NLA.
	Username string `json:"username"`
	Password string `json:"password"`
	// Domain (optional, for AD environments).
	Domain string `json:"domain,omitempty"`
	// ChannelName for the SVC. Defaults to "VPNW".
	ChannelName string `json:"channel_name,omitempty"`
}

// ShapeOptions overrides the default traffic-shaping profile.
type ShapeOptions struct {
	TargetDownRatio   float64 `json:"target_down_ratio,omitempty"`
	MaxClientBurst    int     `json:"max_client_burst,omitempty"`
	BurstWindowMillis int     `json:"burst_window_ms,omitempty"`
	ChaffIntervalMs   int     `json:"chaff_interval_ms,omitempty"`
}
