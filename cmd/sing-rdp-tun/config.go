package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
)

// Config is a superset of the sing-rdp-cli config — same RDP/VLESS fields
// plus optional TUN-specific overrides.
//
//   {
//     "server":      "vps.example.com:3389",
//     "cookie":      "user-1234",
//     "sni":         "DESKTOP-XXXXXXX",
//     "vless_uuid":  "11111111-2222-3333-4444-555555555555",
//     "hostname":    "DESKTOP-CLIENT0",
//     "insecure":    true,
//
//     "tun_name":    "singrdp0",
//     "tun_address": "172.19.0.1/30",
//     "tun_mtu":     1500,
//     "auto_route":  true
//   }
type Config struct {
	// --- RDP / VLESS fields (same as sing-rdp-cli) ---
	Server    string `json:"server"`
	Cookie    string `json:"cookie"`
	SNI       string `json:"sni"`
	VLESSUUID string `json:"vless_uuid"`
	Hostname  string `json:"hostname"`
	Insecure  bool   `json:"insecure"`

	// --- TUN-specific fields ---

	// TunName is the OS interface name. Default "singrdp0" (Linux/macOS)
	// or "sing-rdp" (Wintun on Windows — Wintun ignores some of this).
	TunName string `json:"tun_name"`

	// TunAddress is the IPv4 CIDR for our side of the TUN. The remote side
	// is unused (gVisor handles all addressing in userspace). Default
	// 172.19.0.1/30.
	TunAddress string `json:"tun_address"`

	// TunMTU defaults to 1500. Lower it if you're nesting tunnels.
	TunMTU int `json:"tun_mtu"`

	// AutoRoute sets the system default route to the TUN. If false you
	// need to set routes manually (route add ... on Linux,
	// netsh on Windows). Default true. Note: with AutoRoute=true the
	// process must be able to reach the VPS via the *original* route, so
	// we automatically install a host-route exception for the VPS IP.
	AutoRoute bool `json:"auto_route"`
}

// LoadConfig reads, validates, and applies defaults.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) Validate() error {
	switch {
	case c.Server == "":
		return errors.New("server is required")
	case c.Cookie == "":
		return errors.New("cookie is required")
	case c.VLESSUUID == "":
		return errors.New("vless_uuid is required")
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.TunName == "" {
		c.TunName = "singrdp0"
	}
	if c.TunAddress == "" {
		c.TunAddress = "172.19.0.1/30"
	}
	if c.TunMTU == 0 {
		c.TunMTU = 1500
	}
	if c.Hostname == "" {
		c.Hostname = "DESKTOP-CLIENT0"
	}
	if c.SNI == "" {
		if host, _, err := net.SplitHostPort(c.Server); err == nil {
			c.SNI = host
		}
	}
	// AutoRoute zero-value is false; intentionally not auto-flipping to
	// true so users opt in. The deploy.sh-generated config sets it to true
	// explicitly.
}
