package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
)

// Config is the JSON shape `deploy.sh client-config --json` emits and what
// users edit by hand on Windows. We keep it intentionally small — one
// flat object, no nested structs, all fields commented in the doc.
//
// Example:
//
//	{
//	  "server":      "vps.example.com:3389",
//	  "cookie":      "user-1234",
//	  "sni":         "DESKTOP-ABC1234",
//	  "vless_uuid":  "11111111-2222-3333-4444-555555555555",
//	  "local_socks": "127.0.0.1:1080",
//	  "hostname":    "DESKTOP-CLIENT0",
//	  "insecure":    true
//	}
type Config struct {
	// Server is the VPS's host:port (sing-rdp-server endpoint).
	Server string `json:"server"`
	// Cookie is the mstshash value (cookie-gate magic).
	Cookie string `json:"cookie"`
	// SNI is the TLS server_name (typically the DESKTOP-XXX hostname).
	SNI string `json:"sni"`
	// VLESSUUID authenticates with the inner sing-box VLESS inbound.
	VLESSUUID string `json:"vless_uuid"`
	// LocalSOCKS is where the SOCKS5 server listens locally. Apps point
	// their proxy setting here. Default 127.0.0.1:1080.
	LocalSOCKS string `json:"local_socks"`
	// Hostname is the machine name we emit in the CredSSP AUTHENTICATE
	// message. Should look like a normal Windows client (e.g.
	// "DESKTOP-CLIENT0"). Doesn't have to match the server's hostname.
	Hostname string `json:"hostname"`
	// Insecure skips TLS verification. Required when the server uses a
	// self-signed cert (the default for sing-rdp deployments).
	Insecure bool `json:"insecure"`
}

// LoadConfig reads and validates a config JSON from path.
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

// Validate enforces the required fields. Defaults are filled in separately
// via applyDefaults so validation errors don't get masked by a successful
// default.
func (c *Config) Validate() error {
	switch {
	case c.Server == "":
		return errors.New("server is required (e.g. \"vps.example.com:3389\")")
	case c.Cookie == "":
		return errors.New("cookie is required")
	case c.VLESSUUID == "":
		return errors.New("vless_uuid is required")
	}
	if _, err := parseUUID(c.VLESSUUID); err != nil {
		return fmt.Errorf("vless_uuid: %w", err)
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.LocalSOCKS == "" {
		c.LocalSOCKS = "127.0.0.1:1080"
	}
	if c.Hostname == "" {
		c.Hostname = "DESKTOP-CLIENT0"
	}
	if c.SNI == "" {
		// Caller probably meant the same as the server hostname half.
		if host, _, err := splitHostPort(c.Server); err == nil {
			c.SNI = host
		}
	}
}

// splitHostPort is a tiny helper that wraps net.SplitHostPort but accepts
// addresses without a port (treated as host-only). Used to derive the SNI
// default from the server endpoint when the user didn't set one.
func splitHostPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "", nil
	}
	return host, port, nil
}
