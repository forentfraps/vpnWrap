//go:build !windows

package main

import (
	"context"
	"errors"
)

// runTUN is the non-Windows placeholder. Linux and macOS could be added
// later — both need /dev/net/tun or utun + ip route / route(8) commands
// with somewhat different syntax. For now we keep the door open by
// having the flag exist on every platform but politely refuse here.
func runTUN(ctx context.Context, cfg *Config) error {
	return errors.New("-tun is currently only implemented on Windows")
}
