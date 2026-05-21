//go:build !windows

package main

import (
	"errors"
	"os"
)

// elevate_other.go: non-Windows stubs. On Linux/macOS the user is
// expected to launch with sudo for TUN mode; we don't try to re-spawn
// ourselves under sudo because the UX of that across desktop envs is
// nothing like Windows UAC.

func isElevated() bool { return os.Geteuid() == 0 }

func relaunchElevated(_ []string) error {
	return errors.New("self-elevation is Windows-only; re-run with sudo")
}

var errUserCancelled = errors.New("user cancelled elevation")

func enableANSI() {}
