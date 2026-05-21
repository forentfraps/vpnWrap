package main

import (
	"encoding/hex"
	"errors"
	"strings"
)

// parseUUID converts a UUID string ("11111111-2222-3333-4444-555555555555")
// to the 16 raw bytes used inside the VLESS request. Same impl as
// sing-rdp-cli — keeping it here avoids cross-cmd imports.
func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	s = strings.TrimSpace(s)
	if len(s) != 36 {
		return u, errors.New("uuid must be 36 chars (8-4-4-4-12)")
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, errors.New("uuid dashes in wrong positions")
	}
	hexStr := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return u, err
	}
	copy(u[:], b)
	return u, nil
}
