package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// VLESS protocol request layout — what we send as the first bytes of the
// inner stream. After this header both sides exchange application data
// freely. See https://xtls.github.io/development/protocols/vless.html
//
//   version (1B)         = 0
//   uuid (16B)
//   addons length (1B)   = 0  (no addons)
//   command (1B)         = 1  (TCP CONNECT)
//   port (2B BE)
//   addr type (1B)       = 1 (IPv4) / 2 (Domain) / 3 (IPv6)
//   addr (variable)
//
// Response from server is:
//   version (1B)         = 0
//   addons length (1B)   = 0
//
// We don't implement UDP, MUX, XTLS flow control, or any addons — VLESS
// over our RDP tunnel doesn't need them.

const (
	vlessVersion = 0
	vlessCmdTCP  = 1

	vlessAddrIPv4   = 1
	vlessAddrDomain = 2
	vlessAddrIPv6   = 3
)

// writeVLESSRequest writes a VLESS CONNECT request for the given destination
// on the already-established conn. Caller is responsible for reading the
// VLESS response *and* draining it before treating subsequent bytes as
// application data — readVLESSResponse handles that.
func writeVLESSRequest(w io.Writer, uuid [16]byte, dstHost string, dstPort uint16) error {
	var hdr []byte
	hdr = append(hdr, vlessVersion)
	hdr = append(hdr, uuid[:]...)
	hdr = append(hdr, 0)             // addons length
	hdr = append(hdr, vlessCmdTCP)   // command
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], dstPort)
	hdr = append(hdr, portBuf[:]...)

	// Address encoding: IPv4 / IPv6 / domain.
	if ip := net.ParseIP(dstHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			hdr = append(hdr, vlessAddrIPv4)
			hdr = append(hdr, ip4...)
		} else {
			hdr = append(hdr, vlessAddrIPv6)
			hdr = append(hdr, ip.To16()...)
		}
	} else {
		if len(dstHost) > 255 {
			return errors.New("vless: domain name too long")
		}
		hdr = append(hdr, vlessAddrDomain)
		hdr = append(hdr, byte(len(dstHost)))
		hdr = append(hdr, dstHost...)
	}

	_, err := w.Write(hdr)
	return err
}

// readVLESSResponse consumes the VLESS server response. Must be called once
// before reading application data. Returns the response version byte (for
// future use) or an error.
func readVLESSResponse(r io.Reader) (byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, fmt.Errorf("vless: read response: %w", err)
	}
	// hdr[0] = version, hdr[1] = addons length
	if hdr[1] > 0 {
		skip := make([]byte, hdr[1])
		if _, err := io.ReadFull(r, skip); err != nil {
			return 0, fmt.Errorf("vless: skip addons: %w", err)
		}
	}
	return hdr[0], nil
}
