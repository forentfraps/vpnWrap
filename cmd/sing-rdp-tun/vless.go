package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Minimal VLESS client — same protocol layout as sing-rdp-cli, kept here so
// this binary has no cross-cmd imports.

const (
	vlessVersion = 0
	vlessCmdTCP  = 1

	vlessAddrIPv4   = 1
	vlessAddrDomain = 2
	vlessAddrIPv6   = 3
)

func writeVLESSRequest(w io.Writer, uuid [16]byte, dstHost string, dstPort uint16) error {
	var hdr []byte
	hdr = append(hdr, vlessVersion)
	hdr = append(hdr, uuid[:]...)
	hdr = append(hdr, 0)
	hdr = append(hdr, vlessCmdTCP)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], dstPort)
	hdr = append(hdr, portBuf[:]...)

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

// LazyResponseStripper consumes the 2-byte VLESS response on the first Read,
// passes through after. Necessary to avoid the three-way deadlock we hit in
// sing-rdp-cli — see the doc comment there for the gory details.
type LazyResponseStripper struct {
	net.Conn
	once     sync.Once
	stripErr error
}

func newLazyResponseStripper(c net.Conn) *LazyResponseStripper {
	return &LazyResponseStripper{Conn: c}
}

func (l *LazyResponseStripper) Read(p []byte) (int, error) {
	l.once.Do(func() {
		var hdr [2]byte
		if _, err := io.ReadFull(l.Conn, hdr[:]); err != nil {
			l.stripErr = fmt.Errorf("vless: read response: %w", err)
			return
		}
		if hdr[1] > 0 {
			if _, err := io.CopyN(io.Discard, l.Conn, int64(hdr[1])); err != nil {
				l.stripErr = fmt.Errorf("vless: skip addons: %w", err)
				return
			}
		}
	})
	if l.stripErr != nil {
		return 0, l.stripErr
	}
	return l.Conn.Read(p)
}
