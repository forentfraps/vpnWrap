package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

// packetaddr — sing-box / xray-core's UDP-multiplexing wire format for VLESS
// inbounds configured with packet_encoding: "packetaddr".
//
// Frame layout for each UDP datagram on the stream:
//
//   [length: 2 bytes big-endian]   // covers atyp + addr + port + payload
//   [atyp:   1 byte]               // 1=IPv4, 3=domain, 4=IPv6
//   [addr:   variable]             // 4 bytes for IPv4, 16 for IPv6,
//                                  // (1-byte length + N bytes) for domain
//   [port:   2 bytes big-endian]
//   [payload: variable]            // (length) - 1 - addr_len - 2 bytes
//
// Why packetaddr and not xudp: packetaddr is dramatically simpler (no
// session/keepalive/end frames, just length-prefixed packets) while
// supporting the same use case — multiple UDP destinations through one
// VLESS UDP connection. Both are supported by sing-box; pick whichever
// matches `packet_encoding` on the server.

const (
	paAtypIPv4   = 0x01
	paAtypDomain = 0x03
	paAtypIPv6   = 0x04

	// 65535 - (1 atyp + 256 domain + 2 port) headroom; in practice
	// fragmentation kicks in well before we hit this.
	paMaxPayload = 65535 - 256
)

// writePacketAddr serializes one UDP packet (dst + payload) onto w in
// packetaddr format. The destination may be an IPv4, IPv6, or unresolved
// hostname address.
func writePacketAddr(w io.Writer, dstHost string, dstPort uint16, payload []byte) error {
	if len(payload) > paMaxPayload {
		return fmt.Errorf("packetaddr: payload too large (%d > %d)", len(payload), paMaxPayload)
	}

	// Build the inner portion (everything covered by the length prefix).
	var inner []byte
	if ip := net.ParseIP(dstHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			inner = append(inner, paAtypIPv4)
			inner = append(inner, ip4...)
		} else {
			inner = append(inner, paAtypIPv6)
			inner = append(inner, ip.To16()...)
		}
	} else {
		if len(dstHost) == 0 || len(dstHost) > 255 {
			return fmt.Errorf("packetaddr: bad domain %q", dstHost)
		}
		inner = append(inner, paAtypDomain)
		inner = append(inner, byte(len(dstHost)))
		inner = append(inner, dstHost...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], dstPort)
	inner = append(inner, portBuf[:]...)
	inner = append(inner, payload...)

	// Length prefix and emit.
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(inner)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(inner); err != nil {
		return err
	}
	return nil
}

// readPacketAddr reads one packetaddr frame off r and returns the source
// (set by the remote on responses) and the payload.
//
// Note on direction: the server uses the same on-wire format for
// responses, but the "addr" field there describes the remote endpoint
// the packet *came from*, not where it's going. The caller treats it as
// a source address.
func readPacketAddr(r io.Reader) (srcAddr netip.AddrPort, srcDomain string, payload []byte, err error) {
	var lenBuf [2]byte
	if _, err = io.ReadFull(r, lenBuf[:]); err != nil {
		return
	}
	total := binary.BigEndian.Uint16(lenBuf[:])
	if total < 1+2 { // atyp + port at minimum
		err = errors.New("packetaddr: frame too short")
		return
	}

	buf := make([]byte, total)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}

	// Parse: atyp, addr, port, payload.
	atyp := buf[0]
	rest := buf[1:]
	switch atyp {
	case paAtypIPv4:
		if len(rest) < 4+2 {
			err = errors.New("packetaddr: ipv4 frame truncated")
			return
		}
		ip, _ := netip.AddrFromSlice(rest[:4])
		port := binary.BigEndian.Uint16(rest[4:6])
		srcAddr = netip.AddrPortFrom(ip, port)
		payload = rest[6:]
	case paAtypIPv6:
		if len(rest) < 16+2 {
			err = errors.New("packetaddr: ipv6 frame truncated")
			return
		}
		ip, _ := netip.AddrFromSlice(rest[:16])
		port := binary.BigEndian.Uint16(rest[16:18])
		srcAddr = netip.AddrPortFrom(ip, port)
		payload = rest[18:]
	case paAtypDomain:
		if len(rest) < 1 {
			err = errors.New("packetaddr: domain length missing")
			return
		}
		dlen := int(rest[0])
		if len(rest) < 1+dlen+2 {
			err = errors.New("packetaddr: domain frame truncated")
			return
		}
		srcDomain = string(rest[1 : 1+dlen])
		port := binary.BigEndian.Uint16(rest[1+dlen : 1+dlen+2])
		srcAddr = netip.AddrPortFrom(netip.Addr{}, port) // addr empty for domain
		payload = rest[1+dlen+2:]
	default:
		err = fmt.Errorf("packetaddr: unknown atyp 0x%02x", atyp)
	}
	return
}
