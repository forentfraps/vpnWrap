package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Minimal SOCKS5 server (RFC 1928). We implement only what apps actually
// use against us:
//   - method negotiation with NoAuth (0x00)
//   - CONNECT command
//   - IPv4 / IPv6 / domain destinations
//
// We do NOT implement:
//   - UDP ASSOCIATE
//   - BIND
//   - GSSAPI / username-password auth (the SOCKS5 listener is loopback-only)
//
// The signature exposes a single function: ServeSOCKS5 takes a listener
// and a Dialer that knows how to reach the actual destination through our
// RDP+VLESS tunnel.

const (
	socksVer5 = 0x05

	socksMethodNoAuth      = 0x00
	socksMethodNoAcceptable = 0xFF

	socksCmdConnect      = 0x01
	socksCmdUDPAssociate = 0x03

	socksAddrIPv4   = 0x01
	socksAddrDomain = 0x03
	socksAddrIPv6   = 0x04

	socksRepSuccess          = 0x00
	socksRepGeneralFailure   = 0x01
	socksRepCmdNotSupported  = 0x07
	socksRepAddrNotSupported = 0x08
)

// Dialer is what ServeSOCKS5 calls to obtain the TCP connection through
// which it forwards bytes for SOCKS5 CONNECT. The string is "host:port".
type Dialer interface {
	Dial(dst string) (net.Conn, error)
}

// UDPRelay is the SOCKS5 UDP ASSOCIATE backend. When a SOCKS5 client
// requests UDP ASSOCIATE, the server returns the bind address its UDP
// relay listener is bound to; subsequent UDP datagrams from the client
// arrive there and are forwarded by the relay through the VPN tunnel.
//
// Nil disables UDP — clients requesting ASSOCIATE get cmd-not-supported.
type UDPRelay interface {
	// BindAddr returns the host:port the relay listens on. SOCKS5 reports
	// this back to the client in the ASSOCIATE reply.
	BindAddr() (host string, port uint16)
}

// ServeSOCKS5 runs the accept loop until the listener is closed.
func ServeSOCKS5(ln net.Listener, dial Dialer, udp UDPRelay, logf func(string, ...any)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			if err := handleSOCKS5(c, dial, udp); err != nil {
				logf("socks5: %v", err)
			}
		}()
	}
}

func handleSOCKS5(c net.Conn, dial Dialer, udp UDPRelay) error {
	// --- method negotiation ---
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if greet[0] != socksVer5 {
		return errors.New("not SOCKS5")
	}
	methods := make([]byte, greet[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	// We only support NoAuth; reject everything else.
	chosen := byte(socksMethodNoAcceptable)
	for _, m := range methods {
		if m == socksMethodNoAuth {
			chosen = socksMethodNoAuth
			break
		}
	}
	if _, err := c.Write([]byte{socksVer5, chosen}); err != nil {
		return err
	}
	if chosen == socksMethodNoAcceptable {
		return errors.New("client refused NoAuth")
	}

	// --- request ---
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != socksVer5 {
		return errors.New("bad request version")
	}
	// Branch by command. CONNECT is the common TCP case; UDP ASSOCIATE
	// is what tun2socks uses for UDP forwarding.
	switch hdr[1] {
	case socksCmdConnect:
		// fall through to the existing TCP CONNECT path below
	case socksCmdUDPAssociate:
		if udp == nil {
			writeReply(c, socksRepCmdNotSupported)
			return errors.New("UDP ASSOCIATE requested but no UDP relay configured")
		}
		// hdr[3] was already consumed as ATYP — pass it through so the
		// UDP handler doesn't re-read (which would treat the addr's
		// first byte as the atyp and bail).
		return handleUDPAssociate(c, hdr[3], udp)
	default:
		writeReply(c, socksRepCmdNotSupported)
		return fmt.Errorf("unsupported cmd: %d", hdr[1])
	}
	// hdr[2] is RSV, hdr[3] is ATYP.

	var host string
	switch hdr[3] {
	case socksAddrIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return err
		}
		host = net.IP(ip[:]).String()
	case socksAddrIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return err
		}
		host = net.IP(ip[:]).String()
	case socksAddrDomain:
		var lenByte [1]byte
		if _, err := io.ReadFull(c, lenByte[:]); err != nil {
			return err
		}
		buf := make([]byte, lenByte[0])
		if _, err := io.ReadFull(c, buf); err != nil {
			return err
		}
		host = string(buf)
	default:
		writeReply(c, socksRepAddrNotSupported)
		return fmt.Errorf("unsupported atyp: %d", hdr[3])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	// --- open tunnel ---
	dst := net.JoinHostPort(host, strconv.Itoa(int(port)))
	upstream, err := dial.Dial(dst)
	if err != nil {
		writeReply(c, socksRepGeneralFailure)
		return fmt.Errorf("dial %s: %w", dst, err)
	}
	defer upstream.Close()

	if err := writeReply(c, socksRepSuccess); err != nil {
		return err
	}

	// --- splice ---
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
	return nil
}

// writeReply emits a SOCKS5 reply with the given REP code. We set BND.ADDR
// to 0.0.0.0:0 because we never bind a specific address — apps that care
// (rare) can deal.
func writeReply(c net.Conn, rep byte) error {
	reply := []byte{
		socksVer5,
		rep,
		0x00, // RSV
		socksAddrIPv4,
		0, 0, 0, 0, // BND.ADDR
		0, 0, // BND.PORT
	}
	_, err := c.Write(reply)
	return err
}

// handleUDPAssociate finishes the SOCKS5 UDP ASSOCIATE setup. It:
//
//  1. Reads (and discards) the client's claimed DST.ADDR/PORT — per RFC
//     they're informational. tun2socks fills them with 0.
//  2. Reports the UDP relay's bind addr in the success reply.
//  3. Holds the TCP "control" connection open until it closes. When the
//     client drops the control conn, the SOCKS5 standard says the UDP
//     ASSOCIATE ends.
//
// The actual datagram relay (listening on the UDP socket and bridging to
// VLESS) lives in udp.go; this handler just glues the SOCKS5 control
// plane to it.
//
// atyp comes from the request header (hdr[3]) — the caller already
// consumed those 4 bytes, so we MUST NOT read atyp from the wire here
// or we'll treat the addr's first byte as atyp.
func handleUDPAssociate(c net.Conn, atyp byte, udp UDPRelay) error {
	if err := discardSOCKSAddr(c, atyp); err != nil {
		return fmt.Errorf("udp assoc: discard addr: %w", err)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return fmt.Errorf("udp assoc: read port: %w", err)
	}

	host, port := udp.BindAddr()
	if err := writeReplyAddr(c, socksRepSuccess, host, port); err != nil {
		return fmt.Errorf("udp assoc: reply: %w", err)
	}

	// Per RFC 1928 §6, the UDP ASSOCIATE expires when the TCP control
	// connection closes. Block here reading from c (any byte arriving is
	// undefined per spec; we treat EOF / error as termination). The UDP
	// relay itself stays running independent of any single control conn.
	buf := make([]byte, 64)
	for {
		if _, err := c.Read(buf); err != nil {
			return nil // normal shutdown
		}
	}
}

// writeReplyAddr emits the success reply with a concrete BND addr.
// SOCKS5 ASSOCIATE clients (tun2socks included) use this to know where to
// send their UDP datagrams.
func writeReplyAddr(c net.Conn, rep byte, host string, port uint16) error {
	var (
		atyp byte
		addr []byte
	)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp, addr = socksAddrIPv4, ip4
		} else {
			atyp, addr = socksAddrIPv6, ip.To16()
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("bind host too long: %q", host)
		}
		atyp = socksAddrDomain
		addr = append([]byte{byte(len(host))}, host...)
	}
	out := []byte{socksVer5, rep, 0x00, atyp}
	out = append(out, addr...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	out = append(out, portBuf[:]...)
	_, err := c.Write(out)
	return err
}

func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func discardSOCKSAddr(r io.Reader, atyp byte) error {
	switch atyp {
	case socksAddrIPv4:
		return discardN(r, 4)
	case socksAddrIPv6:
		return discardN(r, 16)
	case socksAddrDomain:
		l, err := readByte(r)
		if err != nil {
			return err
		}
		return discardN(r, int(l))
	default:
		return fmt.Errorf("unknown atyp 0x%02x", atyp)
	}
}

func discardN(r io.Reader, n int) error {
	if n == 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}

// EncodeSOCKSUDPPacket wraps a UDP payload for a destination in the SOCKS5
// UDP request format. tun2socks emits this; we parse it on the relay.
// Provided as a helper so udp.go can produce response envelopes back to
// tun2socks in the same shape.
//
//   +----+------+------+----------+----------+----------+
//   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//   +----+------+------+----------+----------+----------+
//   | 2  |  1   |  1   | Variable |    2     | Variable |
//   +----+------+------+----------+----------+----------+
func EncodeSOCKSUDPPacket(dstHost string, dstPort uint16, payload []byte) ([]byte, error) {
	hdr := []byte{0, 0, 0} // RSV(2) + FRAG(1)
	if ip := net.ParseIP(dstHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			hdr = append(hdr, socksAddrIPv4)
			hdr = append(hdr, ip4...)
		} else {
			hdr = append(hdr, socksAddrIPv6)
			hdr = append(hdr, ip.To16()...)
		}
	} else {
		if len(dstHost) > 255 {
			return nil, fmt.Errorf("dst host too long: %q", dstHost)
		}
		hdr = append(hdr, socksAddrDomain)
		hdr = append(hdr, byte(len(dstHost)))
		hdr = append(hdr, dstHost...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], dstPort)
	hdr = append(hdr, portBuf[:]...)
	hdr = append(hdr, payload...)
	return hdr, nil
}

// DecodeSOCKSUDPPacket parses an inbound SOCKS5 UDP datagram from
// tun2socks (or any SOCKS5-UDP client). Returns the dst (host:port) and
// the payload.
func DecodeSOCKSUDPPacket(b []byte) (dstHost string, dstPort uint16, payload []byte, err error) {
	if len(b) < 4 {
		err = fmt.Errorf("socks5 udp: short header (%d)", len(b))
		return
	}
	// b[0:2] = RSV, b[2] = FRAG (we ignore fragmentation), b[3] = ATYP
	atyp := b[3]
	i := 4
	switch atyp {
	case socksAddrIPv4:
		if len(b) < i+4+2 {
			err = fmt.Errorf("socks5 udp: ipv4 truncated")
			return
		}
		dstHost = net.IP(b[i : i+4]).String()
		i += 4
	case socksAddrIPv6:
		if len(b) < i+16+2 {
			err = fmt.Errorf("socks5 udp: ipv6 truncated")
			return
		}
		dstHost = net.IP(b[i : i+16]).String()
		i += 16
	case socksAddrDomain:
		if len(b) < i+1 {
			err = fmt.Errorf("socks5 udp: domain length missing")
			return
		}
		dl := int(b[i])
		i++
		if len(b) < i+dl+2 {
			err = fmt.Errorf("socks5 udp: domain truncated")
			return
		}
		dstHost = string(b[i : i+dl])
		i += dl
	default:
		err = fmt.Errorf("socks5 udp: bad atyp 0x%02x", atyp)
		return
	}
	dstPort = binary.BigEndian.Uint16(b[i : i+2])
	i += 2
	payload = b[i:]
	return
}
