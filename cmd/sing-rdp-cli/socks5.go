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

	socksCmdConnect = 0x01

	socksAddrIPv4   = 0x01
	socksAddrDomain = 0x03
	socksAddrIPv6   = 0x04

	socksRepSuccess          = 0x00
	socksRepGeneralFailure   = 0x01
	socksRepCmdNotSupported  = 0x07
	socksRepAddrNotSupported = 0x08
)

// Dialer is what ServeSOCKS5 calls to obtain the connection through which
// it forwards bytes. The string is "host:port" — domain or IP.
type Dialer interface {
	Dial(dst string) (net.Conn, error)
}

// ServeSOCKS5 runs the accept loop until the listener is closed.
func ServeSOCKS5(ln net.Listener, dial Dialer, logf func(string, ...any)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			if err := handleSOCKS5(c, dial); err != nil {
				logf("socks5: %v", err)
			}
		}()
	}
}

func handleSOCKS5(c net.Conn, dial Dialer) error {
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
	if hdr[1] != socksCmdConnect {
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
