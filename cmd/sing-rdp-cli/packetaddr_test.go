package main

import (
	"bytes"
	"testing"
)

func TestPacketAddrRoundtripIPv4(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello dns")
	if err := writePacketAddr(&buf, "1.1.1.1", 53, payload); err != nil {
		t.Fatal(err)
	}

	src, srcDomain, got, err := readPacketAddr(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if srcDomain != "" {
		t.Errorf("expected domain empty, got %q", srcDomain)
	}
	if src.Addr().String() != "1.1.1.1" {
		t.Errorf("src addr: got %s want 1.1.1.1", src.Addr())
	}
	if src.Port() != 53 {
		t.Errorf("src port: got %d want 53", src.Port())
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload: got %q want %q", got, payload)
	}
}

func TestPacketAddrRoundtripDomain(t *testing.T) {
	var buf bytes.Buffer
	if err := writePacketAddr(&buf, "example.com", 443, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	src, srcDomain, got, err := readPacketAddr(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if srcDomain != "example.com" {
		t.Errorf("domain: %q", srcDomain)
	}
	if src.Port() != 443 {
		t.Errorf("port: %d", src.Port())
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Errorf("payload: % x", got)
	}
}

func TestPacketAddrMultipleFrames(t *testing.T) {
	// Verify that back-to-back frames decode cleanly off one stream.
	var buf bytes.Buffer
	if err := writePacketAddr(&buf, "1.2.3.4", 80, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writePacketAddr(&buf, "5.6.7.8", 443, []byte("second")); err != nil {
		t.Fatal(err)
	}

	_, _, p1, err := readPacketAddr(&buf)
	if err != nil {
		t.Fatal(err)
	}
	_, _, p2, err := readPacketAddr(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(p1) != "first" || string(p2) != "second" {
		t.Errorf("got %q / %q", p1, p2)
	}
}

func TestSOCKS5UDPEnvelopeRoundtrip(t *testing.T) {
	payload := []byte("dns query bytes")
	wrapped, err := EncodeSOCKSUDPPacket("8.8.8.8", 53, payload)
	if err != nil {
		t.Fatal(err)
	}
	dst, port, got, err := DecodeSOCKSUDPPacket(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if dst != "8.8.8.8" {
		t.Errorf("dst: %q", dst)
	}
	if port != 53 {
		t.Errorf("port: %d", port)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestSOCKS5UDPEnvelopeDomain(t *testing.T) {
	wrapped, err := EncodeSOCKSUDPPacket("dns.example", 53, []byte("q"))
	if err != nil {
		t.Fatal(err)
	}
	dst, port, _, err := DecodeSOCKSUDPPacket(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if dst != "dns.example" || port != 53 {
		t.Errorf("got %s:%d", dst, port)
	}
}

func TestSOCKS5UDPEnvelopeRejectsShort(t *testing.T) {
	if _, _, _, err := DecodeSOCKSUDPPacket([]byte{1, 2}); err == nil {
		t.Error("expected error on short input")
	}
}
