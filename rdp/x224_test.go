package rdp

import (
	"bytes"
	"testing"
)

func TestX224ConnectionRequestRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteConnectionRequest(&buf, "Administrator", ProtoSSL|ProtoHybrid); err != nil {
		t.Fatalf("write: %v", err)
	}
	cr, err := ReadConnectionRequest(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cr.RequestedProtocols != ProtoSSL|ProtoHybrid {
		t.Errorf("protocols: got 0x%x want 0x%x", cr.RequestedProtocols, ProtoSSL|ProtoHybrid)
	}
	if !bytes.Contains(cr.Cookie, []byte("Administrator")) {
		t.Errorf("cookie missing: %q", cr.Cookie)
	}
}

func TestX224ConnectionRequestNoCookie(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteConnectionRequest(&buf, "", ProtoSSL); err != nil {
		t.Fatalf("write: %v", err)
	}
	cr, err := ReadConnectionRequest(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cr.RequestedProtocols != ProtoSSL {
		t.Errorf("protocols: got 0x%x", cr.RequestedProtocols)
	}
	if len(cr.Cookie) != 0 {
		t.Errorf("expected no cookie, got %q", cr.Cookie)
	}
}

func TestX224ConnectionConfirmRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteConnectionConfirm(&buf, ProtoHybrid); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadConnectionConfirm(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != ProtoHybrid {
		t.Errorf("got 0x%x want 0x%x", got, ProtoHybrid)
	}
}

func TestCookieMatching(t *testing.T) {
	var buf bytes.Buffer
	WriteConnectionRequest(&buf, "svc-jumpbox", ProtoSSL)
	cr, _ := ReadConnectionRequest(&buf)

	if !cr.MatchesCookie("svc-jumpbox") {
		t.Error("expected match")
	}
	if cr.MatchesCookie("Administrator") {
		t.Error("expected mismatch")
	}
	if cr.MatchesCookie("") {
		t.Error("expected mismatch on empty magic")
	}
}
