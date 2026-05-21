package credssp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

func TestTSRequestRoundtrip(t *testing.T) {
	in := &TSRequest{
		Version:    TSRequestVersion,
		NegoTokens: NewNegoToken([]byte("hello world")),
	}
	b, err := MarshalTSRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnmarshalTSRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != TSRequestVersion {
		t.Errorf("version: got %d", out.Version)
	}
	if len(out.NegoTokens) != 1 || !bytes.Equal(out.NegoTokens[0].NegoToken, []byte("hello world")) {
		t.Errorf("nego token: %+v", out.NegoTokens)
	}
}

func TestTSRequestErrorCode(t *testing.T) {
	in := &TSRequest{
		Version:   TSRequestVersion,
		ErrorCode: StatusLogonFailure,
	}
	b, err := MarshalTSRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnmarshalTSRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.ErrorCode != StatusLogonFailure {
		// Cast the untyped const so it doesn't default to `int` when boxed
		// into Errorf's interface{} args — that overflows on 32-bit GOARCHes
		// (linux/arm, linux/386). int64 matches ErrorCode's field type.
		t.Errorf("errorCode: got 0x%x want 0x%x", out.ErrorCode, int64(StatusLogonFailure))
	}
}

func TestNTLMSignaturesValidate(t *testing.T) {
	id := MachineIdentity{
		NetBIOSName:   "DESKTOP-ABC1234",
		DNSName:       "DESKTOP-ABC1234",
		NetBIOSDomain: "WORKGROUP",
		DNSDomain:     "",
	}
	ch, err := MakeChallenge(id, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !IsChallenge(ch) {
		t.Error("MakeChallenge output isn't recognized as CHALLENGE")
	}
	if !IsNegotiate(MakeNegotiate()) {
		t.Error("MakeNegotiate output isn't recognized")
	}
	auth, err := MakeAuthenticate(id, "Administrator")
	if err != nil {
		t.Fatal(err)
	}
	if !IsAuthenticate(auth) {
		t.Error("MakeAuthenticate output isn't recognized")
	}
}

func TestChallengeContainsHostname(t *testing.T) {
	id := MachineIdentity{
		NetBIOSName:   "DESKTOP-XYZ7890",
		DNSName:       "DESKTOP-XYZ7890",
		NetBIOSDomain: "WORKGROUP",
	}
	ch, err := MakeChallenge(id, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// UTF-16LE encoding of "DESKTOP-XYZ7890" should appear in the payload.
	wantUTF16 := utf16LE("DESKTOP-XYZ7890")
	if !bytes.Contains(ch, wantUTF16) {
		t.Errorf("CHALLENGE doesn't contain UTF-16 hostname")
	}
}

// TestServerClientHandshake exercises the full state machine over an
// in-process pipe: client sends NEGOTIATE, server replies CHALLENGE,
// client sends AUTHENTICATE + pubKeyAuth, server accepts, client sends
// authInfo.
func TestServerClientAccept(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	id := MachineIdentity{
		NetBIOSName:   "DESKTOP-TEST123",
		DNSName:       "DESKTOP-TEST123",
		NetBIOSDomain: "WORKGROUP",
	}

	var wg sync.WaitGroup
	var serverErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = RunServer(a, ServerConfig{Identity: id, Mode: ServerModeAccept})
	}()

	if err := RunClient(b, ClientConfig{Identity: id, UserName: "Administrator"}); err != nil {
		t.Fatalf("client: %v", err)
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server: %v", serverErr)
	}
}

func TestServerRejects(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	id := MachineIdentity{NetBIOSName: "DESKTOP-REJECT0", NetBIOSDomain: "WORKGROUP"}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = RunServer(a, ServerConfig{Identity: id, Mode: ServerModeReject})
	}()

	err := RunClient(b, ClientConfig{Identity: id, UserName: "prober"})
	wg.Wait()

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected AuthError, got %v", err)
	}
	if authErr.NTStatus != StatusLogonFailure {
		// uint32 cast matches NTStatus's field type and avoids the
		// untyped-const-defaulting-to-int overflow on 32-bit platforms.
		t.Errorf("got 0x%x want 0x%x", authErr.NTStatus, uint32(StatusLogonFailure))
	}
}

// io.Discard / io.NopCloser aliases used in earlier drafts; keep imports.
var _ = io.Discard
