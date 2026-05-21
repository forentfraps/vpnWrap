package credssp

import (
	"crypto/rand"
	"errors"
)

// ClientConfig parameters the CredSSP client state machine.
type ClientConfig struct {
	// Identity for the AUTHENTICATE message (must match what the server
	// expects in its CHALLENGE TargetInfo for the byte pattern to look
	// consistent). When the peer is our own server, any consistent value
	// works because we don't crypto-validate.
	Identity MachineIdentity

	// UserName placed in the AUTHENTICATE message. Should look like a
	// plausible Windows username — typically the same as the mstshash
	// cookie value to keep the story consistent.
	UserName string
}

// RunClient drives the client-side CredSSP exchange on `conn`. Symmetric
// with RunServer; the conn must already be TLS-wrapped post-CC.
//
// We send a bytewise-correct exchange with random crypto fields. The peer
// (our server) doesn't validate, so the dance completes and we reach the
// post-CredSSP boundary ready to begin our Fast-Path tunnel.
func RunClient(conn Conn, cfg ClientConfig) error {
	// Step 1: send NEGOTIATE.
	r1 := &TSRequest{
		Version:    TSRequestVersion,
		NegoTokens: NewNegoToken(MakeNegotiate()),
	}
	if err := writeTSRequest(conn, r1); err != nil {
		return err
	}

	// Step 2: receive CHALLENGE.
	r2, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if len(r2.NegoTokens) == 0 || !IsChallenge(r2.NegoTokens[0].NegoToken) {
		return errors.New("credssp: expected CHALLENGE in TSRequest #2")
	}

	// Step 3: send AUTHENTICATE + pubKeyAuth.
	auth, err := MakeAuthenticate(cfg.Identity, cfg.UserName)
	if err != nil {
		return err
	}
	pubKeyAuth := make([]byte, 16)
	if _, err := rand.Read(pubKeyAuth); err != nil {
		return err
	}
	r3 := &TSRequest{
		Version:    TSRequestVersion,
		NegoTokens: NewNegoToken(auth),
		PubKeyAuth: pubKeyAuth,
	}
	if err := writeTSRequest(conn, r3); err != nil {
		return err
	}

	// Step 4: receive server's pubKeyAuth response (or errorCode).
	r4, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if r4.ErrorCode != 0 {
		return &AuthError{NTStatus: uint32(r4.ErrorCode)}
	}

	// Step 5: send authInfo (we send 16 random bytes — server discards).
	authInfo := make([]byte, 16)
	if _, err := rand.Read(authInfo); err != nil {
		return err
	}
	r5 := &TSRequest{
		Version:  TSRequestVersion,
		AuthInfo: authInfo,
	}
	return writeTSRequest(conn, r5)
}

// AuthError wraps an NTSTATUS returned by the server during CredSSP.
type AuthError struct{ NTStatus uint32 }

func (e *AuthError) Error() string {
	switch e.NTStatus {
	case StatusLogonFailure:
		return "credssp: STATUS_LOGON_FAILURE (wrong cookie?)"
	case StatusAccountDisabled:
		return "credssp: STATUS_ACCOUNT_DISABLED"
	default:
		return "credssp: NTSTATUS rejection"
	}
}
