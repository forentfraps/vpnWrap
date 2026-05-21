package credssp

import (
	"crypto/rand"
	"errors"
	"io"
	"time"
)

// ServerMode controls what the server-side state machine does at the end of
// the CredSSP exchange.
type ServerMode int

const (
	// ServerModeAccept completes the dance, accepts whatever AUTHENTICATE
	// the peer sent (no crypto check), and emits a pubKeyAuth response so
	// the client moves on to the RDP MCS phase. Used for tunnel clients
	// that have passed the cookie gate.
	ServerModeAccept ServerMode = iota

	// ServerModeReject completes the NTLM exchange through AUTHENTICATE
	// and then replies with a TSRequest containing errorCode =
	// STATUS_LOGON_FAILURE. Used for active probers who don't have the
	// cookie — they see a normal "wrong credentials" outcome, the same
	// signal a real Windows server would emit.
	ServerModeReject
)

// ServerConfig parameters the CredSSP server state machine.
type ServerConfig struct {
	// Identity controls the machine name/domain values that go into the
	// CHALLENGE message and TargetInfo AV pairs. Should match the cert CN.
	Identity MachineIdentity

	// Mode determines the terminal behaviour. See ServerMode.
	Mode ServerMode

	// ReadTimeout bounds reads of incoming TSRequest messages.
	ReadTimeout time.Duration
}

// Conn is the minimum subset of net.Conn we need (read/write timeouts not
// strictly required — caller can set deadlines on the underlying conn).
type Conn interface {
	io.Reader
	io.Writer
}

// RunServer drives the server-side CredSSP exchange on `conn`, which is
// expected to be the TLS-wrapped RDP connection post-X.224 CC.
//
// State machine:
//   1. Read TSRequest #1 — contains NTLMSSP NEGOTIATE.
//   2. Send TSRequest #2 — contains NTLMSSP CHALLENGE.
//   3. Read TSRequest #3 — contains NTLMSSP AUTHENTICATE + pubKeyAuth.
//   4a. (Accept) Send TSRequest #4 — contains our pubKeyAuth response.
//        Read TSRequest #5 — contains authInfo. Done.
//   4b. (Reject) Send TSRequest #4 — errorCode = STATUS_LOGON_FAILURE. Done.
func RunServer(conn Conn, cfg ServerConfig) error {
	// Step 1: read NEGOTIATE.
	r1, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if len(r1.NegoTokens) == 0 || !IsNegotiate(r1.NegoTokens[0].NegoToken) {
		return errors.New("credssp: expected NEGOTIATE in TSRequest #1")
	}

	// Step 2: send CHALLENGE.
	challenge, err := MakeChallenge(cfg.Identity, nil, filetimeNow())
	if err != nil {
		return err
	}
	r2 := &TSRequest{
		Version:    TSRequestVersion,
		NegoTokens: NewNegoToken(challenge),
	}
	if err := writeTSRequest(conn, r2); err != nil {
		return err
	}

	// Step 3: read AUTHENTICATE + pubKeyAuth.
	r3, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if len(r3.NegoTokens) == 0 || !IsAuthenticate(r3.NegoTokens[0].NegoToken) {
		return errors.New("credssp: expected AUTHENTICATE in TSRequest #3")
	}

	if cfg.Mode == ServerModeReject {
		// Step 4b: tell the peer their credentials were bad. Matches what
		// Windows emits on a failed CredSSP auth.
		bad := &TSRequest{
			Version:   TSRequestVersion,
			ErrorCode: StatusLogonFailure,
		}
		return writeTSRequest(conn, bad)
	}

	// Step 4a: respond with our pubKeyAuth (16 random bytes — peer won't
	// validate because peer is also us).
	resp := make([]byte, 16)
	if _, err := rand.Read(resp); err != nil {
		return err
	}
	r4 := &TSRequest{
		Version:    TSRequestVersion,
		PubKeyAuth: resp,
	}
	if err := writeTSRequest(conn, r4); err != nil {
		return err
	}

	// Step 5: consume authInfo and discard. We don't decrypt — we just
	// need to drain the bytes so the connection is at the post-CredSSP
	// boundary when we hand it back.
	if _, err := readTSRequest(conn); err != nil {
		return err
	}
	return nil
}

// filetimeNow returns the current time as a Windows FILETIME (100ns ticks
// since 1601-01-01 UTC). Used in TargetInfo.MsvAvTimestamp.
func filetimeNow() uint64 {
	const epochDiff = 11644473600 // seconds between 1601 and 1970
	t := time.Now().UTC()
	return uint64((t.Unix()+epochDiff)*10_000_000) + uint64(t.Nanosecond()/100)
}
