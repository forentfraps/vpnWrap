// Package credssp implements just enough of [MS-CSSP] for our purposes:
// emit/parse TSRequest messages that wrap an NTLMSSP exchange, drive the
// state machine to either accept (cookie-matched tunnel client) or reject
// (active prober) credentials, and produce post-CredSSP bytes that match
// what a real Windows RDP server emits.
//
// We do NOT implement the cryptographic checks (NTLMv2 response validation,
// pubKeyAuth signing). The purpose is byte-correct mimicry — to pass DPI
// and active probing — not actual authentication. Real user auth happens
// out of band via the magic cookie in the X.224 Connection Request.
//
// References:
//   - [MS-CSSP]: Credential Security Support Provider Protocol
//   - [MS-NLMP]: NT LAN Manager Authentication Protocol
package credssp

import (
	"encoding/asn1"
	"errors"
)

// Current TSRequest version negotiated by Windows 10/11 mstsc.
const TSRequestVersion = 6

// TSRequest is the wire form of the credssp message. Per MS-CSSP 2.2.1.
//
// Note: encoding/asn1's `optional` tag works correctly for slice fields
// (nil = omitted), and `explicit,tag:N` produces the [N] EXPLICIT wrapper
// CredSSP expects.
//
// ErrorCode is int64, not int — NTSTATUS values like STATUS_LOGON_FAILURE
// (0xC000006D = 3,221,225,581) exceed 2^31-1 and overflow `int` when
// compiled for 32-bit platforms (linux/arm, linux/386). int64 also matches
// the unsigned-32-bit semantics Windows uses on the wire: encoding/asn1
// emits the value with a leading 00 byte for the positive form, which is
// what mstsc/CredSSP expects.
type TSRequest struct {
	Version     int        `asn1:"explicit,tag:0"`
	NegoTokens  []NegoItem `asn1:"explicit,optional,tag:1"`
	AuthInfo    []byte     `asn1:"explicit,optional,tag:2"`
	PubKeyAuth  []byte     `asn1:"explicit,optional,tag:3"`
	ErrorCode   int64      `asn1:"explicit,optional,tag:4"`
	ClientNonce []byte     `asn1:"explicit,optional,tag:5"`
}

// NegoItem wraps a single NTLMSSP token inside a NegoData SEQUENCE.
type NegoItem struct {
	NegoToken []byte `asn1:"explicit,tag:0"`
}

// MarshalTSRequest encodes a TSRequest to DER.
func MarshalTSRequest(r *TSRequest) ([]byte, error) {
	return asn1.Marshal(*r)
}

// UnmarshalTSRequest parses a DER TSRequest. Trailing bytes are an error
// (we only expect one TSRequest per CredSSP message).
func UnmarshalTSRequest(b []byte) (*TSRequest, error) {
	var r TSRequest
	rest, err := asn1.Unmarshal(b, &r)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("credssp: trailing bytes after TSRequest")
	}
	return &r, nil
}

// NewNegoToken is a convenience constructor: wrap raw NTLMSSP bytes in a
// single-item NegoData list.
func NewNegoToken(ntlmssp []byte) []NegoItem {
	return []NegoItem{{NegoToken: ntlmssp}}
}

// Windows NTSTATUS values used in the errorCode field on rejection.
const (
	StatusLogonFailure         = 0xC000006D
	StatusAccountRestriction   = 0xC000006E
	StatusInvalidLogonHours    = 0xC000006F
	StatusInvalidWorkstation   = 0xC0000070
	StatusPasswordExpired      = 0xC0000071
	StatusAccountDisabled      = 0xC0000072
)
