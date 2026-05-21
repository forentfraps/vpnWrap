package credssp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// NTLMSSP message structure per [MS-NLMP]. We implement only what we need
// to look bytewise-correct on the wire — no real authentication.

const ntlmSignature = "NTLMSSP\x00"

const (
	msgTypeNegotiate    = 0x00000001
	msgTypeChallenge    = 0x00000002
	msgTypeAuthenticate = 0x00000003
)

// Negotiate flags. The set below matches what Windows 10/11 mstsc emits
// in a default-config CredSSP exchange. Don't change without re-capturing
// from a real client.
const (
	flgNegotiateUnicode               = 0x00000001
	flgNegotiateOEM                   = 0x00000002
	flgRequestTarget                  = 0x00000004
	flgNegotiateSign                  = 0x00000010
	flgNegotiateSeal                  = 0x00000020
	flgNegotiateNTLM                  = 0x00000200
	flgNegotiateAlwaysSign            = 0x00008000
	flgNegotiateExtendedSessionSecurity = 0x00080000
	flgTargetTypeServer               = 0x00020000
	flgNegotiateTargetInfo            = 0x00800000
	flgNegotiateVersion               = 0x02000000
	flgNegotiate128                   = 0x20000000
	flgNegotiateKeyExch               = 0x40000000
	flgNegotiate56                    = 0x80000000
)

// DefaultChallengeFlags is the flag set our server sends in CHALLENGE.
// Mirrors a Windows Server 2019 reply.
const DefaultChallengeFlags = flgNegotiateUnicode |
	flgRequestTarget |
	flgNegotiateSign |
	flgNegotiateSeal |
	flgNegotiateNTLM |
	flgNegotiateAlwaysSign |
	flgNegotiateExtendedSessionSecurity |
	flgTargetTypeServer |
	flgNegotiateTargetInfo |
	flgNegotiateVersion |
	flgNegotiate128 |
	flgNegotiateKeyExch |
	flgNegotiate56

// DefaultNegotiateFlags is what our client emits in NEGOTIATE.
const DefaultNegotiateFlags = flgNegotiateUnicode |
	flgNegotiateOEM |
	flgRequestTarget |
	flgNegotiateSign |
	flgNegotiateSeal |
	flgNegotiateNTLM |
	flgNegotiateAlwaysSign |
	flgNegotiateExtendedSessionSecurity |
	flgNegotiateVersion |
	flgNegotiate128 |
	flgNegotiateKeyExch |
	flgNegotiate56

// Version block ([MS-NLMP] 2.2.2.10). 8 bytes: ProductMajor, ProductMinor,
// ProductBuild (LE u16), Reserved×3, NTLMRevisionCurrent.
// Values below are Windows 10 build 19041 (a very common in-the-wild value).
var WindowsVersionBlock = [8]byte{
	0x0a,             // major = 10
	0x00,             // minor = 0
	0x63, 0x45,       // build = 17763 LE... wait actually 0x4563 = 17763, let me use 19041
	0x00, 0x00, 0x00, // reserved
	0x0f,             // NTLMSSP_REVISION_W2K3
}

func init() {
	// 19041 = 0x4A61 little-endian -> bytes 0x61, 0x4A
	WindowsVersionBlock[2] = 0x61
	WindowsVersionBlock[3] = 0x4A
}

// AV_PAIR types ([MS-NLMP] 2.2.2.1).
const (
	avEOL              = 0x0000
	avNbComputerName   = 0x0001
	avNbDomainName     = 0x0002
	avDnsComputerName  = 0x0003
	avDnsDomainName    = 0x0004
	avDnsTreeName      = 0x0005
	avFlags            = 0x0006
	avTimestamp        = 0x0007
	avSingleHost       = 0x0008
	avTargetName       = 0x0009
	avChannelBindings  = 0x000A
)

// utf16LE returns the UTF-16LE encoding of s (no BOM, no terminator).
func utf16LE(s string) []byte {
	enc := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(enc))
	for i, r := range enc {
		binary.LittleEndian.PutUint16(out[2*i:], r)
	}
	return out
}

// MachineIdentity describes the Windows-like host we impersonate.
type MachineIdentity struct {
	// NetBIOSName is the (up to 15-char, uppercase) NetBIOS computer name.
	// Typically the same as the DNS computer name without the suffix.
	NetBIOSName string
	// DNSName is the DNS hostname (e.g. "DESKTOP-A1B2C3D.localdomain" or
	// just "DESKTOP-A1B2C3D" for workgroup machines).
	DNSName string
	// NetBIOSDomain is the workgroup or AD NetBIOS domain ("WORKGROUP" if
	// not domain-joined — extremely common for the machines we mimic).
	NetBIOSDomain string
	// DNSDomain is the AD DNS domain ("" for workgroup machines).
	DNSDomain string
}

// BuildTargetInfo encodes the AV_PAIR block that goes into a Windows
// CHALLENGE_MESSAGE. The order below matches a fresh Windows 10 install
// in a workgroup: NbDomain, NbComputer, DnsDomain, DnsComputer, Timestamp,
// EOL.
func BuildTargetInfo(id MachineIdentity, timestampFiletime uint64) []byte {
	var buf bytes.Buffer
	writeAV := func(typ uint16, value []byte) {
		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:], typ)
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(value)))
		buf.Write(hdr[:])
		buf.Write(value)
	}
	writeAV(avNbDomainName, utf16LE(id.NetBIOSDomain))
	writeAV(avNbComputerName, utf16LE(id.NetBIOSName))
	writeAV(avDnsDomainName, utf16LE(id.DNSDomain))
	writeAV(avDnsComputerName, utf16LE(id.DNSName))

	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], timestampFiletime)
	writeAV(avTimestamp, ts[:])

	writeAV(avEOL, nil)
	return buf.Bytes()
}

// Common errors.
var (
	ErrShortMessage   = errors.New("ntlmssp: message too short")
	ErrBadSignature   = errors.New("ntlmssp: bad signature")
	ErrUnexpectedType = errors.New("ntlmssp: unexpected message type")
)

// CommonHeader validates the NTLMSSP signature and returns the message type.
func messageType(b []byte) (uint32, error) {
	if len(b) < 12 {
		return 0, ErrShortMessage
	}
	if string(b[:8]) != ntlmSignature {
		return 0, ErrBadSignature
	}
	return binary.LittleEndian.Uint32(b[8:12]), nil
}

// MakeChallenge builds an NTLMSSP CHALLENGE_MESSAGE with the given identity.
// The serverChallenge (8 random bytes) is generated if challenge is nil.
func MakeChallenge(id MachineIdentity, challenge []byte, timestampFiletime uint64) ([]byte, error) {
	if challenge == nil {
		challenge = make([]byte, 8)
		if _, err := rand.Read(challenge); err != nil {
			return nil, err
		}
	} else if len(challenge) != 8 {
		return nil, errors.New("ntlmssp: server challenge must be 8 bytes")
	}

	targetName := utf16LE(id.NetBIOSName)
	targetInfo := BuildTargetInfo(id, timestampFiletime)

	// Layout: 48-byte fixed header + 8-byte version + payload (targetName, targetInfo).
	const headerLen = 48
	const versionLen = 8
	payloadOffset := headerLen + versionLen

	var buf bytes.Buffer
	buf.WriteString(ntlmSignature)

	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], msgTypeChallenge)
	buf.Write(u32[:])

	// TargetName fields: len(2) max(2) offset(4)
	writeFields := func(payloadLen, offset uint32) {
		var f [8]byte
		binary.LittleEndian.PutUint16(f[0:], uint16(payloadLen))
		binary.LittleEndian.PutUint16(f[2:], uint16(payloadLen))
		binary.LittleEndian.PutUint32(f[4:], offset)
		buf.Write(f[:])
	}
	writeFields(uint32(len(targetName)), uint32(payloadOffset))

	// Negotiate flags.
	binary.LittleEndian.PutUint32(u32[:], DefaultChallengeFlags)
	buf.Write(u32[:])

	// Server challenge (8 bytes).
	buf.Write(challenge)

	// Reserved (8 bytes).
	buf.Write(make([]byte, 8))

	// TargetInfo fields.
	writeFields(uint32(len(targetInfo)), uint32(payloadOffset)+uint32(len(targetName)))

	// Version block.
	buf.Write(WindowsVersionBlock[:])

	// Payload.
	buf.Write(targetName)
	buf.Write(targetInfo)

	return buf.Bytes(), nil
}

// IsAuthenticate returns true if b looks like an NTLMSSP AUTHENTICATE_MESSAGE.
// We don't validate the contents (we don't authenticate); we just need to
// recognize that the prober/client has supplied one before we can move on.
func IsAuthenticate(b []byte) bool {
	t, err := messageType(b)
	return err == nil && t == msgTypeAuthenticate
}

// IsNegotiate returns true if b is an NTLMSSP NEGOTIATE_MESSAGE.
func IsNegotiate(b []byte) bool {
	t, err := messageType(b)
	return err == nil && t == msgTypeNegotiate
}

// IsChallenge returns true if b is an NTLMSSP CHALLENGE_MESSAGE.
func IsChallenge(b []byte) bool {
	t, err := messageType(b)
	return err == nil && t == msgTypeChallenge
}

// MakeNegotiate builds an NTLMSSP NEGOTIATE_MESSAGE the tunnel client uses.
// We deliberately omit the OEM domain/workstation fields (length 0) — modern
// mstsc does the same when not domain-joined.
func MakeNegotiate() []byte {
	const headerLen = 32
	const versionLen = 8

	var buf bytes.Buffer
	buf.WriteString(ntlmSignature)

	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], msgTypeNegotiate)
	buf.Write(u32[:])

	binary.LittleEndian.PutUint32(u32[:], DefaultNegotiateFlags)
	buf.Write(u32[:])

	// DomainName fields (zero) + WorkstationName fields (zero).
	buf.Write(make([]byte, 16))

	// Version block.
	buf.Write(WindowsVersionBlock[:])

	_ = headerLen
	_ = versionLen
	return buf.Bytes()
}

// MakeAuthenticate builds a bytewise-plausible AUTHENTICATE_MESSAGE. Crypto
// fields are filled with random bytes (the server we talk to is us and
// doesn't validate). For a probing scenario we would never be the client —
// real mstsc would be — so this path is only used by our tunnel client.
func MakeAuthenticate(id MachineIdentity, userName string) ([]byte, error) {
	user := utf16LE(userName)
	domain := utf16LE(id.NetBIOSDomain)
	host := utf16LE(id.NetBIOSName)

	// Fill in random LM/NT responses. NTLMv2 NT response is 24+ bytes
	// including blob; we use 88 bytes which is a typical observed length.
	lmResp := make([]byte, 24)
	ntResp := make([]byte, 88)
	sessKey := make([]byte, 16)
	if _, err := rand.Read(lmResp); err != nil {
		return nil, err
	}
	if _, err := rand.Read(ntResp); err != nil {
		return nil, err
	}
	if _, err := rand.Read(sessKey); err != nil {
		return nil, err
	}

	const fixedLen = 64 // header + 6 field descriptors + flags
	const versionLen = 8
	const micLen = 16
	payloadOffset := fixedLen + versionLen + micLen

	// Concatenate payload in order: LM, NT, Domain, User, Workstation, SessKey.
	var payload bytes.Buffer
	offs := func(b []byte) uint32 { return uint32(payloadOffset + payload.Len()) }
	lmOff := offs(lmResp)
	payload.Write(lmResp)
	ntOff := offs(ntResp)
	payload.Write(ntResp)
	dOff := offs(domain)
	payload.Write(domain)
	uOff := offs(user)
	payload.Write(user)
	hOff := offs(host)
	payload.Write(host)
	sOff := offs(sessKey)
	payload.Write(sessKey)

	var buf bytes.Buffer
	buf.WriteString(ntlmSignature)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], msgTypeAuthenticate)
	buf.Write(u32[:])

	writeFields := func(n uint32, off uint32) {
		var f [8]byte
		binary.LittleEndian.PutUint16(f[0:], uint16(n))
		binary.LittleEndian.PutUint16(f[2:], uint16(n))
		binary.LittleEndian.PutUint32(f[4:], off)
		buf.Write(f[:])
	}
	writeFields(uint32(len(lmResp)), lmOff)
	writeFields(uint32(len(ntResp)), ntOff)
	writeFields(uint32(len(domain)), dOff)
	writeFields(uint32(len(user)), uOff)
	writeFields(uint32(len(host)), hOff)
	writeFields(uint32(len(sessKey)), sOff)

	binary.LittleEndian.PutUint32(u32[:], DefaultNegotiateFlags)
	buf.Write(u32[:])

	buf.Write(WindowsVersionBlock[:])

	// MIC (Message Integrity Code) — zeros, will be ignored.
	buf.Write(make([]byte, micLen))

	buf.Write(payload.Bytes())
	return buf.Bytes(), nil
}
