package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// X.224 (COTP) PDU codes we care about.
const (
	cotpConnectionRequest = 0xE0
	cotpConnectionConfirm = 0xD0
	cotpData              = 0xF0
)

// RDP Negotiation request/response types ([MS-RDPBCGR] 2.2.1.1.1 / 2.2.1.2.1).
const (
	rdpNegReq      = 0x01
	rdpNegRsp      = 0x02
	rdpNegFailure  = 0x03
)

// Negotiation protocol flags.
const (
	ProtoStandardRDP = 0x00000000
	ProtoSSL         = 0x00000001
	ProtoHybrid      = 0x00000002 // CredSSP / NLA
	ProtoRDSTLS      = 0x00000004
	ProtoHybridEx    = 0x00000008
)

// ConnectionRequest is the parsed X.224 Connection Request PDU.
type ConnectionRequest struct {
	// Optional routing token / mstshash cookie. Empty if neither was sent.
	Cookie []byte
	// Requested protocols from the RDP_NEG_REQ block (0 if no neg block).
	RequestedProtocols uint32
}

// WriteConnectionRequest emits an X.224 Connection Request with an mstshash cookie
// (mstsc-style) and an RDP_NEG_REQ block requesting the given protocols.
func WriteConnectionRequest(w io.Writer, cookie string, protocols uint32) error {
	var body bytes.Buffer

	// Variable part: "Cookie: mstshash=<cookie>\r\n" if cookie non-empty.
	if cookie != "" {
		body.WriteString("Cookie: mstshash=")
		body.WriteString(cookie)
		body.WriteString("\r\n")
	}
	// RDP_NEG_REQ (8 bytes): type, flags, length=8, requestedProtocols.
	var neg [8]byte
	neg[0] = rdpNegReq
	neg[1] = 0
	binary.LittleEndian.PutUint16(neg[2:], 8)
	binary.LittleEndian.PutUint32(neg[4:], protocols)
	body.Write(neg[:])

	// X.224 header:
	//   LI (length indicator): bytes in header after this byte
	//   code = CR (0xE0)
	//   dstRef (2), srcRef (2), classOpt (1) = 0
	var x224 bytes.Buffer
	hdrLen := 6 + body.Len()
	x224.WriteByte(byte(hdrLen)) // LI
	x224.WriteByte(cotpConnectionRequest)
	x224.Write([]byte{0, 0, 0, 0, 0}) // dst, src, class
	x224.Write(body.Bytes())

	return WriteTPKT(w, x224.Bytes())
}

// ReadConnectionRequest reads and parses an X.224 Connection Request PDU
// (wrapped in TPKT).
func ReadConnectionRequest(r io.Reader) (*ConnectionRequest, error) {
	body, err := ReadTPKT(r)
	if err != nil {
		return nil, err
	}
	if len(body) < 7 {
		return nil, errors.New("rdp: X.224 CR too short")
	}
	if body[1] != cotpConnectionRequest {
		return nil, errors.New("rdp: not an X.224 CR")
	}
	// Skip dst/src/class.
	variable := body[7:]

	out := &ConnectionRequest{}

	// Optional cookie line ending with \r\n.
	if i := bytes.Index(variable, []byte("\r\n")); i >= 0 && bytes.HasPrefix(variable, []byte("Cookie:")) {
		out.Cookie = append([]byte(nil), variable[:i]...)
		variable = variable[i+2:]
	}

	if len(variable) >= 8 && variable[0] == rdpNegReq {
		out.RequestedProtocols = binary.LittleEndian.Uint32(variable[4:])
	}
	return out, nil
}

// WriteConnectionConfirm sends X.224 Connection Confirm with an RDP_NEG_RSP
// selecting `selected`.
func WriteConnectionConfirm(w io.Writer, selected uint32) error {
	var rsp [8]byte
	rsp[0] = rdpNegRsp
	rsp[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(rsp[2:], 8)
	binary.LittleEndian.PutUint32(rsp[4:], selected)

	var x224 bytes.Buffer
	hdrLen := 6 + 8
	x224.WriteByte(byte(hdrLen))
	x224.WriteByte(cotpConnectionConfirm)
	x224.Write([]byte{0, 0, 0, 0, 0})
	x224.Write(rsp[:])
	return WriteTPKT(w, x224.Bytes())
}

// ReadConnectionConfirm parses the server's CC and returns the selected protocol.
func ReadConnectionConfirm(r io.Reader) (uint32, error) {
	body, err := ReadTPKT(r)
	if err != nil {
		return 0, err
	}
	if len(body) < 7 || body[1] != cotpConnectionConfirm {
		return 0, errors.New("rdp: not an X.224 CC")
	}
	variable := body[7:]
	if len(variable) >= 8 && variable[0] == rdpNegRsp {
		return binary.LittleEndian.Uint32(variable[4:]), nil
	}
	if len(variable) >= 8 && variable[0] == rdpNegFailure {
		return 0, errors.New("rdp: server returned RDP_NEG_FAILURE")
	}
	// No negotiation block — standard RDP security.
	return ProtoStandardRDP, nil
}
