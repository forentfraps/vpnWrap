package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// Minimal MCS (T.125) framing for what RDP actually uses. We don't implement a
// full ASN.1 PER codec — RDP uses a tightly constrained subset and the bytes
// are well-known. Constants below come from observing mstsc + xrdp captures.

// MCS PDU types (DomainMCSPDU) we touch.
const (
	mcsErectDomainRequest = 0x04
	mcsAttachUserRequest  = 0x28
	mcsAttachUserConfirm  = 0x2E
	mcsChannelJoinRequest = 0x38
	mcsChannelJoinConfirm = 0x3E
	mcsSendDataRequest    = 0x64
	mcsSendDataIndication = 0x68
	mcsDisconnectProvider = 0x21
)

// Well-known channel IDs.
const (
	ChannelIO       uint16 = 1003 // I/O channel (display + input)
	ChannelMCSGlob  uint16 = 1001
	ChannelUserBase uint16 = 1002

	// ChannelVPNW is our custom static virtual channel ID. RDP servers assign
	// channel IDs during MCS Connect Response; we reserve this slot for the
	// "VPNW" SVC. Real allocations vary, but for standalone mode (where both
	// ends are us) we pin it.
	ChannelVPNW uint16 = 1010
)

// WriteSendDataRequest wraps `payload` in an MCS Send Data Request bound to channelID.
// User ID is fixed to 1007 (typical mstsc value after attach-user).
func WriteSendDataRequest(w io.Writer, channelID uint16, payload []byte) error {
	var buf bytes.Buffer

	// X.224 Data PDU: LI=2, code=0xF0, EOT=0x80.
	buf.Write([]byte{0x02, cotpData, 0x80})

	// MCS SendDataRequest: type (1B) | initiator userID (2B BE, offset by base) |
	// channelID (2B BE) | dataPriority+segmentation (1B = 0x70) | length (variable).
	buf.WriteByte(mcsSendDataRequest)
	binary.Write(&buf, binary.BigEndian, uint16(1007-1001)) // initiator
	binary.Write(&buf, binary.BigEndian, channelID)
	buf.WriteByte(0x70)
	writeMCSLength(&buf, len(payload))
	buf.Write(payload)

	return WriteTPKT(w, buf.Bytes())
}

// ReadSendDataIndication / Request — same wire format from our perspective,
// distinguished by the PDU type byte. Returns channelID, payload.
func ReadSendData(r io.Reader) (uint16, []byte, error) {
	body, err := ReadTPKT(r)
	if err != nil {
		return 0, nil, err
	}
	// Skip X.224 data header (3 bytes).
	if len(body) < 3 || body[1] != cotpData {
		return 0, nil, errors.New("rdp: expected X.224 data PDU")
	}
	body = body[3:]
	if len(body) < 6 {
		return 0, nil, errors.New("rdp: MCS PDU too short")
	}
	if body[0] != mcsSendDataRequest && body[0] != mcsSendDataIndication {
		return 0, nil, errors.New("rdp: expected MCS Send Data PDU")
	}
	chid := binary.BigEndian.Uint16(body[3:5])
	// body[5] = data priority byte
	payload, _, err := readMCSLength(body[6:])
	if err != nil {
		return 0, nil, err
	}
	return chid, payload, nil
}

// MCS uses ASN.1 PER-style variable length: 1 byte if < 0x80, otherwise
// high bit + length-of-length encoding. We only ever emit/parse 1-2 byte forms.
func writeMCSLength(w io.ByteWriter, n int) {
	if n < 0x80 {
		_ = w.WriteByte(byte(n))
		return
	}
	_ = w.WriteByte(byte(0x80 | ((n >> 8) & 0x7F)))
	_ = w.WriteByte(byte(n & 0xFF))
}

func readMCSLength(b []byte) ([]byte, int, error) {
	if len(b) < 1 {
		return nil, 0, errors.New("rdp: empty MCS length")
	}
	if b[0]&0x80 == 0 {
		n := int(b[0])
		if len(b) < 1+n {
			return nil, 0, errors.New("rdp: MCS length truncated")
		}
		return b[1 : 1+n], 1 + n, nil
	}
	if len(b) < 2 {
		return nil, 0, errors.New("rdp: MCS long length truncated")
	}
	n := int(b[0]&0x7F)<<8 | int(b[1])
	if len(b) < 2+n {
		return nil, 0, errors.New("rdp: MCS long length payload truncated")
	}
	return b[2 : 2+n], 2 + n, nil
}
