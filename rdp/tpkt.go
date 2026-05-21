// Package rdp implements the minimum RDP framing needed to look like a real RDP
// session through the X.224/MCS layers and to carry payload bytes inside
// Fast-Path Output PDUs after the connection is established.
//
// References:
//   - [MS-RDPBCGR]: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting
//   - [MS-RDPEDYC]: Remote Desktop Protocol: Dynamic Virtual Channel Extension
//   - ITU-T T.123 (TPKT), X.224 (COTP)
package rdp

import (
	"encoding/binary"
	"errors"
	"io"
)

// TPKT header per RFC 1006 / T.123. Four bytes: version=3, reserved=0, length (BE u16).
const (
	tpktVersion  = 0x03
	tpktHdrLen   = 4
	maxTPKTBody  = 0xFFFF - tpktHdrLen
)

var errShortTPKT = errors.New("rdp: TPKT length < header")

// WriteTPKT writes a single TPKT frame containing body.
func WriteTPKT(w io.Writer, body []byte) error {
	if len(body) > maxTPKTBody {
		return errors.New("rdp: TPKT body too large")
	}
	hdr := [tpktHdrLen]byte{tpktVersion, 0, 0, 0}
	binary.BigEndian.PutUint16(hdr[2:], uint16(tpktHdrLen+len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// ReadTPKT reads one TPKT frame and returns its body.
func ReadTPKT(r io.Reader) ([]byte, error) {
	var hdr [tpktHdrLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != tpktVersion {
		return nil, errors.New("rdp: not a TPKT frame")
	}
	total := binary.BigEndian.Uint16(hdr[2:])
	if int(total) < tpktHdrLen {
		return nil, errShortTPKT
	}
	body := make([]byte, int(total)-tpktHdrLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}
