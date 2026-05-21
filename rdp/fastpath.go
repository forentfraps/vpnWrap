package rdp

import (
	"encoding/binary"
	"errors"
	"io"
)

// Fast-Path Output PDU framing ([MS-RDPBCGR] 2.2.9.1.2). Once the slow-path
// connection is established and the channel is up, both endpoints can switch
// to fast-path PDUs which are cheaper than TPKT/MCS-wrapped messages.
//
// We use Fast-Path Output for server -> client and Fast-Path Input for the
// opposite direction. Header layout (output side):
//   1 byte:  fpOutputHeader   (action=0, numEvents=0, flags=0)
//   1-2 bytes: length (variable-length encoding)
//   N bytes:  payload (one or more updateHeader+data blocks)
//
// For our purposes we always emit a single FASTPATH_UPDATETYPE_SURFCMDS update
// containing the encrypted tunnel bytes. The receiver knows to strip the
// 1-byte updateHeader and read the rest.

const (
	fastPathOutputAction = 0x00 // action = FASTPATH_OUTPUT (lowest 2 bits)
	fastPathUpdSurfCmds  = 0x04 // FASTPATH_UPDATETYPE_SURFCMDS
)

// WriteFastPath writes one Fast-Path PDU with payload `data`.
func WriteFastPath(w io.Writer, data []byte) error {
	// updateHeader: low nibble = updateCode, high nibble = fragmentation/compression (0)
	bodyLen := 1 + 2 + len(data) // updateHeader + size(u16 LE) + payload
	if bodyLen > 0x7FFF {
		return errors.New("rdp: fast-path body too large")
	}

	// 2-byte length encoding (always use the long form for simplicity):
	// first byte has high bit set, low 7 bits = high 7 bits of length;
	// second byte = low 8 bits of length.
	total := 1 /*header*/ + 2 /*length*/ + bodyLen
	if total > 0x7FFF {
		return errors.New("rdp: fast-path frame too large")
	}

	hdr := make([]byte, 0, 3+bodyLen)
	hdr = append(hdr, fastPathOutputAction)
	hdr = append(hdr, byte(0x80|((total>>8)&0x7F)), byte(total&0xFF))
	hdr = append(hdr, fastPathUpdSurfCmds)
	var sz [2]byte
	binary.LittleEndian.PutUint16(sz[:], uint16(len(data)))
	hdr = append(hdr, sz[:]...)
	hdr = append(hdr, data...)

	_, err := w.Write(hdr)
	return err
}

// ReadFastPath reads one Fast-Path PDU and returns its payload.
func ReadFastPath(r io.Reader) ([]byte, error) {
	var first [2]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return nil, err
	}
	// Decode length: if high bit of first length byte set, two-byte form.
	var total int
	if first[1]&0x80 != 0 {
		var b2 [1]byte
		if _, err := io.ReadFull(r, b2[:]); err != nil {
			return nil, err
		}
		total = int(first[1]&0x7F)<<8 | int(b2[0])
	} else {
		total = int(first[1])
	}

	consumed := 2
	if first[1]&0x80 != 0 {
		consumed = 3
	}
	if total < consumed+3 {
		return nil, errors.New("rdp: fast-path frame too short")
	}
	rest := make([]byte, total-consumed)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	// rest = updateHeader(1) + size(2) + payload
	if rest[0] != fastPathUpdSurfCmds {
		return nil, errors.New("rdp: unexpected fast-path update type")
	}
	size := binary.LittleEndian.Uint16(rest[1:3])
	if int(size) != len(rest)-3 {
		return nil, errors.New("rdp: fast-path size mismatch")
	}
	return rest[3:], nil
}
