package credssp

import (
	"encoding/binary"
	"errors"
	"io"
)

// CredSSP messages on the wire are bare DER TSRequest blobs — no length
// prefix at the CredSSP layer (TLS frames them). To read one, we parse
// the outer SEQUENCE length from the DER bytes themselves.

const (
	maxTSRequest = 64 * 1024
)

func writeTSRequest(w io.Writer, r *TSRequest) error {
	b, err := MarshalTSRequest(r)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readTSRequest(r io.Reader) (*TSRequest, error) {
	// Read SEQUENCE tag (1 byte) + length (1 or more bytes).
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x30 {
		return nil, errors.New("credssp: not a SEQUENCE")
	}

	var bodyLen int
	var lenBytes []byte
	if hdr[1]&0x80 == 0 {
		// Short form: hdr[1] is the length directly.
		bodyLen = int(hdr[1])
	} else {
		// Long form: low 7 bits = number of subsequent length bytes.
		n := int(hdr[1] & 0x7F)
		if n == 0 || n > 4 {
			return nil, errors.New("credssp: bad SEQUENCE length")
		}
		lenBytes = make([]byte, n)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, err
		}
		switch n {
		case 1:
			bodyLen = int(lenBytes[0])
		case 2:
			bodyLen = int(binary.BigEndian.Uint16(lenBytes))
		case 3:
			bodyLen = int(uint32(lenBytes[0])<<16 | uint32(lenBytes[1])<<8 | uint32(lenBytes[2]))
		case 4:
			bodyLen = int(binary.BigEndian.Uint32(lenBytes))
		}
	}
	if bodyLen <= 0 || bodyLen > maxTSRequest {
		return nil, errors.New("credssp: TSRequest body length out of range")
	}

	// Re-assemble the full DER blob for asn1.Unmarshal.
	full := make([]byte, 0, 2+len(lenBytes)+bodyLen)
	full = append(full, hdr[0], hdr[1])
	full = append(full, lenBytes...)
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	full = append(full, body...)
	return UnmarshalTSRequest(full)
}
