package rdp

import (
	"bytes"
	"testing"
)

func TestTPKTRoundtrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x01},
		make([]byte, 1024),
		make([]byte, 0xFFFF-tpktHdrLen),
	}
	for i, c := range cases {
		for j := range c {
			c[j] = byte(j)
		}
		var buf bytes.Buffer
		if err := WriteTPKT(&buf, c); err != nil {
			t.Fatalf("case %d write: %v", i, err)
		}
		got, err := ReadTPKT(&buf)
		if err != nil {
			t.Fatalf("case %d read: %v", i, err)
		}
		if !bytes.Equal(got, c) {
			t.Fatalf("case %d mismatch: got %d bytes, want %d", i, len(got), len(c))
		}
	}
}

func TestTPKTRejectsBadVersion(t *testing.T) {
	bad := []byte{0x04, 0x00, 0x00, 0x05, 0xAA}
	_, err := ReadTPKT(bytes.NewReader(bad))
	if err == nil {
		t.Fatal("expected error on bad TPKT version")
	}
}

func TestTPKTRejectsOversizedBody(t *testing.T) {
	huge := make([]byte, maxTPKTBody+1)
	var buf bytes.Buffer
	if err := WriteTPKT(&buf, huge); err == nil {
		t.Fatal("expected error writing oversized TPKT body")
	}
}
