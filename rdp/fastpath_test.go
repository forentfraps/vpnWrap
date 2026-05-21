package rdp

import (
	"bytes"
	"testing"
)

func TestFastPathRoundtrip(t *testing.T) {
	payloads := [][]byte{
		{0x01, 0x02, 0x03},
		make([]byte, 256),
		make([]byte, 1400),
	}
	for i, p := range payloads {
		for j := range p {
			p[j] = byte(j * 7)
		}
		var buf bytes.Buffer
		if err := WriteFastPath(&buf, p); err != nil {
			t.Fatalf("case %d write: %v", i, err)
		}
		got, err := ReadFastPath(&buf)
		if err != nil {
			t.Fatalf("case %d read: %v", i, err)
		}
		if !bytes.Equal(got, p) {
			t.Fatalf("case %d payload mismatch", i)
		}
	}
}

func TestFastPathBackToBack(t *testing.T) {
	var buf bytes.Buffer
	a, b := []byte("hello"), []byte("world!")
	if err := WriteFastPath(&buf, a); err != nil {
		t.Fatal(err)
	}
	if err := WriteFastPath(&buf, b); err != nil {
		t.Fatal(err)
	}
	got1, _ := ReadFastPath(&buf)
	got2, _ := ReadFastPath(&buf)
	if !bytes.Equal(got1, a) || !bytes.Equal(got2, b) {
		t.Fatalf("mismatch: %q %q", got1, got2)
	}
}
