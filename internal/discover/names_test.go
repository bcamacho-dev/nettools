package discover

import (
	"net/netip"
	"testing"
)

func TestPTRNames(t *testing.T) {
	msg := []byte{
		0x00, 0x07,
		0x84, 0x00,
		0x00, 0x00,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		3, 'f', 'o', 'o', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0x00, 12,
		0x00, 1,
		0, 0, 0, 0,
		0, 11,
		3, 'b', 'a', 'r', 5, 'l', 'o', 'c', 'a', 'l', 0,
	}
	id, names := ptrNames(msg)
	if id != 7 || len(names) != 1 || names[0] != "bar.local" {
		t.Fatalf("id=%d names=%v", id, names)
	}
	q := ptrQuery(7, netip.MustParseAddr("192.168.1.20"))
	if len(q) < 12 || q[0] != 0 || q[1] != 7 {
		t.Fatalf("query id bytes = %v", q[:2])
	}
}

func TestParseNetBIOS(t *testing.T) {
	name := []byte{1, 'x', 0}
	tail := []byte{0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0, 19}
	rdata := make([]byte, 19)
	rdata[0] = 1
	copy(rdata[1:], []byte("HOST"))
	msg := []byte{0x00, 0x07, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	msg = append(msg, name...)
	msg = append(msg, tail...)
	msg = append(msg, rdata...)
	id, names := ParseNetBIOS(msg)
	if id != 7 || len(names) != 1 || names[0] != "HOST" {
		t.Fatalf("id=%d names=%v", id, names)
	}
}
