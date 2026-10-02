package discover

import (
	"fmt"
	"net/netip"
	"strings"

	"nettools/internal/model"
)

func ptrQuery(id uint16, ip netip.Addr) []byte {
	b4 := ip.As4()
	name := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b4[3], b4[2], b4[1], b4[0])
	buf := []byte{byte(id >> 8), byte(id), 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0, 0, 12, 0, 1)
	return buf
}

func ptrNames(msg []byte) (uint16, []string) {
	if len(msg) < 12 {
		return 0, nil
	}
	id := uint16(msg[0])<<8 | uint16(msg[1])
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		_, off, err = readName(msg, off, 0)
		if err != nil || off+4 > len(msg) {
			return id, nil
		}
		off += 4
	}
	var names []string
	for i := 0; i < an; i++ {
		var err error
		_, off, err = readName(msg, off, 0)
		if err != nil || off+10 > len(msg) {
			return id, names
		}
		typ := int(msg[off])<<8 | int(msg[off+1])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if rdlen < 0 || off+rdlen > len(msg) {
			return id, names
		}
		if typ == 12 || typ == 5 {
			name, _, err := readName(msg, off, 0)
			if err == nil && name != "" {
				names = append(names, strings.TrimSuffix(name, "."))
			}
		}
		off += rdlen
	}
	return id, names
}

func readName(msg []byte, off, depth int) (string, int, error) {
	if depth > 8 || off < 0 || off >= len(msg) {
		return "", off, fmt.Errorf("nome DNS inválido")
	}
	var labels []string
	for {
		if off >= len(msg) {
			return "", off, fmt.Errorf("nome DNS truncado")
		}
		n := int(msg[off])
		if n == 0 {
			return strings.Join(labels, "."), off + 1, nil
		}
		if n&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return "", off, fmt.Errorf("ponteiro DNS truncado")
			}
			ptr := int(n&0x3F)<<8 | int(msg[off+1])
			name, _, err := readName(msg, ptr, depth+1)
			if err != nil {
				return "", off, err
			}
			if name != "" {
				labels = append(labels, name)
			}
			return strings.Join(labels, "."), off + 2, nil
		}
		if n&0xC0 != 0 {
			return "", off, fmt.Errorf("rótulo DNS inválido")
		}
		off++
		if off+n > len(msg) {
			return "", off, fmt.Errorf("rótulo DNS truncado")
		}
		labels = append(labels, string(msg[off:off+n]))
		off += n
	}
}

func netbiosQuery(id uint16) []byte {
	q := []byte{
		byte(id >> 8), byte(id),
		0x00, 0x00,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		32,
	}
	q = append(q, []byte("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")...)
	q = append(q, 0x00, 0x00, 0x21, 0x00, 0x01)
	return q
}

func ParseNetBIOS(msg []byte) (uint16, []string) {
	if len(msg) < 12 {
		return 0, nil
	}
	id := uint16(msg[0])<<8 | uint16(msg[1])
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	off := 12
	for i := 0; i < qd && off < len(msg); i++ {
		off = skipNetbiosName(msg, off)
		off += 4
	}
	var names []string
	for i := 0; i < an && off < len(msg); i++ {
		off = skipNetbiosName(msg, off)
		if off+10 > len(msg) {
			break
		}
		typ := int(msg[off])<<8 | int(msg[off+1])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if rdlen < 0 || off+rdlen > len(msg) {
			break
		}
		if typ == 0x21 {
			names = append(names, netbiosRData(msg[off:off+rdlen])...)
		}
		off += rdlen
	}
	return id, names
}

func skipNetbiosName(msg []byte, off int) int {
	if off >= len(msg) {
		return off
	}
	n := int(msg[off])
	if n&0xC0 == 0xC0 {
		return off + 2
	}
	return off + 1 + n + 1
}

func netbiosRData(rdata []byte) []string {
	if len(rdata) < 1 {
		return nil
	}
	count := int(rdata[0])
	var names []string
	p := 1
	for i := 0; i < count && p+18 <= len(rdata); i++ {
		name := strings.TrimRight(string(rdata[p:p+15]), " \x00")
		p += 18
		if name != "" {
			names = append(names, model.Clip(name))
		}
	}
	return names
}
