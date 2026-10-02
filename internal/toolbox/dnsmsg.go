package toolbox

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

func buildQuery(id uint16, name string, qtype uint16, unicast bool) []byte {
	buf := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	buf = append(buf, encodeName(name)...)
	class := uint16(1)
	if unicast {
		class = 0x8001
	}
	buf = append(buf, byte(qtype>>8), byte(qtype), byte(class>>8), byte(class))
	return buf
}

func encodeName(name string) []byte {
	var buf []byte
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			label = label[:63]
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}

type rec struct {
	Name   string
	Type   int
	IP     string
	Port   int
	Target string
	Ptr    string
}

func parseRecords(msg []byte) []rec {
	if len(msg) < 12 {
		return nil
	}
	qd := int(msg[4])<<8 | int(msg[5])
	total := int(msg[6])<<8 | int(msg[7])
	total += int(msg[8])<<8 | int(msg[9])
	total += int(msg[10])<<8 | int(msg[11])
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := readName(msg, off, 0)
		if err != nil || next+4 > len(msg) {
			return nil
		}
		off = next + 4
	}
	var out []rec
	for i := 0; i < total && off < len(msg); i++ {
		name, next, err := readName(msg, off, 0)
		if err != nil || next+10 > len(msg) {
			break
		}
		typ := int(msg[next])<<8 | int(msg[next+1])
		rdlen := int(msg[next+8])<<8 | int(msg[next+9])
		data := next + 10
		if rdlen < 0 || data+rdlen > len(msg) {
			break
		}
		item := rec{Name: strings.TrimSuffix(name, "."), Type: typ}
		switch typ {
		case 1:
			if rdlen == 4 {
				item.IP = net.IP(msg[data : data+4]).String()
			}
		case 12, 5:
			ptr, _, err := readName(msg, data, 0)
			if err == nil {
				item.Ptr = strings.TrimSuffix(ptr, ".")
			}
		case 28:
			if rdlen == 16 {
				item.IP = net.IP(msg[data : data+16]).String()
			}
		case 33:
			if rdlen >= 6 {
				item.Port = int(binary.BigEndian.Uint16(msg[data+4 : data+6]))
				target, _, err := readName(msg, data+6, 0)
				if err == nil {
					item.Target = strings.TrimSuffix(target, ".")
				}
			}
		}
		out = append(out, item)
		off = data + rdlen
	}
	return out
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

func ptrName(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip[3], ip[2], ip[1], ip[0])
}
