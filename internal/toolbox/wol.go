package toolbox

import (
	"net"
	"strings"

	"nettools/internal/model"
	"nettools/internal/netinfo"
)

func Wake(info netinfo.Info, mac string) (model.WakeResult, error) {
	hw, err := parseMAC(mac)
	if err != nil {
		return model.WakeResult{}, err
	}
	if info.Iface == nil || !info.Local.Is4() {
		return model.WakeResult{}, &netinfo.Rejected{Reason: "não há interface IPv4 para enviar o despertar"}
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: info.Local.AsSlice(), Port: 0})
	if err != nil {
		return model.WakeResult{}, err
	}
	defer conn.Close()
	pkt := magic(hw)
	var sent bool
	var bcast string
	for _, dst := range wakeTargets(info) {
		if _, err := conn.WriteToUDP(pkt, dst); err == nil {
			sent = true
			if bcast == "" {
				bcast = dst.IP.String()
			}
		}
	}
	if !sent {
		return model.WakeResult{}, &netinfo.Rejected{Reason: "não foi possível enviar o pacote de despertar"}
	}
	return model.WakeResult{MAC: hw.String(), Broadcast: bcast}, nil
}

func parseMAC(s string) (net.HardwareAddr, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", ":")
	s = strings.ReplaceAll(s, ".", "")
	if !strings.Contains(s, ":") && len(s) == 12 {
		var b strings.Builder
		for i := 0; i < 12; i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			b.WriteString(s[i : i+2])
		}
		s = b.String()
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return nil, &netinfo.Rejected{Reason: "MAC inválido"}
	}
	if hw[0]&1 == 1 {
		return nil, &netinfo.Rejected{Reason: "o MAC precisa ser de um aparelho, não de um grupo"}
	}
	return hw, nil
}

func magic(hw net.HardwareAddr) []byte {
	pkt := make([]byte, 6+16*6)
	for i := 0; i < 6; i++ {
		pkt[i] = 0xff
	}
	for i := 0; i < 16; i++ {
		copy(pkt[6+i*6:], hw)
	}
	return pkt
}

func wakeTargets(info netinfo.Info) []*net.UDPAddr {
	out := []*net.UDPAddr{{IP: net.IPv4bcast, Port: 9}}
	if b := broadcast(info.IfacePrefix); b.IsValid() {
		out = append([]*net.UDPAddr{{IP: b.AsSlice(), Port: 9}}, out...)
	}
	return out
}
