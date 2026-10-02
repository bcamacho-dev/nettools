package toolbox

import (
	"context"
	"crypto/rand"
	"net"
	"strings"
	"time"

	"nettools/internal/model"
	"nettools/internal/netinfo"
)

var serviceTypes = []string{
	"_http._tcp.local",
	"_https._tcp.local",
	"_ipp._tcp.local",
	"_ipps._tcp.local",
	"_printer._tcp.local",
	"_pdl-datastream._tcp.local",
	"_smb._tcp.local",
	"_googlecast._tcp.local",
	"_airplay._tcp.local",
	"_raop._tcp.local",
	"_hap._tcp.local",
	"_homekit._tcp.local",
	"_workstation._tcp.local",
	"_ssh._tcp.local",
	"_device-info._tcp.local",
	"_spotify-connect._tcp.local",
}

func Services(ctx context.Context, info netinfo.Info) ([]model.Service, error) {
	if info.Iface == nil || !info.Local.Is4() {
		return nil, &netinfo.Rejected{Reason: "não há interface IPv4 para escutar anúncios"}
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: info.Local.AsSlice(), Port: 0})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := uint16(idb[0])<<8 | uint16(idb[1])
	for _, name := range serviceTypes {
		if ctx.Err() != nil {
			break
		}
		_, _ = conn.WriteToUDP(buildQuery(id, name, 12, true), dst)
		id++
		if id == 0 {
			id = 1
		}
	}
	timer := time.NewTimer(2500 * time.Millisecond)
	defer timer.Stop()
	_ = conn.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	buf := make([]byte, 1500)
	var recs []rec
	for {
		if ctx.Err() != nil {
			break
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		recs = append(recs, parseRecords(append([]byte(nil), buf[:n]...))...)
		select {
		case <-timer.C:
			return assemble(recs), nil
		default:
		}
	}
	return assemble(recs), nil
}

func assemble(recs []rec) []model.Service {
	type inst struct {
		typ  string
		name string
		host string
		port int
		ips  []string
	}
	order := []string{}
	byName := map[string]*inst{}
	hosts := map[string][]string{}
	for _, rec := range recs {
		switch rec.Type {
		case 1, 28:
			if rec.IP != "" {
				hosts[strings.ToLower(rec.Name)] = addUnique(hosts[strings.ToLower(rec.Name)], rec.IP)
			}
		case 12:
			if rec.Ptr == "" {
				continue
			}
			key := strings.ToLower(rec.Ptr)
			if _, ok := byName[key]; ok {
				continue
			}
			byName[key] = &inst{typ: rec.Name, name: serviceLabel(rec.Ptr, rec.Name)}
			order = append(order, key)
		case 33:
			key := strings.ToLower(rec.Name)
			item := byName[key]
			if item == nil {
				item = &inst{name: serviceLabel(rec.Name, "")}
				byName[key] = item
				order = append(order, key)
			}
			item.host = rec.Target
			item.port = rec.Port
		}
	}
	out := make([]model.Service, 0, len(order))
	for _, key := range order {
		item := byName[key]
		if item.name == "" {
			continue
		}
		ips := hosts[strings.ToLower(item.host)]
		svc := model.Service{
			Name: model.Clip(unescapeDNS(item.name)),
			Type: strings.TrimSuffix(item.typ, ".local"),
			Host: model.Clip(unescapeDNS(item.host)),
			Port: item.port,
		}
		if len(ips) > 0 {
			svc.IP = strings.Join(ips, ", ")
		}
		out = append(out, svc)
		if len(out) == 100 {
			break
		}
	}
	return out
}

func serviceLabel(instance, typ string) string {
	name := strings.TrimSuffix(instance, ".")
	typ = strings.TrimSuffix(typ, ".")
	if typ != "" {
		name = strings.TrimSuffix(name, "."+typ)
	}
	return name
}

func unescapeDNS(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		n := 0
		ok := true
		for _, c := range s[i+1 : i+4] {
			if c < '0' || c > '9' {
				ok = false
				break
			}
			n = n*10 + int(c-'0')
		}
		if !ok || n > 255 {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String()
}
