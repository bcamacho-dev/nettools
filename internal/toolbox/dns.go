package toolbox

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"nettools/internal/model"
	"nettools/internal/netinfo"
)

func Lookup(ctx context.Context, info netinfo.Info, name string) (model.DNSResult, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return model.DNSResult{}, &netinfo.Rejected{Reason: "informe um nome ou um endereço"}
	}
	kind := "A"
	qname := name
	qtype := uint16(1)
	if ip, err := netip.ParseAddr(name); err == nil {
		if !ip.Is4() {
			return model.DNSResult{}, &netinfo.Rejected{Reason: "a consulta reversa desta caixa é IPv4"}
		}
		kind = "PTR"
		qname = ptrName(ip.AsSlice())
		qtype = 12
	} else if !validName(name) {
		return model.DNSResult{}, &netinfo.Rejected{Reason: "nome inválido"}
	}

	servers := []string{"sistema"}
	if info.Iface != nil {
		for _, server := range platformExtra(info.Iface, info.Local).DNS {
			if ip, err := netip.ParseAddr(server); err != nil || !ip.Is4() {
				continue
			}
			servers = addUnique(servers, server)
			if len(servers) == 5 {
				break
			}
		}
	}
	out := model.DNSResult{Name: name, Kind: kind, Answers: make([]model.DNSAnswer, len(servers))}
	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Add(1)
		go func(i int, server string) {
			defer wg.Done()
			out.Answers[i] = ask(ctx, info, server, qname, qtype, kind)
		}(i, server)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return model.DNSResult{}, ctx.Err()
	}
	return out, nil
}

func ask(ctx context.Context, info netinfo.Info, server, qname string, qtype uint16, kind string) model.DNSAnswer {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	start := time.Now()
	answer := model.DNSAnswer{Server: server}
	var values []string
	var err error
	if server == "sistema" {
		values, err = askSystem(ctx, kind, qname)
	} else {
		values, err = askServer(ctx, info, server, qname, qtype, kind)
	}
	answer.MS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		answer.Error = model.Clip(err.Error())
		return answer
	}
	if values == nil {
		values = []string{}
	}
	answer.Values = values
	return answer
}

func askSystem(ctx context.Context, kind, qname string) ([]string, error) {
	r := net.DefaultResolver
	if kind == "PTR" {
		ip := strings.TrimSuffix(qname, ".in-addr.arpa")
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			return nil, &netinfo.Rejected{Reason: "endereço inválido"}
		}
		addr := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
		names, err := r.LookupAddr(ctx, addr)
		if err != nil {
			return nil, err
		}
		for i, name := range names {
			names[i] = strings.TrimSuffix(name, ".")
		}
		return names, nil
	}
	return r.LookupHost(ctx, qname)
}

func askServer(ctx context.Context, info netinfo.Info, server, qname string, qtype uint16, kind string) ([]string, error) {
	ip, err := netip.ParseAddr(server)
	if err != nil || !ip.Is4() {
		return nil, &netinfo.Rejected{Reason: "servidor DNS sem IPv4"}
	}
	var local *net.UDPAddr
	if info.Local.Is4() {
		local = &net.UDPAddr{IP: info.Local.AsSlice()}
	}
	dialer := net.Dialer{LocalAddr: local, Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(ip.String(), "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := uint16(idb[0])<<8 | uint16(idb[1])
	if _, err := conn.Write(buildQuery(id, qname, qtype, false)); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	msg := buf[:n]
	if len(msg) < 12 || uint16(msg[0])<<8|uint16(msg[1]) != id {
		return nil, &netinfo.Rejected{Reason: "resposta DNS inesperada"}
	}
	if msg[2]&0x02 != 0 {
		return nil, &netinfo.Rejected{Reason: "resposta DNS truncada"}
	}
	var values []string
	for _, rec := range parseRecords(msg) {
		if kind == "PTR" && rec.Ptr != "" && (rec.Type == 12 || rec.Type == 5) {
			values = addUnique(values, rec.Ptr)
		}
		if kind == "A" && rec.IP != "" && (rec.Type == 1 || rec.Type == 28) {
			values = addUnique(values, rec.IP)
		}
	}
	return values, nil
}
