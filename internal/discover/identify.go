package discover

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"nettools/internal/model"
)

var knownPorts = []model.Port{
	{22, "ssh"},
	{80, "http"},
	{443, "https"},
	{445, "smb"},
	{515, "lpd"},
	{631, "ipp"},
	{3389, "rdp"},
	{8008, "chromecast"},
	{8009, "cast"},
	{8080, "http-alt"},
	{8443, "https-alt"},
	{9100, "jetdirect"},
}

func Identify(ctx context.Context, local net.IP, ips []netip.Addr) (map[string][]string, map[string][]model.Port, map[string]string) {
	names := map[string][]string{}
	var mu sync.Mutex
	add := func(ip, kind, value string) {
		value = model.Clip(value)
		if ip == "" || value == "" {
			return
		}
		mu.Lock()
		names[ip] = append(names[ip], kind+":"+value)
		mu.Unlock()
	}

	phase, cancel := context.WithTimeout(ctx, 14*time.Second)
	var ports map[string][]model.Port
	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		for ip, v := range ssdpNames(phase, local) {
			add(ip, "ssdp", v)
		}
	}()
	go func() {
		defer wg.Done()
		for ip, v := range mdnsNames(phase, local, ips) {
			add(ip, "mdns", v)
		}
	}()
	go func() {
		defer wg.Done()
		for ip, v := range netbiosNames(phase, local, ips) {
			add(ip, "netbios", v)
		}
	}()
	go func() {
		defer wg.Done()
		for ip, v := range dnsNames(phase, ips) {
			add(ip, "dns", v)
		}
	}()
	go func() {
		defer wg.Done()
		ports = probePorts(phase, ips)
	}()
	wg.Wait()
	cancel()

	titles := httpTitles(ctx, ports)
	for ip, title := range titles {
		add(ip, "http", title)
	}
	if ports == nil {
		ports = map[string][]model.Port{}
	}
	return names, ports, titles
}

func listenUntil(ctx context.Context, window time.Duration) time.Time {
	deadline := time.Now().Add(window)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		return dl
	}
	return deadline
}

func BestName(items []string) string {
	order := []string{"netbios:", "mdns:", "dns:", "http:", "ssdp:"}
	for _, prefix := range order {
		for _, item := range items {
			if strings.HasPrefix(item, prefix) {
				return strings.TrimPrefix(item, prefix)
			}
		}
	}
	return ""
}

func ssdpNames(ctx context.Context, local net.IP) map[string]string {
	out := map[string]string{}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local, Port: 0})
	if err != nil {
		return out
	}
	defer conn.Close()
	msg := []byte("M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	dst := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	_, _ = conn.WriteToUDP(msg, dst)
	_ = conn.SetReadDeadline(listenUntil(ctx, 2*time.Second))
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if addr == nil || addr.IP == nil {
			continue
		}
		if server := ssdpServer(string(buf[:n])); server != "" {
			out[addr.IP.String()] = server
		}
	}
	return out
}

func ssdpServer(payload string) string {
	for _, line := range strings.Split(payload, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 7 && strings.EqualFold(line[:7], "server:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}

func mdnsNames(ctx context.Context, local net.IP, ips []netip.Addr) map[string]string {
	out := map[string]string{}
	if len(ips) == 0 {
		return out
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local, Port: 0})
	if err != nil {
		return out
	}
	defer conn.Close()
	ids := make(map[uint16]string, len(ips))
	var tid uint16 = 1
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		ids[tid] = ip.String()
		_, _ = conn.WriteToUDP(ptrQuery(tid, ip), &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: 5353})
		tid++
		if tid == 0 {
			tid = 1
		}
	}
	_ = conn.SetReadDeadline(listenUntil(ctx, 2*time.Second))
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		id, names := ptrNames(buf[:n])
		ip := ids[id]
		if ip == "" || len(names) == 0 {
			continue
		}
		if _, exists := out[ip]; !exists {
			out[ip] = names[0]
		}
	}
	return out
}

func netbiosNames(ctx context.Context, local net.IP, ips []netip.Addr) map[string]string {
	out := map[string]string{}
	if len(ips) == 0 {
		return out
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local, Port: 0})
	if err != nil {
		return out
	}
	defer conn.Close()
	ids := make(map[uint16]string, len(ips))
	var tid uint16 = 1
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		ids[tid] = ip.String()
		_, _ = conn.WriteToUDP(netbiosQuery(tid), &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: 137})
		tid++
		if tid == 0 {
			tid = 1
		}
	}
	_ = conn.SetReadDeadline(listenUntil(ctx, 2*time.Second))
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		id, names := ParseNetBIOS(buf[:n])
		ip := ids[id]
		if ip == "" || len(names) == 0 {
			continue
		}
		if _, exists := out[ip]; !exists {
			out[ip] = names[0]
		}
	}
	return out
}

func dnsNames(ctx context.Context, ips []netip.Addr) map[string]string {
	out := map[string]string{}
	var mu sync.Mutex
	sem := make(chan struct{}, 24)
	var wg sync.WaitGroup
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(cctx, ip.String())
			if err != nil || len(names) == 0 {
				return
			}
			mu.Lock()
			out[ip.String()] = strings.TrimSuffix(names[0], ".")
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}

func probePorts(ctx context.Context, ips []netip.Addr) map[string][]model.Port {
	out := map[string][]model.Port{}
	var mu sync.Mutex
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	dialer := net.Dialer{Timeout: 300 * time.Millisecond}
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			var found []model.Port
			for _, port := range knownPorts {
				if ctx.Err() != nil {
					break
				}
				addr := net.JoinHostPort(ip.String(), strconv.Itoa(port.Port))
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err != nil {
					continue
				}
				conn.Close()
				found = append(found, port)
			}
			if len(found) == 0 {
				return
			}
			mu.Lock()
			out[ip.String()] = found
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}

func httpTitles(ctx context.Context, ports map[string][]model.Port) map[string]string {
	out := map[string]string{}
	type target struct {
		ip   string
		port int
	}
	var targets []target
	for ip, list := range ports {
		port := 0
		for _, p := range list {
			if p.Port == 80 {
				port = 80
				break
			}
			if p.Port == 8080 {
				port = 8080
			}
		}
		if port != 0 {
			targets = append(targets, target{ip, port})
		}
	}
	var mu sync.Mutex
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, tg := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(tg target) {
			defer wg.Done()
			defer func() { <-sem }()
			title := fetchTitle(ctx, tg.ip, tg.port)
			if title == "" {
				return
			}
			mu.Lock()
			out[tg.ip] = title
			mu.Unlock()
		}(tg)
	}
	wg.Wait()
	return out
}

func fetchTitle(ctx context.Context, ip string, port int) string {
	host := net.JoinHostPort(ip, strconv.Itoa(port))
	cctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, "http://"+host+"/", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "NetTools")
	client := &http.Client{
		Timeout: 1200 * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 || req.URL.Hostname() != ip {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 16<<10))
	return htmlTitle(body)
}

func htmlTitle(body []byte) string {
	s := string(body)
	lower := strings.ToLower(s)
	i := strings.Index(lower, "<title")
	if i < 0 {
		return ""
	}
	j := strings.Index(lower[i:], ">")
	if j < 0 {
		return ""
	}
	rest := s[i+j+1:]
	k := strings.Index(strings.ToLower(rest), "</title>")
	if k < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:k])
}
