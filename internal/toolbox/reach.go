package toolbox

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"nettools/internal/model"
	"nettools/internal/netinfo"
)

var servicePorts = []model.Port{
	{22, "ssh"},
	{53, "dns"},
	{80, "http"},
	{443, "https"},
	{445, "smb"},
	{515, "lpd"},
	{631, "ipp"},
	{3389, "rdp"},
	{8008, "chromecast"},
	{8080, "http-alt"},
	{8443, "https-alt"},
	{9100, "impressora"},
}

func Reach(ctx context.Context, info netinfo.Info, host string, port int) (model.ReachResult, error) {
	ip, err := resolveLAN(ctx, info, host)
	if err != nil {
		return model.ReachResult{}, err
	}
	ports := servicePorts
	timeout := 500 * time.Millisecond
	if port != 0 {
		if port < 1 || port > 65535 {
			return model.ReachResult{}, &netinfo.Rejected{Reason: "porta inválida"}
		}
		ports = []model.Port{{Port: port, Label: portLabel(port)}}
		timeout = 1500 * time.Millisecond
	}
	out := model.ReachResult{
		Host:  host,
		IP:    ip.String(),
		Ports: make([]model.PortProbe, len(ports)),
	}
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, spec := range ports {
		wg.Add(1)
		go func(i int, spec model.Port) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out.Ports[i] = model.PortProbe{Port: spec.Port, Label: spec.Label, Error: "cancelado"}
				return
			}
			out.Ports[i] = dial(ctx, ip.String(), spec, timeout)
		}(i, spec)
	}
	wg.Wait()
	return out, nil
}

func dial(ctx context.Context, ip string, spec model.Port, timeout time.Duration) model.PortProbe {
	probe := model.PortProbe{Port: spec.Port, Label: spec.Label}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(spec.Port)))
	probe.MS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			probe.Error = "sem resposta"
		} else {
			probe.Error = "fechada"
		}
		return probe
	}
	_ = conn.Close()
	probe.Open = true
	return probe
}

func portLabel(port int) string {
	for _, spec := range servicePorts {
		if spec.Port == port {
			return spec.Label
		}
	}
	return "tcp"
}
