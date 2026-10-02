package toolbox

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"nettools/internal/model"
	"nettools/internal/netinfo"
)

const pathHops = 8

func Path(ctx context.Context, info netinfo.Info, host string, exit bool) (model.PathResult, error) {
	var target string
	switch {
	case exit:
		target = "1.1.1.1"
	case strings.TrimSpace(host) == "":
		if !info.Gateway.IsValid() {
			return model.PathResult{}, &netinfo.Rejected{Reason: "não há gateway para traçar"}
		}
		target = info.Gateway.String()
	default:
		ip, err := resolveLAN(ctx, info, host)
		if err != nil {
			return model.PathResult{}, err
		}
		target = ip.String()
	}
	target, err := ipv4Only(target)
	if err != nil {
		return model.PathResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	hops, err := trace(ctx, target)
	if err != nil {
		return model.PathResult{}, err
	}
	return model.PathResult{Target: target, Hops: hops}, nil
}

func trace(ctx context.Context, target string) ([]model.Hop, error) {
	name, args, err := traceCommand(target)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	configure(cmd)
	out, err := cmd.CombinedOutput()
	hops := parseHops(string(out))
	if len(hops) == 0 {
		if ctx.Err() != nil {
			return nil, &netinfo.Rejected{Reason: "o traçado excedeu o tempo"}
		}
		if err != nil {
			return nil, &netinfo.Rejected{Reason: model.Clip(name + ": " + err.Error())}
		}
		return nil, &netinfo.Rejected{Reason: "o traçado não devolveu saltos"}
	}
	return hops, nil
}

func traceCommand(target string) (string, []string, error) {
	hops := strconv.Itoa(pathHops)
	if runtime.GOOS == "windows" {
		return "tracert", []string{"-d", "-h", hops, "-w", "500", target}, nil
	}
	if path, err := exec.LookPath("tracepath"); err == nil {
		return path, []string{"-n", "-m", hops, target}, nil
	}
	if path, err := exec.LookPath("traceroute"); err == nil {
		return path, []string{"-n", "-w", "1", "-q", "1", "-m", hops, target}, nil
	}
	return "", nil, &netinfo.Rejected{Reason: "não há tracepath nem traceroute neste sistema"}
}

var (
	hopLine = regexp.MustCompile(`(?m)^\s*(\d+)\??[:.]?\s+(.*)$`)
	hopIP   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	hopMS   = regexp.MustCompile(`([0-9]+(?:[.,][0-9]+)?)\s*ms`)
)

func parseHops(text string) []model.Hop {
	var hops []model.Hop
	for _, match := range hopLine.FindAllStringSubmatch(text, -1) {
		ttl, err := strconv.Atoi(match[1])
		if err != nil || ttl < 1 || ttl > 64 {
			continue
		}
		rest := match[2]
		hop := model.Hop{TTL: ttl}
		if ips := hopIP.FindAllString(rest, -1); len(ips) > 0 {
			hop.IP = ips[len(ips)-1]
		}
		if times := hopMS.FindAllStringSubmatch(rest, -1); len(times) > 0 {
			var sum float64
			var n int
			for _, item := range times {
				v, err := strconv.ParseFloat(strings.ReplaceAll(item[1], ",", "."), 64)
				if err != nil {
					continue
				}
				sum += v
				n++
			}
			if n > 0 {
				hop.MS = sum / float64(n)
			}
		}
		hop.Timeout = hop.IP == ""
		hops = upsertHop(hops, hop)
	}
	if hops == nil {
		return []model.Hop{}
	}
	return hops
}

func upsertHop(hops []model.Hop, hop model.Hop) []model.Hop {
	for i := range hops {
		if hops[i].TTL != hop.TTL {
			continue
		}
		if hops[i].IP == "" && hop.IP != "" {
			hops[i] = hop
		}
		return hops
	}
	return append(hops, hop)
}
