package toolbox

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"nettools/internal/netinfo"
)

func validName(host string) bool {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || len(host) > 253 || strings.HasPrefix(host, "-") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

func onLAN(info netinfo.Info, ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	if info.Gateway.IsValid() && ip == info.Gateway {
		return true
	}
	return info.IfacePrefix.IsValid() && info.IfacePrefix.Contains(ip)
}

func resolveLAN(ctx context.Context, info netinfo.Info, host string) (netip.Addr, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return netip.Addr{}, &netinfo.Rejected{Reason: "informe um endereço desta rede"}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !onLAN(info, ip) {
			return netip.Addr{}, &netinfo.Rejected{Reason: "o endereço está fora da rede local"}
		}
		return ip, nil
	}
	if !validName(host) {
		return netip.Addr{}, &netinfo.Rejected{Reason: "nome inválido"}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", strings.TrimSuffix(host, "."))
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, &netinfo.Rejected{Reason: "não foi possível resolver o nome nesta rede"}
	}
	for _, ip := range ips {
		if onLAN(info, ip) {
			return ip, nil
		}
	}
	return netip.Addr{}, &netinfo.Rejected{Reason: "o nome não aponta para um endereço desta rede"}
}

func ipv4Only(host string) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil || !ip.Is4() {
		return "", &netinfo.Rejected{Reason: "alvo inválido"}
	}
	return ip.String(), nil
}
