package toolbox

import (
	"net"
	"net/netip"
	"os"
	"strings"

	"nettools/internal/model"
	"nettools/internal/netinfo"
)

func Snapshot(info netinfo.Info) model.LAN {
	host, _ := os.Hostname()
	lan := model.LAN{
		Network:  info.View(),
		Hostname: host,
		DNS:      []string{},
		IPv6:     []string{},
	}
	if info.Iface == nil {
		return lan
	}
	lan.MTU = info.Iface.MTU
	lan.Up = info.Iface.Flags&net.FlagUp != 0
	if addrs, err := info.Iface.Addrs(); err == nil {
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
				continue
			}
			lan.IPv6 = append(lan.IPv6, p.Addr().String())
		}
	}
	if b := broadcast(info.IfacePrefix); b.IsValid() {
		lan.Broadcast = b.String()
	}
	extra := platformExtra(info.Iface, info.Local)
	lan.DNS = extra.DNS
	lan.LinkMbps = extra.LinkMbps
	lan.DHCPServer = extra.DHCPServer
	lan.Origin = extra.Origin
	lan.Duplicate = extra.Duplicate
	if lan.DNS == nil {
		lan.DNS = []string{}
	}
	return lan
}

func broadcast(p netip.Prefix) netip.Addr {
	if !p.IsValid() || !p.Addr().Is4() || p.Bits() >= 31 {
		return netip.Addr{}
	}
	return netinfo.LastIP(p)
}

func addUnique(dst []string, values ...string) []string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || value == "0.0.0.0" || value == "::" {
			continue
		}
		seen := false
		for _, have := range dst {
			if have == value {
				seen = true
				break
			}
		}
		if !seen {
			dst = append(dst, value)
		}
	}
	return dst
}
