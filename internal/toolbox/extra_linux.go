//go:build linux

package toolbox

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type extra struct {
	DNS        []string
	LinkMbps   int
	DHCPServer string
	Origin     string
	Duplicate  bool
}

func platformExtra(ifi *net.Interface, _ netip.Addr) extra {
	out := extra{DNS: dnsFromResolv(readText("/etc/resolv.conf"))}
	if ifi == nil || strings.Contains(ifi.Name, "/") {
		return out
	}
	raw := strings.TrimSpace(readText(filepath.Join("/sys/class/net", ifi.Name, "speed")))
	if n, err := strconv.Atoi(raw); err == nil && n > 0 && n < 1_000_000 {
		out.LinkMbps = n
	}
	return out
}

func readText(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
