//go:build !linux && !windows

package toolbox

import (
	"net"
	"net/netip"
	"os"
)

type extra struct {
	DNS        []string
	LinkMbps   int
	DHCPServer string
	Origin     string
	Duplicate  bool
}

func platformExtra(_ *net.Interface, _ netip.Addr) extra {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return extra{}
	}
	return extra{DNS: dnsFromResolv(string(b))}
}
