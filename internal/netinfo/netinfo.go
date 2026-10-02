package netinfo

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"github.com/jackpal/gateway"

	"nettools/internal/model"
)

type Rejected struct {
	Reason string
}

func (e *Rejected) Error() string { return e.Reason }

type Info struct {
	Iface       *net.Interface
	Prefix      netip.Prefix
	IfacePrefix netip.Prefix
	Local       netip.Addr
	Gateway     netip.Addr
	Targets     []netip.Addr
	HostCount   int
	OS          string
	Scannable   bool
	ScanError   string
}

func Detect(ifaceName, cidr string) (Info, error) {
	gwAddr := gatewayAddr()
	var ifi *net.Interface
	var local netip.Addr
	var ifacePrefix netip.Prefix
	var err error

	if ifaceName != "" {
		ifi, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return Info{}, fmt.Errorf("interface %s: %w", ifaceName, err)
		}
		local, ifacePrefix, err = ipv4Prefix(ifi, gwAddr)
		if err != nil {
			return Info{}, err
		}
	} else {
		lip, derr := gateway.DiscoverInterface()
		if derr != nil {
			return Info{}, fmt.Errorf("interface da rota padrão: %w", derr)
		}
		ip4 := lip.To4()
		if ip4 == nil {
			return Info{}, errors.New("a rota padrão não é IPv4")
		}
		local = netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
		ifi, ifacePrefix, err = ifaceByIP(local)
		if err != nil {
			return Info{}, err
		}
	}

	scanPrefix := ifacePrefix
	if cidr != "" {
		p, perr := netip.ParsePrefix(cidr)
		if perr != nil {
			return Info{}, fmt.Errorf("cidr: %w", perr)
		}
		p = p.Masked()
		if !p.Addr().Is4() {
			return Info{}, errors.New("o cidr precisa ser IPv4")
		}
		if !ContainsPrefix(ifacePrefix, p) {
			return Info{}, fmt.Errorf("o cidr %s não está dentro de %s", p, ifacePrefix)
		}
		scanPrefix = p
	}

	info := Info{
		Iface:       ifi,
		Prefix:      scanPrefix,
		IfacePrefix: ifacePrefix,
		Local:       local,
		Gateway:     gwAddr,
		OS:          runtime.GOOS,
	}
	info.finish()
	return info, nil
}

func (n Info) LocalOK() bool {
	return isLocalAddr(n.Local)
}

func (n Info) View() model.Network {
	name, mac := "", ""
	if n.Iface != nil {
		name = n.Iface.Name
		mac = n.Iface.HardwareAddr.String()
	}
	gw := ""
	if n.Gateway.IsValid() {
		gw = n.Gateway.String()
	}
	return model.Network{
		Interface: name,
		MAC:       mac,
		IP:        n.Local.String(),
		Subnet:    n.Prefix.String(),
		Gateway:   gw,
		Hosts:     n.HostCount,
		OS:        n.OS,
		Scannable: n.Scannable,
		ScanError: n.ScanError,
	}
}

func (n Info) LocalIP() net.IP {
	if !n.Local.Is4() {
		return nil
	}
	b := n.Local.As4()
	return net.IPv4(b[0], b[1], b[2], b[3])
}

func (n *Info) finish() {
	n.Prefix = n.Prefix.Masked()
	if !isLocalAddr(n.Local) && !n.Prefix.Addr().IsLoopback() {
		n.Scannable = false
		n.ScanError = "a interface não está numa rede local (privada, CGNAT ou link-local)"
		n.HostCount = hostCount(n.Prefix)
		return
	}
	if n.Prefix.Bits() < 22 || n.Prefix.Bits() > 32 {
		n.Scannable = false
		n.ScanError = fmt.Sprintf("a rede %s é grande demais para varrer; use --cidr com um bloco de /22 ou menor", n.Prefix)
		n.HostCount = hostCount(n.Prefix)
		return
	}
	hosts, err := Hosts(n.Prefix)
	if err != nil {
		n.Scannable = false
		n.ScanError = err.Error()
		return
	}
	filtered := make([]netip.Addr, 0, len(hosts))
	for _, h := range hosts {
		if h == n.Local {
			continue
		}
		filtered = append(filtered, h)
	}
	n.Targets = filtered
	n.HostCount = len(filtered)
	n.Scannable = true
}

func gatewayAddr() netip.Addr {
	gw, err := gateway.DiscoverGateway()
	if err != nil {
		return netip.Addr{}
	}
	ip4 := gw.To4()
	if ip4 == nil {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
}

func ipv4Prefix(ifi *net.Interface, gw netip.Addr) (netip.Addr, netip.Prefix, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	var first netip.Prefix
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil || !p.Addr().Is4() {
			continue
		}
		if !first.IsValid() {
			first = p
		}
		if gw.IsValid() && p.Contains(gw) {
			return p.Addr(), p.Masked(), nil
		}
	}
	if !first.IsValid() {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("a interface %s não tem IPv4", ifi.Name)
	}
	return first.Addr(), first.Masked(), nil
}

func ifaceByIP(ip netip.Addr) (*net.Interface, netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, netip.Prefix{}, err
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil || !p.Addr().Is4() {
				continue
			}
			if p.Addr() == ip {
				chosen := ifi
				return &chosen, p.Masked(), nil
			}
		}
	}
	return nil, netip.Prefix{}, fmt.Errorf("nenhuma interface tem o endereço %s", ip)
}

func isLocalAddr(ip netip.Addr) bool {
	return ip.IsValid() && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || isCGNAT(ip))
}

func isCGNAT(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	return b[0] == 100 && b[1]&0xC0 == 0x40
}

func ContainsPrefix(outer, inner netip.Prefix) bool {
	if !outer.IsValid() || !inner.IsValid() || !outer.Addr().Is4() || !inner.Addr().Is4() {
		return false
	}
	if inner.Bits() < outer.Bits() {
		return false
	}
	return outer.Contains(inner.Addr()) && outer.Contains(LastIP(inner))
}

func LastIP(p netip.Prefix) netip.Addr {
	p = p.Masked()
	bits := p.Bits()
	if bits >= 32 {
		return p.Addr()
	}
	if bits <= 0 {
		return netip.MustParseAddr("255.255.255.255")
	}
	v := uint32(p.Addr().As4()[0])<<24 | uint32(p.Addr().As4()[1])<<16 | uint32(p.Addr().As4()[2])<<8 | uint32(p.Addr().As4()[3])
	v |= uint32(1<<(32-bits)) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func Hosts(p netip.Prefix) ([]netip.Addr, error) {
	if !p.Addr().Is4() {
		return nil, errors.New("somente IPv4")
	}
	p = p.Masked()
	bits := p.Bits()
	if bits < 22 || bits > 32 {
		return nil, &Rejected{Reason: fmt.Sprintf("a rede %s é grande demais para varrer; use --cidr com um bloco de /22 ou menor", p)}
	}
	total := 1 << (32 - bits)
	cur := p.Addr()
	out := make([]netip.Addr, 0, total)
	for i := 0; i < total; i++ {
		skip := bits <= 30 && (i == 0 || i == total-1)
		if !skip {
			out = append(out, cur)
		}
		cur = next4(cur)
	}
	return out, nil
}

func hostCount(p netip.Prefix) int {
	if !p.IsValid() {
		return 0
	}
	bits := p.Bits()
	if bits <= 0 || bits > 32 {
		return 0
	}
	n := 1 << (32 - bits)
	if bits <= 30 && n >= 2 {
		n -= 2
	}
	return n
}

func next4(a netip.Addr) netip.Addr {
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v++
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
