//go:build windows

package toolbox

import (
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type extra struct {
	DNS        []string
	LinkMbps   int
	DHCPServer string
	Origin     string
	Duplicate  bool
}

func platformExtra(ifi *net.Interface, local netip.Addr) extra {
	out := extra{}
	if ifi == nil {
		return out
	}
	aa, keep := adapterByIndex(ifi.Index)
	if aa == nil {
		return out
	}
	defer keep()
	for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
		if ip := d.Address.IP(); ip != nil {
			out.DNS = addUnique(out.DNS, ip.String())
		}
		if len(out.DNS) == 8 {
			break
		}
	}
	if aa.TransmitLinkSpeed > 0 {
		mbps := int(aa.TransmitLinkSpeed / 1_000_000)
		if mbps > 0 && mbps < 1_000_000 {
			out.LinkMbps = mbps
		}
	}
	if ip := aa.Dhcpv4Server.IP(); ip != nil && !ip.IsUnspecified() {
		out.DHCPServer = ip.String()
	}
	for u := aa.FirstUnicastAddress; u != nil; u = u.Next {
		ip := u.Address.IP()
		if ip == nil || ip.To4() == nil {
			continue
		}
		if u.DadState == windows.IpDadStateDuplicate {
			out.Duplicate = true
		}
		if !local.IsValid() || ip.String() != local.String() {
			continue
		}
		switch u.PrefixOrigin {
		case windows.IpPrefixOriginDhcp:
			out.Origin = "dhcp"
		case windows.IpPrefixOriginManual:
			out.Origin = "manual"
		}
	}
	return out
}

func adapterByIndex(index int) (*windows.IpAdapterAddresses, func()) {
	var b []byte
	size := uint32(15000)
	for {
		b = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX|windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
		if err == nil {
			if size == 0 {
				return nil, func() {}
			}
			break
		}
		errno, ok := err.(syscall.Errno)
		if !ok || errno != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(b)) {
			return nil, func() {}
		}
	}
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		if int(aa.IfIndex) == index || (aa.IfIndex == 0 && int(aa.Ipv6IfIndex) == index) {
			buf := b
			return aa, func() { runtime.KeepAlive(buf) }
		}
	}
	return nil, func() {}
}
