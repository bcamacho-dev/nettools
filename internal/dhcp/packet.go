package dhcp

import (
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"nettools/internal/model"
)

func newDiscover(hw net.HardwareAddr) (*dhcpv4.DHCPv4, error) {
	return dhcpv4.NewDiscovery(
		hw,
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithOption(dhcpv4.OptHostName("nettools")),
	)
}

func readOffers(conn net.PacketConn, xid dhcpv4.TransactionID) []model.DHCPServer {
	buf := make([]byte, 2048)
	seen := map[string]struct{}{}
	out := []model.DHCPServer{}
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		var src net.IP
		if ua, ok := addr.(*net.UDPAddr); ok {
			src = ua.IP
		}
		srv, ok := parseOffer(buf[:n], xid, src)
		if !ok {
			continue
		}
		key := srv.ServerID + "|" + srv.SourceIP
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, srv)
	}
	return out
}

func parseOffer(b []byte, xid dhcpv4.TransactionID, src net.IP) (model.DHCPServer, bool) {
	msg, err := dhcpv4.FromBytes(b)
	if err != nil || msg.MessageType() != dhcpv4.MessageTypeOffer || msg.TransactionID != xid {
		return model.DHCPServer{}, false
	}
	srv := model.DHCPServer{
		DNS:    []string{},
		Router: []string{},
	}
	if sid := msg.ServerIdentifier(); sid != nil {
		srv.ServerID = sid.String()
	}
	if src != nil {
		srv.SourceIP = src.String()
	}
	if msg.YourIPAddr != nil && !msg.YourIPAddr.IsUnspecified() {
		srv.OfferedIP = msg.YourIPAddr.String()
	}
	srv.Hostname = model.Clip(dhcpv4.GetString(dhcpv4.OptionHostName, msg.Options))
	if mask := dhcpv4.GetIP(dhcpv4.OptionSubnetMask, msg.Options); mask != nil {
		srv.SubnetMask = mask.String()
	}
	srv.DNS = ipList(dhcpv4.GetIPs(dhcpv4.OptionDomainNameServer, msg.Options))
	srv.Router = ipList(dhcpv4.GetIPs(dhcpv4.OptionRouter, msg.Options))
	if srv.ServerID == "" {
		srv.ServerID = srv.SourceIP
	}
	if srv.ServerID == "" && srv.SourceIP == "" {
		return model.DHCPServer{}, false
	}
	return srv, true
}

func directedBroadcasts(ifi *net.Interface) []net.IP {
	if ifi == nil {
		return nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP == nil || ipnet.Mask == nil {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		mask := ipnet.Mask
		if len(mask) == 16 {
			mask = mask[12:]
		}
		if len(mask) != 4 {
			continue
		}
		bcast := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			bcast[i] = ip4[i] | ^mask[i]
		}
		out = append(out, bcast)
	}
	return out
}

func ipList(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}
