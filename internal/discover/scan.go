package discover

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"

	"nettools/internal/dhcp"
	"nettools/internal/model"
	"nettools/internal/netinfo"
	"nettools/internal/oui"
)

type Result struct {
	Devices   []model.Device
	DHCP      []model.DHCPServer
	DHCPError string
}

func Run(ctx context.Context, info netinfo.Info, progress func(string)) (Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	progress(fmt.Sprintf("ARP em %d endereços", len(info.Targets)))
	arpCtx, cancel := context.WithTimeout(ctx, arpWindow(len(info.Targets)))
	macs, err := ScanMAC(arpCtx, info.Iface, info.Targets)
	cancel()
	if err != nil {
		return Result{}, err
	}

	progress(fmt.Sprintf("Identificando %d dispositivos", len(macs)))
	ips := make([]netip.Addr, 0, len(macs))
	for ip := range macs {
		addr, err := netip.ParseAddr(ip)
		if err == nil {
			ips = append(ips, addr)
		}
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Compare(ips[j]) < 0 })

	idCtx, idCancel := context.WithTimeout(ctx, 20*time.Second)
	names, ports, titles := Identify(idCtx, info.LocalIP(), ips)
	idCancel()

	devices := make([]model.Device, 0, len(ips)+2)
	for _, ip := range ips {
		key := ip.String()
		itemNames := names[key]
		if itemNames == nil {
			itemNames = []string{}
		}
		itemPorts := ports[key]
		if itemPorts == nil {
			itemPorts = []model.Port{}
		}
		d := model.Device{
			IP:        key,
			MAC:       macs[key],
			Vendor:    oui.Lookup(macs[key]),
			Names:     itemNames,
			Ports:     itemPorts,
			HTTPTitle: titles[key],
			Hostname:  BestName(itemNames),
		}
		if info.Gateway.IsValid() && ip == info.Gateway {
			d.Role = "gateway"
		}
		devices = append(devices, d)
	}
	devices = append(devices, selfDevice(info))
	if info.Gateway.IsValid() && !hasIP(devices, info.Gateway.String()) {
		devices = append(devices, model.Device{
			IP:    info.Gateway.String(),
			Role:  "gateway",
			Names: []string{},
			Ports: []model.Port{},
		})
	}
	sort.Slice(devices, func(i, j int) bool {
		return lessIP(devices[i].IP, devices[j].IP)
	})

	progress("Procurando DHCP")
	dhcpServers, dhcpErr := lookupDHCP(ctx, info)
	progress("Concluído")
	return Result{Devices: devices, DHCP: dhcpServers, DHCPError: dhcpErr}, nil
}

func DHCPOnly(ctx context.Context, info netinfo.Info) Result {
	servers, errText := lookupDHCP(ctx, info)
	return Result{Devices: []model.Device{}, DHCP: servers, DHCPError: errText}
}

func lookupDHCP(ctx context.Context, info netinfo.Info) ([]model.DHCPServer, string) {
	dhcpCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	servers, err := dhcp.Discover(dhcpCtx, info.Iface)
	if servers == nil {
		servers = []model.DHCPServer{}
	}
	if err != nil {
		return servers, err.Error()
	}
	for i := range servers {
		if servers[i].MAC == "" {
			ip, perr := netip.ParseAddr(servers[i].SourceIP)
			if perr != nil || !ip.Is4() {
				ip, perr = netip.ParseAddr(servers[i].ServerID)
			}
			if perr == nil && ip.Is4() && info.Prefix.Contains(ip) {
				if mac, rerr := ResolveMAC(info.Iface, ip); rerr == nil {
					servers[i].MAC = mac
				}
			}
		}
		if servers[i].MAC != "" {
			servers[i].Vendor = oui.Lookup(servers[i].MAC)
		}
		if servers[i].DNS == nil {
			servers[i].DNS = []string{}
		}
		if servers[i].Router == nil {
			servers[i].Router = []string{}
		}
	}
	return servers, ""
}

func selfDevice(info netinfo.Info) model.Device {
	host, _ := os.Hostname()
	mac := ""
	if info.Iface != nil {
		mac = info.Iface.HardwareAddr.String()
	}
	return model.Device{
		IP:       info.Local.String(),
		MAC:      mac,
		Vendor:   oui.Lookup(mac),
		Hostname: host,
		Names:    []string{},
		Ports:    []model.Port{},
		Role:     "este servidor",
	}
}

func hasIP(devices []model.Device, ip string) bool {
	for _, d := range devices {
		if d.IP == ip {
			return true
		}
	}
	return false
}

func lessIP(a, b string) bool {
	ia, ea := netip.ParseAddr(a)
	ib, eb := netip.ParseAddr(b)
	if ea != nil || eb != nil {
		return a < b
	}
	return ia.Compare(ib) < 0
}

func arpWindow(n int) time.Duration {
	d := 4*time.Second + time.Duration(n)*2*time.Millisecond
	if d < 8*time.Second {
		d = 8 * time.Second
	}
	if d > 40*time.Second {
		d = 40 * time.Second
	}
	return d
}
