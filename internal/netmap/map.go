package netmap

import (
	"net/netip"
	"sort"
	"strings"

	"nettools/internal/model"
)

const (
	nodeW = 150.0
	nodeH = 48.0
	gapX  = 14.0
	gapY  = 36.0
	pad   = 16.0
)

func Build(net model.Network, devices []model.Device, dhcp []model.DHCPServer) model.NetMap {
	devices = dedupe(devices)
	devices = ensureAnchors(net, devices)
	dhcpIPs := dhcpAddrs(dhcp)

	var gateway *model.Device
	grid := make([]model.Device, 0, len(devices))
	for i := range devices {
		if kindOf(devices[i]) == "gateway" {
			if gateway == nil {
				chosen := devices[i]
				gateway = &chosen
			}
			continue
		}
		grid = append(grid, devices[i])
	}
	sort.Slice(grid, func(i, j int) bool {
		ki, kj := kindRank(kindOf(grid[i])), kindRank(kindOf(grid[j]))
		if ki != kj {
			return ki < kj
		}
		return lessIP(grid[i].IP, grid[j].IP)
	})

	cols := columns(len(grid))
	width := pad*2 + float64(cols)*nodeW + float64(max(cols-1, 0))*gapX
	if width < pad*2+nodeW {
		width = pad*2 + nodeW
	}

	out := model.NetMap{
		Width:  width,
		Subnet: net.Subnet,
		Nodes:  []model.MapNode{},
		Lines:  []model.MapLine{},
		Note:   "A linha é a sub-rede do exame. Ela junta o que foi visto; não é a porta de um switch.",
	}

	var gw model.MapNode
	busY := pad
	if gateway != nil {
		gw = nodeAt(*gateway, dhcpIPs, (width-nodeW)/2, pad)
		out.Nodes = append(out.Nodes, gw)
		busY = gw.Y + gw.H + 28
	}

	if len(grid) == 0 {
		if gateway == nil {
			out.Height = pad * 2
			out.Note = "Examine a rede para desenhar o mapa."
			return out
		}
		out.Height = gw.Y + gw.H + pad
		return out
	}

	gridY := busY + 22
	placed := make([]model.MapNode, 0, len(grid))
	var minX, maxX float64
	for i, device := range grid {
		col := i % cols
		row := i / cols
		item := nodeAt(device, dhcpIPs, pad+float64(col)*(nodeW+gapX), gridY+float64(row)*(nodeH+gapY))
		placed = append(placed, item)
		cx := item.X + item.W/2
		if i == 0 || cx < minX {
			minX = cx
		}
		if i == 0 || cx > maxX {
			maxX = cx
		}
	}
	if gateway != nil {
		cx := gw.X + gw.W/2
		if cx < minX {
			minX = cx
		}
		if cx > maxX {
			maxX = cx
		}
	}
	if maxX-minX < 48 {
		mid := (minX + maxX) / 2
		minX = mid - 24
		maxX = mid + 24
	}
	out.Lines = append(out.Lines, model.MapLine{X1: minX, Y1: busY, X2: maxX, Y2: busY})
	if gateway != nil {
		cx := gw.X + gw.W/2
		out.Lines = append(out.Lines, model.MapLine{X1: cx, Y1: gw.Y + gw.H, X2: cx, Y2: busY})
	}
	for _, item := range placed {
		cx := item.X + item.W/2
		out.Lines = append(out.Lines, model.MapLine{X1: cx, Y1: busY, X2: cx, Y2: item.Y})
		out.Nodes = append(out.Nodes, item)
	}
	last := placed[len(placed)-1]
	out.Height = last.Y + last.H + pad
	return out
}

func nodeAt(d model.Device, dhcpIPs map[string]struct{}, x, y float64) model.MapNode {
	kind := kindOf(d)
	label, detail := labels(d, kind)
	badge := ""
	if _, ok := dhcpIPs[d.IP]; ok {
		badge = "DHCP"
		if !strings.Contains(detail, "DHCP") {
			detail = clip("DHCP · "+detail, 26)
		}
	}
	return model.MapNode{
		ID:     "ip:" + d.IP,
		Kind:   kind,
		Label:  label,
		Detail: detail,
		Badge:  badge,
		IP:     d.IP,
		X:      x,
		Y:      y,
		W:      nodeW,
		H:      nodeH,
	}
}

func kindOf(d model.Device) string {
	switch d.Role {
	case "gateway":
		return "gateway"
	case "este servidor":
		return "self"
	}
	printer, computer, media := false, false, false
	for _, port := range d.Ports {
		switch port.Port {
		case 515, 631, 9100:
			printer = true
		case 8008, 8009:
			media = true
		case 22, 139, 445, 3389:
			computer = true
		}
	}
	switch {
	case printer:
		return "printer"
	case media:
		return "media"
	case computer:
		return "computer"
	default:
		return "other"
	}
}

func kindRank(kind string) int {
	switch kind {
	case "self":
		return 0
	case "dhcp":
		return 1
	case "printer":
		return 2
	case "computer":
		return 3
	case "media":
		return 4
	default:
		return 5
	}
}

func columns(n int) int {
	switch {
	case n <= 1:
		return 1
	case n < 6:
		return n
	case n > 64:
		return 10
	case n > 24:
		return 8
	default:
		return 6
	}
}

func labels(d model.Device, kind string) (string, string) {
	name := strings.TrimSpace(d.Hostname)
	switch {
	case name == "" && kind == "self":
		name = "Este servidor"
	case name == "" && kind == "gateway":
		name = "Gateway"
	case name == "" && d.Vendor != "":
		name = d.Vendor
	case name == "":
		name = d.IP
	}
	detail := d.IP
	if name == d.IP {
		if d.Vendor != "" {
			detail = d.Vendor
		} else {
			detail = kindName(kind)
		}
	}
	return clip(name, 22), clip(detail, 26)
}

func kindName(kind string) string {
	switch kind {
	case "self":
		return "Este servidor"
	case "gateway":
		return "Gateway"
	case "printer":
		return "Impressora"
	case "computer":
		return "Computador"
	case "media":
		return "Mídia"
	case "dhcp":
		return "DHCP"
	default:
		return "Aparelho"
	}
}

func ensureAnchors(net model.Network, devices []model.Device) []model.Device {
	if net.IP != "" && !hasIP(devices, net.IP) {
		devices = append(devices, model.Device{
			IP:    net.IP,
			MAC:   net.MAC,
			Role:  "este servidor",
			Names: []string{},
			Ports: []model.Port{},
		})
	}
	if net.Gateway != "" && !hasIP(devices, net.Gateway) {
		devices = append(devices, model.Device{
			IP:    net.Gateway,
			Role:  "gateway",
			Names: []string{},
			Ports: []model.Port{},
		})
	}
	return devices
}

func dedupe(devices []model.Device) []model.Device {
	seen := map[string]int{}
	out := make([]model.Device, 0, len(devices))
	for _, d := range devices {
		if d.IP == "" {
			continue
		}
		if i, ok := seen[d.IP]; ok {
			out[i] = richer(out[i], d)
			continue
		}
		seen[d.IP] = len(out)
		out = append(out, d)
	}
	return out
}

func richer(a, b model.Device) model.Device {
	if a.Hostname == "" {
		a.Hostname = b.Hostname
	}
	if a.MAC == "" {
		a.MAC = b.MAC
	}
	if a.Vendor == "" {
		a.Vendor = b.Vendor
	}
	if a.Role == "" {
		a.Role = b.Role
	}
	if len(b.Ports) > len(a.Ports) {
		a.Ports = b.Ports
	}
	return a
}

func dhcpAddrs(servers []model.DHCPServer) map[string]struct{} {
	out := map[string]struct{}{}
	for _, server := range servers {
		if ip, err := netip.ParseAddr(server.ServerID); err == nil && ip.Is4() {
			out[ip.String()] = struct{}{}
		}
		if ip, err := netip.ParseAddr(server.SourceIP); err == nil && ip.Is4() {
			out[ip.String()] = struct{}{}
		}
	}
	return out
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

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n < 2 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
