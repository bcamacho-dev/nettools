package netmap

import (
	"testing"

	"nettools/internal/model"
)

func TestBuildPlacesGatewayAndHosts(t *testing.T) {
	net := model.Network{IP: "192.168.0.10", Gateway: "192.168.0.1", Subnet: "192.168.0.0/24"}
	devices := []model.Device{
		{IP: "192.168.0.20", Hostname: "hp", Ports: []model.Port{{Port: 9100, Label: "impressora"}}, Names: []string{}},
		{IP: "192.168.0.30", Hostname: "notebook", Ports: []model.Port{{Port: 445, Label: "smb"}}, Names: []string{}},
		{IP: "192.168.0.10", Hostname: "nettools", Role: "este servidor", Names: []string{}, Ports: []model.Port{}},
		{IP: "192.168.0.1", Hostname: "roteador", Role: "gateway", Names: []string{}, Ports: []model.Port{}},
	}
	dhcp := []model.DHCPServer{{ServerID: "192.168.0.1", SourceIP: "192.168.0.1"}}
	got := Build(net, devices, dhcp)

	if len(got.Nodes) != 4 {
		t.Fatalf("nodes = %d", len(got.Nodes))
	}
	var gw, self, printer model.MapNode
	for _, node := range got.Nodes {
		switch node.IP {
		case "192.168.0.1":
			gw = node
		case "192.168.0.10":
			self = node
		case "192.168.0.20":
			printer = node
		}
	}
	if gw.Kind != "gateway" || gw.Badge != "DHCP" {
		t.Fatalf("gateway = %#v", gw)
	}
	if self.Kind != "self" || printer.Kind != "printer" {
		t.Fatalf("self %#v printer %#v", self, printer)
	}
	if gw.Y >= self.Y {
		t.Fatalf("gateway should sit above the hosts: gw %v self %v", gw.Y, self.Y)
	}
	if overlaps(got.Nodes) {
		t.Fatal("nodes overlap")
	}
	if !stemMeetsBus(got, self) || !stemMeetsBus(got, printer) {
		t.Fatal("host stem should meet the bus")
	}
}

func TestBuildWithoutScanUsesNetwork(t *testing.T) {
	got := Build(model.Network{IP: "10.0.0.5", Gateway: "10.0.0.1", Subnet: "10.0.0.0/24"}, nil, nil)
	if len(got.Nodes) != 2 {
		t.Fatalf("nodes = %#v", got.Nodes)
	}
	if got.Subnet != "10.0.0.0/24" {
		t.Fatal(got.Subnet)
	}
}

func TestBuildManyDoNotOverlap(t *testing.T) {
	devices := make([]model.Device, 0, 30)
	for i := 1; i <= 30; i++ {
		devices = append(devices, model.Device{
			IP:    "192.168.1." + itoa(i),
			Names: []string{},
			Ports: []model.Port{},
		})
	}
	got := Build(model.Network{IP: "192.168.1.2", Gateway: "192.168.1.1"}, devices, nil)
	if overlaps(got.Nodes) {
		t.Fatal("overlap in a 30 host map")
	}
	if got.Width < nodeW || got.Height < nodeH {
		t.Fatalf("size %v x %v", got.Width, got.Height)
	}
}

func overlaps(nodes []model.MapNode) bool {
	for i := range nodes {
		for j := i + 1; j < len(nodes); j++ {
			a, b := nodes[i], nodes[j]
			if a.X < b.X+b.W && b.X < a.X+a.W && a.Y < b.Y+b.H && b.Y < a.Y+a.H {
				return true
			}
		}
	}
	return false
}

func stemMeetsBus(m model.NetMap, node model.MapNode) bool {
	cx := node.X + node.W/2
	for _, line := range m.Lines {
		if line.X1 == cx && line.X2 == cx && line.Y2 == node.Y && line.Y1 < node.Y {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}
