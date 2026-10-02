package store

import (
	"path/filepath"
	"testing"
	"time"

	"nettools/internal/model"
)

func TestScanRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sc := model.EmptyScan()
	sc.ID = "abc"
	sc.Kind = "discover"
	sc.Status = "running"
	sc.Detail = "Iniciando"
	sc.Started = time.Now().UTC()
	sc.Network = model.Network{Interface: "eth0", IP: "192.168.1.10", Subnet: "192.168.1.0/24", Hosts: 253, OS: "linux", Scannable: true}
	if err := s.CreateScan(sc); err != nil {
		t.Fatal(err)
	}
	devices := []model.Device{{
		IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "Test", Hostname: "gw",
		Names: []string{"dns:gw.lan"}, Ports: []model.Port{{Port: 80, Label: "http"}}, Role: "gateway",
	}}
	servers := []model.DHCPServer{{
		ServerID: "192.168.1.1", SourceIP: "192.168.1.1", OfferedIP: "192.168.1.50",
		DNS: []string{"192.168.1.1"}, Router: []string{"192.168.1.1"},
	}}
	if err := s.Complete(sc.ID, devices, servers, ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "done" || len(got.Devices) != 1 || got.Devices[0].Hostname != "gw" {
		t.Fatalf("%+v", got)
	}
	if len(got.DHCP) != 1 || got.DHCP[0].OfferedIP != "192.168.1.50" {
		t.Fatalf("dhcp %+v", got.DHCP)
	}
	latest, err := s.Latest("discover")
	if err != nil || latest.ID != "abc" {
		t.Fatalf("latest %+v %v", latest, err)
	}
}
