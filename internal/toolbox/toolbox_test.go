package toolbox

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"nettools/internal/netinfo"
)

func TestBroadcast(t *testing.T) {
	if got := broadcast(netip.MustParsePrefix("192.168.1.0/24")); got.String() != "192.168.1.255" {
		t.Fatalf("broadcast = %s", got)
	}
	if broadcast(netip.MustParsePrefix("10.0.0.1/32")).IsValid() {
		t.Fatal("/32 não tem broadcast")
	}
}

func TestDNSFromResolv(t *testing.T) {
	text := "# comentário\nnameserver 192.168.0.1\nnameserver 192.168.0.1\nnameserver 1.1.1.1\n"
	got := dnsFromResolv(text)
	if len(got) != 2 || got[0] != "192.168.0.1" || got[1] != "1.1.1.1" {
		t.Fatalf("dns = %#v", got)
	}
}

func TestParseARecord(t *testing.T) {
	msg := buildQuery(0x1234, "nas.local", 1, false)
	msg[2], msg[3] = 0x81, 0x80
	msg[7] = 1
	msg = append(msg, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 192, 168, 1, 20)
	recs := parseRecords(msg)
	if len(recs) != 1 || recs[0].IP != "192.168.1.20" || recs[0].Type != 1 {
		t.Fatalf("recs = %#v", recs)
	}
}

func TestAssembleService(t *testing.T) {
	recs := []rec{
		{Name: "_ipp._tcp.local", Type: 12, Ptr: `HP\032LaserJet._ipp._tcp.local`},
		{Name: `HP\032LaserJet._ipp._tcp.local`, Type: 33, Port: 631, Target: "hp.local"},
		{Name: "hp.local", Type: 1, IP: "192.168.1.40"},
	}
	got := assemble(recs)
	if len(got) != 1 {
		t.Fatalf("services = %#v", got)
	}
	if got[0].Name != "HP LaserJet" || got[0].Port != 631 || got[0].IP != "192.168.1.40" || got[0].Type != "_ipp._tcp" {
		t.Fatalf("service = %#v", got[0])
	}
}

func TestMagicAndMAC(t *testing.T) {
	hw, err := parseMAC("AA-BB-CC-DD-EE-FF")
	if err != nil {
		t.Fatal(err)
	}
	pkt := magic(hw)
	if len(pkt) != 102 {
		t.Fatalf("len = %d", len(pkt))
	}
	for i := 0; i < 6; i++ {
		if pkt[i] != 0xff {
			t.Fatal("prefixo")
		}
	}
	if !strings.EqualFold(hw.String(), "aa:bb:cc:dd:ee:ff") {
		t.Fatal(hw)
	}
	if _, err := parseMAC("01:00:00:00:00:00"); err == nil {
		t.Fatal("multicast deveria falhar")
	}
	dotted, err := parseMAC("aabb.ccdd.eeff")
	if err != nil || dotted.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("dotted = %s %v", dotted, err)
	}
}

func TestParseHops(t *testing.T) {
	tracert := `
Tracing route to 1.1.1.1 over a maximum of 8 hops

  1     1 ms     3 ms     2 ms  192.168.0.1
  2     *        *        *     Esgotado o tempo limite do pedido.
  3    12 ms     9 ms    11 ms  1.1.1.1
`
	hops := parseHops(tracert)
	if len(hops) != 3 || hops[0].IP != "192.168.0.1" || hops[0].MS != 2 || !hops[1].Timeout || hops[2].IP != "1.1.1.1" {
		t.Fatalf("tracert = %#v", hops)
	}
	tracepath := `
 1?: [LOCALHOST]                      pmtu 1500
 1:  10.0.0.1                                          0.842ms
 2:  no reply
`
	hops = parseHops(tracepath)
	if len(hops) != 2 || hops[0].IP != "10.0.0.1" || hops[0].MS < 0.8 || hops[0].MS > 0.9 || !hops[1].Timeout {
		t.Fatalf("tracepath = %#v", hops)
	}
}

func TestARPParsers(t *testing.T) {
	win := `
Interface: 192.168.1.10 --- 0x5
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.1             01-00-5e-00-00-01     static
`
	got := parseWindowsARP(win)
	if len(got) != 1 || got[0].MAC != "aa:bb:cc:dd:ee:ff" || got[0].Interface != "192.168.1.10" {
		t.Fatalf("windows = %#v", got)
	}
	linux := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.0.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n" +
		"192.168.0.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	got = parseLinuxARP(linux)
	if len(got) != 1 || got[0].Interface != "eth0" || got[0].IP != "192.168.0.1" {
		t.Fatalf("linux = %#v", got)
	}
}

func TestResolveLANRejectsPublic(t *testing.T) {
	info := netinfo.Info{IfacePrefix: netip.MustParsePrefix("192.168.1.0/24")}
	if _, err := resolveLAN(t.Context(), info, "8.8.8.8"); err == nil {
		t.Fatal("IP público deveria ser recusado")
	}
	ip, err := resolveLAN(t.Context(), info, "192.168.1.20")
	if err != nil || ip.String() != "192.168.1.20" {
		t.Fatalf("lan = %s %v", ip, err)
	}
	if validName("-tracert") || validName("nome com espaço") || !validName("nas_01.local") {
		t.Fatal("validação de nome")
	}
}

func TestPortLabel(t *testing.T) {
	if portLabel(9100) != "impressora" || portLabel(9) != "tcp" {
		t.Fatal(portLabel(9100), portLabel(9))
	}
	if net.ParseIP("192.168.0.1") == nil {
		t.Fatal("ip")
	}
}
