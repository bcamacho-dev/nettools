package netinfo

import (
	"net/netip"
	"testing"
)

func TestHosts24(t *testing.T) {
	p := netip.MustParsePrefix("192.168.1.0/24")
	hosts, err := Hosts(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 254 {
		t.Fatalf("hosts = %d, want 254", len(hosts))
	}
	if hosts[0] != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("first = %s", hosts[0])
	}
	if hosts[len(hosts)-1] != netip.MustParseAddr("192.168.1.254") {
		t.Fatalf("last = %s", hosts[len(hosts)-1])
	}
}

func TestHosts30And31(t *testing.T) {
	h30, err := Hosts(netip.MustParsePrefix("10.0.0.0/30"))
	if err != nil {
		t.Fatal(err)
	}
	if len(h30) != 2 {
		t.Fatalf("/30 hosts = %d", len(h30))
	}
	h31, err := Hosts(netip.MustParsePrefix("10.0.0.0/31"))
	if err != nil {
		t.Fatal(err)
	}
	if len(h31) != 2 {
		t.Fatalf("/31 hosts = %d", len(h31))
	}
}

func TestHostsTooWide(t *testing.T) {
	_, err := Hosts(netip.MustParsePrefix("10.0.0.0/16"))
	if err == nil {
		t.Fatal("expected rejection")
	}
}

func TestContainsPrefix(t *testing.T) {
	outer := netip.MustParsePrefix("192.168.0.0/16")
	inner := netip.MustParsePrefix("192.168.1.0/24")
	if !ContainsPrefix(outer, inner) {
		t.Fatal("expected /16 to cover /24")
	}
	if ContainsPrefix(inner, outer) {
		t.Fatal("/24 must not cover /16")
	}
	if ContainsPrefix(netip.MustParsePrefix("10.0.0.0/8"), inner) {
		t.Fatal("10/8 must not cover 192.168.1.0/24")
	}
}

func TestCGNAT(t *testing.T) {
	if !isCGNAT(netip.MustParseAddr("100.64.0.1")) {
		t.Fatal("100.64.0.1 should be CGNAT")
	}
	if isCGNAT(netip.MustParseAddr("100.127.0.1")) == false {
		t.Fatal("100.127.0.1 should be CGNAT")
	}
	if isCGNAT(netip.MustParseAddr("100.128.0.1")) {
		t.Fatal("100.128.0.1 is outside CGNAT")
	}
}
