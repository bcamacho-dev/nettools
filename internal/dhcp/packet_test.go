package dhcp

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestDiscoverRoundTrip(t *testing.T) {
	hw := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x11}
	pkt, err := newDiscover(hw)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := dhcpv4.FromBytes(pkt.ToBytes())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.MessageType() != dhcpv4.MessageTypeDiscover {
		t.Fatalf("type = %s", parsed.MessageType())
	}
	if !parsed.IsBroadcast() {
		t.Fatal("discover should request a broadcast reply")
	}
}

func TestParseOffer(t *testing.T) {
	var xid dhcpv4.TransactionID
	xid[0] = 0x11
	offer, err := dhcpv4.New(
		dhcpv4.WithTransactionID(xid),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithYourIP(net.IPv4(192, 168, 1, 50)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.IPv4(192, 168, 1, 1))),
		dhcpv4.WithOption(dhcpv4.OptHostName("router")),
	)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseOffer(offer.ToBytes(), xid, net.IPv4(192, 168, 1, 1))
	if !ok {
		t.Fatal("expected offer")
	}
	if got.ServerID != "192.168.1.1" || got.OfferedIP != "192.168.1.50" || got.Hostname != "router" {
		t.Fatalf("%+v", got)
	}
	if _, ok := parseOffer(offer.ToBytes(), dhcpv4.TransactionID{9}, net.IPv4(192, 168, 1, 1)); ok {
		t.Fatal("xid mismatch should be ignored")
	}
}
