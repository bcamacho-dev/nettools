//go:build linux

package dhcp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"

	"nettools/internal/model"
)

func Discover(ctx context.Context, ifi *net.Interface) ([]model.DHCPServer, error) {
	if ifi == nil || len(ifi.HardwareAddr) == 0 {
		return nil, fmt.Errorf("interface sem endereço MAC")
	}
	conn, err := nclient4.NewRawUDPConn(ifi.Name, 68)
	if err != nil {
		return nil, fmt.Errorf("socket DHCP: %w (no Linux isso pede root ou cap_net_raw)", err)
	}
	defer conn.Close()

	pkt, err := newDiscover(ifi.HardwareAddr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	dest := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	if _, err := conn.WriteTo(pkt.ToBytes(), dest); err != nil {
		return nil, fmt.Errorf("envio DHCP: %w", err)
	}
	go func() {
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			_, _ = conn.WriteTo(pkt.ToBytes(), dest)
		}
	}()
	return readOffers(conn, pkt.TransactionID), nil
}
