//go:build linux

package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/arp"
)

func ScanMAC(ctx context.Context, ifi *net.Interface, ips []netip.Addr) (map[string]string, error) {
	found := map[string]string{}
	if len(ips) == 0 {
		return found, nil
	}
	if ifi == nil {
		return nil, fmt.Errorf("interface ausente")
	}
	c, err := arp.Dial(ifi)
	if err != nil {
		return nil, fmt.Errorf("ARP: %w (no Linux isso pede root ou cap_net_raw)", err)
	}
	defer c.Close()

	deadline := time.Now().Add(8 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			pkt, _, err := c.Read()
			if err != nil {
				return
			}
			if pkt.Operation != arp.OperationReply || !pkt.SenderIP.Is4() {
				continue
			}
			found[pkt.SenderIP.String()] = pkt.SenderHardwareAddr.String()
		}
	}()

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		if err := c.Request(ip); err != nil {
			break
		}
	}
	<-done
	out := make(map[string]string, len(found))
	for k, v := range found {
		out[k] = v
	}
	return out, nil
}

func ResolveMAC(ifi *net.Interface, ip netip.Addr) (string, error) {
	if ifi == nil {
		return "", fmt.Errorf("interface ausente")
	}
	c, err := arp.Dial(ifi)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	hw, err := c.Resolve(ip)
	if err != nil {
		return "", err
	}
	return hw.String(), nil
}
