//go:build !linux && !windows

package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

func ScanMAC(context.Context, *net.Interface, []netip.Addr) (map[string]string, error) {
	return nil, fmt.Errorf("varredura ARP não está disponível neste sistema")
}

func ResolveMAC(*net.Interface, netip.Addr) (string, error) {
	return "", fmt.Errorf("ARP não está disponível neste sistema")
}
