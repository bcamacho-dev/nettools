//go:build windows

package discover

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procSendARP = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SendARP")

func ScanMAC(ctx context.Context, _ *net.Interface, ips []netip.Addr) (map[string]string, error) {
	found := map[string]string{}
	if len(ips) == 0 {
		return found, nil
	}
	if err := procSendARP.Find(); err != nil {
		return nil, fmt.Errorf("SendARP: %w", err)
	}
	var mu sync.Mutex
	sem := make(chan struct{}, 48)
	var wg sync.WaitGroup
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			wg.Wait()
			return found, nil
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			mac, err := sendARP(ip)
			if err != nil {
				return
			}
			mu.Lock()
			found[ip.String()] = mac.String()
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return found, nil
}

func ResolveMAC(_ *net.Interface, ip netip.Addr) (string, error) {
	if err := procSendARP.Find(); err != nil {
		return "", err
	}
	mac, err := sendARP(ip)
	if err != nil {
		return "", err
	}
	return mac.String(), nil
}

func sendARP(ip netip.Addr) (net.HardwareAddr, error) {
	if !ip.Is4() {
		return nil, fmt.Errorf("não é IPv4")
	}
	b := ip.As4()
	dest := binary.LittleEndian.Uint32(b[:])
	mac := make([]byte, 8)
	macLen := uint32(len(mac))
	r, _, _ := procSendARP.Call(
		uintptr(dest),
		0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if r != 0 || macLen == 0 || macLen > 8 {
		return nil, fmt.Errorf("sem resposta")
	}
	return append(net.HardwareAddr(nil), mac[:macLen]...), nil
}
