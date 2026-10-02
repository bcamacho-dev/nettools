//go:build windows

package dhcp

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/windows"

	"nettools/internal/model"
)

func Discover(ctx context.Context, ifi *net.Interface) ([]model.DHCPServer, error) {
	if ifi == nil || len(ifi.HardwareAddr) == 0 {
		return nil, fmt.Errorf("interface sem endereço MAC")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 68})
	if err != nil {
		return nil, fmt.Errorf("não foi possível abrir a porta UDP 68: %w. No Windows isso pede administrador e a porta livre; o exame completo de DHCP roda no servidor Linux", err)
	}
	defer conn.Close()
	if raw, err := conn.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
		})
	}

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
	payload := pkt.ToBytes()
	targets := []*net.UDPAddr{{IP: net.IPv4bcast, Port: 67}}
	for _, ip := range directedBroadcasts(ifi) {
		targets = append(targets, &net.UDPAddr{IP: ip, Port: 67})
	}
	var sent bool
	var sendErr error
	for _, dest := range targets {
		if _, err := conn.WriteTo(payload, dest); err != nil {
			sendErr = err
			continue
		}
		sent = true
	}
	if !sent {
		return nil, fmt.Errorf("envio DHCP: %w", sendErr)
	}
	return readOffers(conn, pkt.TransactionID), nil
}
