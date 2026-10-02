//go:build !linux && !windows

package dhcp

import (
	"context"
	"fmt"
	"net"

	"nettools/internal/model"
)

func Discover(context.Context, *net.Interface) ([]model.DHCPServer, error) {
	return nil, fmt.Errorf("descoberta DHCP não está disponível neste sistema")
}
