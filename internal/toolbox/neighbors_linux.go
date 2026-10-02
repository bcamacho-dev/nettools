//go:build linux

package toolbox

import (
	"os"

	"nettools/internal/model"
	"nettools/internal/netinfo"
)

func Neighbors(netinfo.Info) ([]model.Neighbor, error) {
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	return parseLinuxARP(string(b)), nil
}
