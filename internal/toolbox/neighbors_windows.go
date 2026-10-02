//go:build windows

package toolbox

import (
	"os/exec"

	"nettools/internal/model"
	"nettools/internal/netinfo"
)

func Neighbors(netinfo.Info) ([]model.Neighbor, error) {
	cmd := exec.Command("arp", "-a")
	configure(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil, &netinfo.Rejected{Reason: "não foi possível ler a tabela ARP"}
	}
	return parseWindowsARP(string(out)), nil
}
