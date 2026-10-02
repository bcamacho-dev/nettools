//go:build !linux && !windows

package toolbox

import (
	"nettools/internal/model"
	"nettools/internal/netinfo"
)

func Neighbors(netinfo.Info) ([]model.Neighbor, error) {
	return nil, &netinfo.Rejected{Reason: "a tabela de vizinhos não está disponível neste sistema"}
}
