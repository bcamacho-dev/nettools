package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"time"

	"nettools/internal/discover"
	"nettools/internal/model"
	"nettools/internal/netinfo"
	"nettools/internal/netmap"
	"nettools/internal/stability"
	"nettools/internal/store"
	"nettools/internal/toolbox"
)

var ErrBusy = errors.New("já existe um exame em andamento")

type Engine struct {
	store *store.Store
	iface string
	cidr  string
	mu    sync.Mutex
	busy  bool
}

func New(st *store.Store, iface, cidr string) *Engine {
	return &Engine{store: st, iface: iface, cidr: cidr}
}

func (e *Engine) Network() (model.Network, error) {
	info, err := netinfo.Detect(e.iface, e.cidr)
	if err != nil {
		return model.Network{}, err
	}
	return networkView(info), nil
}

func (e *Engine) StartDiscover() (model.Scan, error) {
	info, err := netinfo.Detect(e.iface, e.cidr)
	if err != nil {
		return model.Scan{}, err
	}
	if !info.LocalOK() {
		return model.Scan{}, &netinfo.Rejected{Reason: "a interface não está numa rede local"}
	}
	if !info.Scannable {
		return model.Scan{}, &netinfo.Rejected{Reason: info.ScanError}
	}
	if !e.begin() {
		return model.Scan{}, ErrBusy
	}

	sc := model.EmptyScan()
	sc.ID = newID()
	sc.Kind = "discover"
	sc.Status = "running"
	sc.Detail = "Iniciando"
	sc.Started = time.Now().UTC()
	sc.Network = networkView(info)
	if err := e.store.CreateScan(sc); err != nil {
		e.end()
		return model.Scan{}, err
	}
	go e.runDiscover(sc.ID, info)
	return sc, nil
}

func (e *Engine) DHCP(ctx context.Context) (model.Scan, error) {
	info, err := netinfo.Detect(e.iface, e.cidr)
	if err != nil {
		return model.Scan{}, err
	}
	if !info.LocalOK() {
		return model.Scan{}, &netinfo.Rejected{Reason: "a interface não está numa rede local"}
	}
	var id string
	err = e.withExam(func() error {
		sc := model.EmptyScan()
		sc.ID = newID()
		id = sc.ID
		sc.Kind = "dhcp"
		sc.Status = "running"
		sc.Detail = "Procurando DHCP"
		sc.Started = time.Now().UTC()
		sc.Network = networkView(info)
		if err := e.store.CreateScan(sc); err != nil {
			return err
		}
		result := discover.DHCPOnly(ctx, info)
		return e.store.Complete(sc.ID, nil, result.DHCP, result.DHCPError)
	})
	if err != nil {
		return model.Scan{}, err
	}
	return e.store.Get(id)
}

func (e *Engine) Stability(ctx context.Context, target string, count int) (model.Stability, error) {
	if target == "" {
		info, err := netinfo.Detect(e.iface, e.cidr)
		if err != nil {
			return model.Stability{}, err
		}
		if !info.Gateway.IsValid() {
			return model.Stability{}, &netinfo.Rejected{Reason: "não há gateway para medir"}
		}
		target = info.Gateway.String()
	}
	var result model.Stability
	err := e.withExam(func() error {
		var err error
		result, err = stability.Probe(ctx, target, count)
		if err != nil {
			return err
		}
		return e.store.SaveStability(result)
	})
	return result, err
}

func (e *Engine) SaveSpeed(sp model.Speed) (model.Speed, error) {
	if sp.DownMbps < 0 || sp.UpMbps < 0 || sp.HTTPRTTMS < 0 || sp.DownMbps > 100000 || sp.UpMbps > 100000 {
		return model.Speed{}, &netinfo.Rejected{Reason: "medição inválida"}
	}
	sp.ID = newID()
	sp.At = time.Now().UTC()
	if err := e.store.SaveSpeed(sp); err != nil {
		return model.Speed{}, err
	}
	return sp, nil
}

func (e *Engine) LatestScan(kind string) (model.Scan, error) {
	return e.store.Latest(kind)
}

func (e *Engine) Scan(id string) (model.Scan, error) {
	return e.store.Get(id)
}

func (e *Engine) LatestStability() (model.Stability, error) {
	return e.store.LatestStability()
}

func (e *Engine) LatestSpeed() (model.Speed, error) {
	return e.store.LatestSpeed()
}

func (e *Engine) LAN() (model.LAN, error) {
	info, err := netinfo.Detect(e.iface, e.cidr)
	if err != nil {
		return model.LAN{}, err
	}
	return toolbox.Snapshot(info), nil
}

func (e *Engine) Map() (model.NetMap, error) {
	net := model.Network{}
	if info, err := netinfo.Detect(e.iface, e.cidr); err == nil {
		net = info.View()
	}
	scan, err := e.store.Latest("discover")
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return netmap.Build(net, nil, nil), nil
		}
		return model.NetMap{}, err
	}
	if scan.Network.IP != "" {
		net = scan.Network
	}
	return netmap.Build(net, scan.Devices, scan.DHCP), nil
}

func (e *Engine) Neighbors() ([]model.Neighbor, error) {
	return toolbox.Neighbors(netinfo.Info{})
}

func (e *Engine) LookupDNS(ctx context.Context, name string) (model.DNSResult, error) {
	info, err := e.detect()
	if err != nil {
		return model.DNSResult{}, err
	}
	var result model.DNSResult
	err = e.withExam(func() error {
		var err error
		result, err = toolbox.Lookup(ctx, info, name)
		return err
	})
	return result, err
}

func (e *Engine) Reach(ctx context.Context, host string, port int) (model.ReachResult, error) {
	info, err := e.detect()
	if err != nil {
		return model.ReachResult{}, err
	}
	var result model.ReachResult
	err = e.withExam(func() error {
		var err error
		result, err = toolbox.Reach(ctx, info, host, port)
		return err
	})
	return result, err
}

func (e *Engine) Path(ctx context.Context, host string, exit bool) (model.PathResult, error) {
	info, err := e.detect()
	if err != nil {
		return model.PathResult{}, err
	}
	var result model.PathResult
	err = e.withExam(func() error {
		var err error
		result, err = toolbox.Path(ctx, info, host, exit)
		return err
	})
	return result, err
}

func (e *Engine) Services(ctx context.Context) ([]model.Service, error) {
	info, err := e.detect()
	if err != nil {
		return nil, err
	}
	var result []model.Service
	err = e.withExam(func() error {
		var err error
		result, err = toolbox.Services(ctx, info)
		return err
	})
	return result, err
}

func (e *Engine) Wake(mac string) (model.WakeResult, error) {
	info, err := e.detect()
	if err != nil {
		return model.WakeResult{}, err
	}
	return toolbox.Wake(info, mac)
}

func (e *Engine) detect() (netinfo.Info, error) {
	info, err := netinfo.Detect(e.iface, e.cidr)
	if err != nil {
		return netinfo.Info{}, err
	}
	if !info.LocalOK() {
		return netinfo.Info{}, &netinfo.Rejected{Reason: "a interface não está numa rede local"}
	}
	return info, nil
}

func (e *Engine) runDiscover(id string, info netinfo.Info) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("exame", "panic", rec)
			_ = e.store.Fail(id, "falha interna")
		}
		e.end()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	result, err := discover.Run(ctx, info, func(detail string) {
		_ = e.store.UpdateDetail(id, detail)
	})
	if err != nil {
		slog.Error("exame", "id", id, "err", err)
		_ = e.store.Fail(id, err.Error())
		return
	}
	if err := e.store.Complete(id, result.Devices, result.DHCP, result.DHCPError); err != nil {
		slog.Error("gravar exame", "id", id, "err", err)
		_ = e.store.Fail(id, err.Error())
	}
}

func (e *Engine) withExam(fn func() error) error {
	if !e.begin() {
		return ErrBusy
	}
	defer e.end()
	return fn()
}

func (e *Engine) begin() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.busy {
		return false
	}
	e.busy = true
	return true
}

func (e *Engine) end() {
	e.mu.Lock()
	e.busy = false
	e.mu.Unlock()
}

func networkView(n netinfo.Info) model.Network {
	gw := ""
	if n.Gateway.IsValid() {
		gw = n.Gateway.String()
	}
	name, mac := "", ""
	if n.Iface != nil {
		name = n.Iface.Name
		mac = n.Iface.HardwareAddr.String()
	}
	return model.Network{
		Interface: name,
		MAC:       mac,
		IP:        n.Local.String(),
		Subnet:    n.Prefix.String(),
		Gateway:   gw,
		Hosts:     n.HostCount,
		OS:        n.OS,
		Scannable: n.Scannable,
		ScanError: n.ScanError,
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
