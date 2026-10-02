package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"nettools/internal/model"
)

var ErrNotFound = errors.New("exame não encontrado")

type Store struct {
	mu sync.Mutex
	db *sql.DB
}

func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", abs)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if _, err := db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  dhcp_error TEXT NOT NULL DEFAULT '',
  started TEXT NOT NULL,
  finished TEXT,
  iface TEXT NOT NULL DEFAULT '',
  mac TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  subnet TEXT NOT NULL DEFAULT '',
  gateway TEXT NOT NULL DEFAULT '',
  hosts INTEGER NOT NULL DEFAULT 0,
  os TEXT NOT NULL DEFAULT '',
  scannable INTEGER NOT NULL DEFAULT 0,
  scan_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS devices (
  scan_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  mac TEXT NOT NULL DEFAULT '',
  vendor TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  names TEXT NOT NULL DEFAULT '[]',
  ports TEXT NOT NULL DEFAULT '[]',
  http_title TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS dhcp_servers (
  scan_id TEXT NOT NULL,
  server_id TEXT NOT NULL DEFAULT '',
  source_ip TEXT NOT NULL DEFAULT '',
  mac TEXT NOT NULL DEFAULT '',
  vendor TEXT NOT NULL DEFAULT '',
  offered_ip TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  subnet_mask TEXT NOT NULL DEFAULT '',
  dns TEXT NOT NULL DEFAULT '[]',
  router TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS stability (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  target TEXT NOT NULL,
  sent INTEGER NOT NULL,
  recv INTEGER NOT NULL,
  loss REAL NOT NULL,
  min_ms REAL NOT NULL,
  avg_ms REAL NOT NULL,
  max_ms REAL NOT NULL,
  jitter_ms REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS speed_tests (
  id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  down_mbps REAL NOT NULL,
  up_mbps REAL NOT NULL,
  http_rtt_ms REAL NOT NULL
);`)
	return err
}

func (s *Store) CreateScan(sc model.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO scans (
    id, kind, status, detail, error, dhcp_error, started, finished,
    iface, mac, ip, subnet, gateway, hosts, os, scannable, scan_error
  ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sc.ID, sc.Kind, sc.Status, sc.Detail, sc.Error, sc.DHCPError, fmtTime(sc.Started),
		sc.Network.Interface, sc.Network.MAC, sc.Network.IP, sc.Network.Subnet, sc.Network.Gateway,
		sc.Network.Hosts, sc.Network.OS, boolInt(sc.Network.Scannable), sc.Network.ScanError,
	)
	return err
}

func (s *Store) UpdateDetail(id, detail string) error {
	if len(detail) > 200 {
		detail = detail[:200]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE scans SET detail = ? WHERE id = ?`, detail, id)
	return err
}

func (s *Store) Fail(id, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE scans SET status = 'error', error = ?, detail = ?, finished = ? WHERE id = ?`,
		message, "Falhou", fmtTime(time.Now().UTC()), id)
	return err
}

func (s *Store) Complete(id string, devices []model.Device, servers []model.DHCPServer, dhcpError string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE scans SET status = 'done', detail = ?, dhcp_error = ?, finished = ? WHERE id = ?`,
		"Concluído", dhcpError, fmtTime(time.Now().UTC()), id); err != nil {
		return err
	}
	if err := insertDevices(tx, id, devices); err != nil {
		return err
	}
	if err := insertDHCP(tx, id, servers); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Get(id string) (model.Scan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(id)
}

func (s *Store) Latest(kind string) (model.Scan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	err := s.db.QueryRow(`SELECT id FROM scans WHERE kind = ? ORDER BY started DESC LIMIT 1`, kind).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, ErrNotFound
	}
	if err != nil {
		return model.Scan{}, err
	}
	return s.get(id)
}

func (s *Store) SaveStability(st model.Stability) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO stability (at, target, sent, recv, loss, min_ms, avg_ms, max_ms, jitter_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fmtTime(st.At), st.Target, st.Sent, st.Recv, st.Loss, st.MinMS, st.AvgMS, st.MaxMS, st.JitterMS)
	return err
}

func (s *Store) LatestStability() (model.Stability, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var st model.Stability
	var at string
	err := s.db.QueryRow(`SELECT at, target, sent, recv, loss, min_ms, avg_ms, max_ms, jitter_ms
    FROM stability ORDER BY id DESC LIMIT 1`).Scan(
		&at, &st.Target, &st.Sent, &st.Recv, &st.Loss, &st.MinMS, &st.AvgMS, &st.MaxMS, &st.JitterMS)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Stability{}, ErrNotFound
	}
	if err != nil {
		return model.Stability{}, err
	}
	st.At, err = time.Parse(time.RFC3339Nano, at)
	return st, err
}

func (s *Store) SaveSpeed(sp model.Speed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO speed_tests (id, at, down_mbps, up_mbps, http_rtt_ms) VALUES (?, ?, ?, ?, ?)`,
		sp.ID, fmtTime(sp.At), sp.DownMbps, sp.UpMbps, sp.HTTPRTTMS)
	return err
}

func (s *Store) LatestSpeed() (model.Speed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sp model.Speed
	var at string
	err := s.db.QueryRow(`SELECT id, at, down_mbps, up_mbps, http_rtt_ms FROM speed_tests ORDER BY at DESC LIMIT 1`).
		Scan(&sp.ID, &at, &sp.DownMbps, &sp.UpMbps, &sp.HTTPRTTMS)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Speed{}, ErrNotFound
	}
	if err != nil {
		return model.Speed{}, err
	}
	sp.At, err = time.Parse(time.RFC3339Nano, at)
	return sp, err
}

func (s *Store) get(id string) (model.Scan, error) {
	var sc model.Scan
	var started, finished sql.NullString
	var scannable int
	err := s.db.QueryRow(`SELECT id, kind, status, detail, error, dhcp_error, started, finished,
    iface, mac, ip, subnet, gateway, hosts, os, scannable, scan_error
    FROM scans WHERE id = ?`, id).Scan(
		&sc.ID, &sc.Kind, &sc.Status, &sc.Detail, &sc.Error, &sc.DHCPError, &started, &finished,
		&sc.Network.Interface, &sc.Network.MAC, &sc.Network.IP, &sc.Network.Subnet, &sc.Network.Gateway,
		&sc.Network.Hosts, &sc.Network.OS, &scannable, &sc.Network.ScanError,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, ErrNotFound
	}
	if err != nil {
		return model.Scan{}, err
	}
	sc.Network.Scannable = scannable == 1
	sc.Started, err = time.Parse(time.RFC3339Nano, started.String)
	if err != nil {
		return model.Scan{}, err
	}
	if finished.Valid && finished.String != "" {
		t, err := time.Parse(time.RFC3339Nano, finished.String)
		if err != nil {
			return model.Scan{}, err
		}
		sc.Finished = &t
	}
	sc.Devices, err = s.devices(id)
	if err != nil {
		return model.Scan{}, err
	}
	sc.DHCP, err = s.dhcpServers(id)
	if err != nil {
		return model.Scan{}, err
	}
	return sc, nil
}

func (s *Store) devices(id string) ([]model.Device, error) {
	rows, err := s.db.Query(`SELECT ip, mac, vendor, hostname, names, ports, http_title, role
    FROM devices WHERE scan_id = ? ORDER BY ip`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Device{}
	for rows.Next() {
		var d model.Device
		var names, ports string
		if err := rows.Scan(&d.IP, &d.MAC, &d.Vendor, &d.Hostname, &names, &ports, &d.HTTPTitle, &d.Role); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(names), &d.Names); err != nil {
			d.Names = []string{}
		}
		if err := json.Unmarshal([]byte(ports), &d.Ports); err != nil {
			d.Ports = []model.Port{}
		}
		if d.Names == nil {
			d.Names = []string{}
		}
		if d.Ports == nil {
			d.Ports = []model.Port{}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) dhcpServers(id string) ([]model.DHCPServer, error) {
	rows, err := s.db.Query(`SELECT server_id, source_ip, mac, vendor, offered_ip, hostname, subnet_mask, dns, router
    FROM dhcp_servers WHERE scan_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.DHCPServer{}
	for rows.Next() {
		var d model.DHCPServer
		var dns, router string
		if err := rows.Scan(&d.ServerID, &d.SourceIP, &d.MAC, &d.Vendor, &d.OfferedIP, &d.Hostname, &d.SubnetMask, &dns, &router); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(dns), &d.DNS); err != nil {
			d.DNS = []string{}
		}
		if err := json.Unmarshal([]byte(router), &d.Router); err != nil {
			d.Router = []string{}
		}
		if d.DNS == nil {
			d.DNS = []string{}
		}
		if d.Router == nil {
			d.Router = []string{}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func insertDevices(tx *sql.Tx, id string, devices []model.Device) error {
	for _, d := range devices {
		names, err := json.Marshal(orStrings(d.Names))
		if err != nil {
			return err
		}
		ports, err := json.Marshal(orPorts(d.Ports))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO devices (scan_id, ip, mac, vendor, hostname, names, ports, http_title, role)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, d.IP, d.MAC, d.Vendor, d.Hostname, string(names), string(ports), d.HTTPTitle, d.Role); err != nil {
			return err
		}
	}
	return nil
}

func insertDHCP(tx *sql.Tx, id string, servers []model.DHCPServer) error {
	for _, d := range servers {
		dns, err := json.Marshal(orStrings(d.DNS))
		if err != nil {
			return err
		}
		router, err := json.Marshal(orStrings(d.Router))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO dhcp_servers (
      scan_id, server_id, source_ip, mac, vendor, offered_ip, hostname, subnet_mask, dns, router
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, d.ServerID, d.SourceIP, d.MAC, d.Vendor, d.OfferedIP, d.Hostname, d.SubnetMask, string(dns), string(router)); err != nil {
			return err
		}
	}
	return nil
}

func orStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func orPorts(v []model.Port) []model.Port {
	if v == nil {
		return []model.Port{}
	}
	return v
}

func fmtTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
