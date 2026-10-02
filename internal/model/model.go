package model

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Network struct {
	Interface string `json:"interface"`
	MAC       string `json:"mac,omitempty"`
	IP        string `json:"ip"`
	Subnet    string `json:"subnet"`
	Gateway   string `json:"gateway,omitempty"`
	Hosts     int    `json:"hosts"`
	OS        string `json:"os"`
	Scannable bool   `json:"scannable"`
	ScanError string `json:"scan_error,omitempty"`
}

type Port struct {
	Port  int    `json:"port"`
	Label string `json:"label"`
}

type Device struct {
	IP        string   `json:"ip"`
	MAC       string   `json:"mac,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	Names     []string `json:"names"`
	Ports     []Port   `json:"ports"`
	HTTPTitle string   `json:"http_title,omitempty"`
	Role      string   `json:"role,omitempty"`
}

type DHCPServer struct {
	ServerID   string   `json:"server_id"`
	SourceIP   string   `json:"source_ip,omitempty"`
	MAC        string   `json:"mac,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	OfferedIP  string   `json:"offered_ip,omitempty"`
	Hostname   string   `json:"hostname,omitempty"`
	SubnetMask string   `json:"subnet_mask,omitempty"`
	DNS        []string `json:"dns"`
	Router     []string `json:"router"`
}

type Scan struct {
	ID        string       `json:"id"`
	Kind      string       `json:"kind"`
	Status    string       `json:"status"`
	Detail    string       `json:"detail,omitempty"`
	Error     string       `json:"error,omitempty"`
	DHCPError string       `json:"dhcp_error,omitempty"`
	Started   time.Time    `json:"started"`
	Finished  *time.Time   `json:"finished,omitempty"`
	Network   Network      `json:"network"`
	Devices   []Device     `json:"devices"`
	DHCP      []DHCPServer `json:"dhcp"`
}

type Stability struct {
	Target   string    `json:"target"`
	At       time.Time `json:"at"`
	Sent     int       `json:"sent"`
	Recv     int       `json:"recv"`
	Loss     float64   `json:"loss"`
	MinMS    float64   `json:"min_ms"`
	AvgMS    float64   `json:"avg_ms"`
	MaxMS    float64   `json:"max_ms"`
	JitterMS float64   `json:"jitter_ms"`
}

type Speed struct {
	ID        string    `json:"id"`
	At        time.Time `json:"at"`
	DownMbps  float64   `json:"down_mbps"`
	UpMbps    float64   `json:"up_mbps"`
	HTTPRTTMS float64   `json:"http_rtt_ms"`
}

func Clip(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) <= 160 {
		return s
	}
	s = s[:160]
	for s != "" && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func EmptyScan() Scan {
	return Scan{
		Devices: []Device{},
		DHCP:    []DHCPServer{},
	}
}

type LAN struct {
	Network
	Hostname   string   `json:"hostname"`
	DNS        []string `json:"dns"`
	MTU        int      `json:"mtu"`
	Up         bool     `json:"up"`
	IPv6       []string `json:"ipv6"`
	Broadcast  string   `json:"broadcast,omitempty"`
	LinkMbps   int      `json:"link_mbps,omitempty"`
	DHCPServer string   `json:"dhcp_server,omitempty"`
	Origin     string   `json:"origin,omitempty"`
	Duplicate  bool     `json:"duplicate"`
}

type DNSAnswer struct {
	Server string   `json:"server"`
	Values []string `json:"values"`
	MS     float64  `json:"ms"`
	Error  string   `json:"error,omitempty"`
}

type DNSResult struct {
	Name    string      `json:"name"`
	Kind    string      `json:"kind"`
	Answers []DNSAnswer `json:"answers"`
}

type PortProbe struct {
	Port  int     `json:"port"`
	Label string  `json:"label"`
	Open  bool    `json:"open"`
	MS    float64 `json:"ms"`
	Error string  `json:"error,omitempty"`
}

type ReachResult struct {
	Host  string      `json:"host"`
	IP    string      `json:"ip"`
	Ports []PortProbe `json:"ports"`
}

type Hop struct {
	TTL     int     `json:"ttl"`
	IP      string  `json:"ip,omitempty"`
	MS      float64 `json:"ms"`
	Timeout bool    `json:"timeout"`
}

type PathResult struct {
	Target string `json:"target"`
	Hops   []Hop  `json:"hops"`
}

type Service struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Host string `json:"host,omitempty"`
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

type Neighbor struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type WakeResult struct {
	MAC       string `json:"mac"`
	Broadcast string `json:"broadcast,omitempty"`
}

type MapNode struct {
	ID     string  `json:"id"`
	Kind   string  `json:"kind"`
	Label  string  `json:"label"`
	Detail string  `json:"detail"`
	Badge  string  `json:"badge,omitempty"`
	IP     string  `json:"ip"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	W      float64 `json:"w"`
	H      float64 `json:"h"`
}

type MapLine struct {
	X1 float64 `json:"x1"`
	Y1 float64 `json:"y1"`
	X2 float64 `json:"x2"`
	Y2 float64 `json:"y2"`
}

type NetMap struct {
	Width  float64   `json:"width"`
	Height float64   `json:"height"`
	Subnet string    `json:"subnet,omitempty"`
	Nodes  []MapNode `json:"nodes"`
	Lines  []MapLine `json:"lines"`
	Note   string    `json:"note"`
}
