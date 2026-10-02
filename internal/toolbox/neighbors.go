package toolbox

import (
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"nettools/internal/model"
	"nettools/internal/oui"
)

func decorate(items []model.Neighbor) []model.Neighbor {
	if items == nil {
		items = []model.Neighbor{}
	}
	out := make([]model.Neighbor, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item.MAC = normalizeMAC(item.MAC)
		if item.IP == "" || item.MAC == "" || item.MAC == "00:00:00:00:00:00" {
			continue
		}
		hw, err := net.ParseMAC(item.MAC)
		if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
			continue
		}
		key := item.IP + "|" + item.MAC
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		item.Vendor = oui.Lookup(item.MAC)
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		a, ea := netip.ParseAddr(out[i].IP)
		b, eb := netip.ParseAddr(out[j].IP)
		if ea == nil && eb == nil {
			return a.Less(b)
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", ":")
	return s
}

var (
	winIface = regexp.MustCompile(`:\s*(\d+\.\d+\.\d+\.\d+)\s+---`)
	winEntry = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})`)
)

func parseWindowsARP(text string) []model.Neighbor {
	iface := ""
	var out []model.Neighbor
	for _, line := range strings.Split(text, "\n") {
		if m := winIface.FindStringSubmatch(line); len(m) == 2 {
			iface = m[1]
			continue
		}
		m := winEntry.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		out = append(out, model.Neighbor{IP: m[1], MAC: m[2], Interface: iface})
	}
	return decorate(out)
}

func parseLinuxARP(text string) []model.Neighbor {
	var out []model.Neighbor
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] == "IP" {
			continue
		}
		if fields[2] == "0x0" {
			continue
		}
		out = append(out, model.Neighbor{IP: fields[0], MAC: fields[3], Interface: fields[5]})
	}
	return decorate(out)
}
