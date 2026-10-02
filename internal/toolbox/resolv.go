package toolbox

import "strings"

func dnsFromResolv(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		out = addUnique(out, fields[1])
		if len(out) == 8 {
			break
		}
	}
	return out
}
