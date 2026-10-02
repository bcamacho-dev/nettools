package oui

import (
	"bufio"
	"embed"
	"strconv"
	"strings"
)

//go:embed prefixes.txt
var files embed.FS

var db map[string]string

func init() {
	raw, err := files.ReadFile("prefixes.txt")
	if err != nil {
		db = map[string]string{}
		return
	}
	db = make(map[string]string, 60000)
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		key, name, ok := strings.Cut(sc.Text(), "\t")
		if !ok || key == "" || name == "" {
			continue
		}
		db[strings.ToUpper(key)] = name
	}
}

func Lookup(mac string) string {
	hex := strings.ToUpper(mac)
	hex = strings.NewReplacer(":", "", "-", "", ".", "").Replace(hex)
	if len(hex) < 6 {
		return ""
	}
	first, err := strconv.ParseUint(hex[:2], 16, 8)
	if err != nil {
		return ""
	}
	if first&1 == 1 {
		return "Multicast"
	}
	for _, n := range []int{9, 7, 6} {
		if len(hex) < n {
			continue
		}
		if name, ok := db[hex[:n]]; ok {
			return name
		}
	}
	if first&2 == 2 {
		return "MAC aleatório"
	}
	return ""
}
