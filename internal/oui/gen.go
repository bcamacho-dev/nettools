//go:build ignore

// Gera prefixes.txt a partir do manuf do Wireshark:
//
//	https://www.wireshark.org/download/automated/data/manuf
//
// go run internal/oui/gen.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	in, err := os.Open("internal/oui/manuf")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer in.Close()

	out, err := os.Create("internal/oui/prefixes.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer out.Close()

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	w := bufio.NewWriter(out)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		spec := strings.TrimSpace(fields[0])
		name := strings.TrimSpace(fields[len(fields)-1])
		if name == "" || name == "Private" || spec == "" {
			continue
		}
		key, ok := prefixKey(spec)
		if !ok {
			continue
		}
		fmt.Fprintf(w, "%s\t%s\n", key, name)
		n++
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("prefixes", n)
}

func prefixKey(spec string) (string, bool) {
	bits := 24
	mac := spec
	if i := strings.IndexByte(spec, '/'); i >= 0 {
		mac = spec[:i]
		n, err := strconv.Atoi(spec[i+1:])
		if err != nil {
			return "", false
		}
		bits = n
	}
	switch bits {
	case 24, 28, 36:
	default:
		return "", false
	}
	hex := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	nibbles := bits / 4
	if len(hex) < nibbles {
		return "", false
	}
	return hex[:nibbles], true
}
