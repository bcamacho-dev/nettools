package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	version := flag.String("version", "0.1.0", "versão do pacote")
	arch := flag.String("arch", "amd64", "arquitetura Debian")
	binary := flag.String("binary", "", "binário Linux do nettools")
	root := flag.String("root", "", "raiz do repositório; vazio usa o diretório acima de packaging")
	out := flag.String("out", "", "caminho do .deb")
	flag.Parse()
	if *binary == "" {
		fmt.Fprintln(os.Stderr, "informe -binary")
		os.Exit(2)
	}
	repo := *root
	if repo == "" {
		wd, err := os.Getwd()
		if err != nil {
			exit(err)
		}
		repo = wd
	}
	debPath := *out
	if debPath == "" {
		debPath = filepath.Join(repo, "dist", fmt.Sprintf("nettools_%s_%s.deb", *version, *arch))
	}
	bin, err := os.ReadFile(*binary)
	if err != nil {
		exit(err)
	}
	if len(bin) < 4 || bin[0] != 0x7f || string(bin[1:4]) != "ELF" {
		exit(fmt.Errorf("%s não é um binário Linux ELF", *binary))
	}
	pack := filepath.Join(repo, "packaging", "debian")
	runScript, err := readUnix(filepath.Join(pack, "run"))
	if err != nil {
		exit(err)
	}
	service, err := readUnix(filepath.Join(pack, "nettools.service"))
	if err != nil {
		exit(err)
	}
	defaults, err := readUnix(filepath.Join(pack, "nettools.default"))
	if err != nil {
		exit(err)
	}
	postinst, err := readUnix(filepath.Join(pack, "postinst"))
	if err != nil {
		exit(err)
	}
	prerm, err := readUnix(filepath.Join(pack, "prerm"))
	if err != nil {
		exit(err)
	}
	postrm, err := readUnix(filepath.Join(pack, "postrm"))
	if err != nil {
		exit(err)
	}

	data, err := tarGz([]item{
		{name: "usr/bin/nettools", mode: 0755, body: bin},
		{name: "usr/lib/nettools/run", mode: 0755, body: runScript},
		{name: "lib/systemd/system/nettools.service", mode: 0644, body: service},
		{name: "etc/default/nettools", mode: 0644, body: defaults},
	})
	if err != nil {
		exit(err)
	}
	installed := (len(bin) + len(runScript) + len(service) + len(defaults) + 1023) / 1024
	controlText := fmt.Sprintf(`Package: nettools
Version: %s
Section: net
Priority: optional
Architecture: %s
Maintainer: Bernardo G Camacho <bernardo.camacho@gmail.com>
Depends: adduser, systemd
Installed-Size: %d
Description: exames de rede local
 Servidor para DHCP, varredura de dispositivos, velocidade, estabilidade
 e o mapa da LAN. O token da primeira execução fica no journal.
`, *version, *arch, installed)
	control, err := tarGz([]item{
		{name: "control", mode: 0644, body: []byte(controlText)},
		{name: "postinst", mode: 0755, body: postinst},
		{name: "prerm", mode: 0755, body: prerm},
		{name: "postrm", mode: 0755, body: postrm},
		{name: "conffiles", mode: 0644, body: []byte("/etc/default/nettools\n")},
	})
	if err != nil {
		exit(err)
	}
	deb := buildDeb(control, data)
	if err := os.MkdirAll(filepath.Dir(debPath), 0755); err != nil {
		exit(err)
	}
	if err := os.WriteFile(debPath, deb, 0644); err != nil {
		exit(err)
	}
	fmt.Println(debPath)
}

type item struct {
	name string
	mode int64
	body []byte
}

func readUnix(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []byte(strings.ReplaceAll(string(b), "\r\n", "\n")), nil
}

func tarGz(files []item) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	for _, name := range parentDirs(files) {
		hdr := &tar.Header{
			Name:     name + "/",
			Mode:     0755,
			Typeflag: tar.TypeDir,
			ModTime:  time.Unix(0, 0),
			Format:   tar.FormatGNU,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
	}
	for _, file := range files {
		hdr := &tar.Header{
			Name:     file.name,
			Mode:     file.mode,
			Size:     int64(len(file.body)),
			Typeflag: tar.TypeReg,
			ModTime:  time.Unix(0, 0),
			Format:   tar.FormatGNU,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(file.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parentDirs(files []item) []string {
	seen := map[string]struct{}{}
	for _, file := range files {
		name := path.Dir(strings.TrimSuffix(file.name, "/"))
		for name != "." && name != "/" && name != "" {
			seen[name] = struct{}{}
			name = path.Dir(name)
		}
	}
	dirs := make([]string, 0, len(seen))
	for name := range seen {
		dirs = append(dirs, name)
	}
	sort.Strings(dirs)
	return dirs
}

func buildDeb(control, data []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	writeAr(&buf, "debian-binary", []byte("2.0\n"))
	writeAr(&buf, "control.tar.gz", control)
	writeAr(&buf, "data.tar.gz", data)
	return buf.Bytes()
}

func writeAr(buf *bytes.Buffer, name string, body []byte) {
	name += "/"
	if len(name) > 16 {
		panic(name)
	}
	name += strings.Repeat(" ", 16-len(name))
	hdr := fmt.Sprintf("%s%-12d%-6d%-6d%-8o%-10d`\n", name, 0, 0, 0, 0100644, len(body))
	if len(hdr) != 60 {
		panic(len(hdr))
	}
	buf.WriteString(hdr)
	buf.Write(body)
	if len(body)%2 == 1 {
		buf.WriteByte('\n')
	}
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
