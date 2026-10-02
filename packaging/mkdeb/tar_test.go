package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

func TestTarIncludesParentDirectories(t *testing.T) {
	raw, err := tarGz([]item{
		{name: "usr/bin/nettools", mode: 0755, body: []byte("bin")},
		{name: "usr/lib/nettools/run", mode: 0755, body: []byte("#!/bin/sh\n")},
		{name: "lib/systemd/system/nettools.service", mode: 0644, body: []byte("[Unit]\n")},
		{name: "etc/default/nettools", mode: 0644, body: []byte("A=1\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	dirs := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if hdr.Typeflag == tar.TypeDir {
			dirs[hdr.Name] = true
		}
	}
	for _, dir := range []string{
		"usr/",
		"usr/bin/",
		"usr/lib/",
		"usr/lib/nettools/",
		"lib/",
		"lib/systemd/",
		"lib/systemd/system/",
		"etc/",
		"etc/default/",
	} {
		if !dirs[dir] {
			t.Errorf("falta o diretório %s em %v", dir, names)
		}
	}
	runAt := indexOf(names, "usr/lib/nettools/run")
	dirAt := indexOf(names, "usr/lib/nettools/")
	if runAt < 0 || dirAt < 0 || dirAt > runAt {
		t.Fatalf("o diretório precisa vir antes do arquivo: %v", names)
	}
}

func indexOf(list []string, want string) int {
	for i, name := range list {
		if name == want {
			return i
		}
	}
	return -1
}
