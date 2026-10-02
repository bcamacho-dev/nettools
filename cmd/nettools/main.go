package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"nettools/internal/api"
	"nettools/internal/engine"
	"nettools/internal/store"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("nettools", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "endereço HTTP")
	tokenFlag := fs.String("token", os.Getenv("NETTOOLS_TOKEN"), "token da API; vazio lê ou cria nettools.token")
	iface := fs.String("iface", "", "interface de rede; vazio usa a da rota padrão")
	cidr := fs.String("cidr", "", "bloco IPv4 a varrer, dentro da rede da interface")
	dbPath := fs.String("db", "nettools.db", "arquivo SQLite")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Uso: nettools serve [opções]\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nNo Linux, ARP e DHCP pedem root ou: sudo setcap cap_net_raw+ep nettools\n")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}

	token, generated, err := loadToken(*tokenFlag, *dbPath)
	if err != nil {
		slog.Error("token", "err", err)
		os.Exit(1)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		slog.Error("banco", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	eng := engine.New(st, *iface, *cidr)
	if info, err := eng.Network(); err != nil {
		slog.Warn("rede ainda não detectada", "err", err)
	} else {
		slog.Info("rede", "iface", info.Interface, "ip", info.IP, "subnet", info.Subnet, "gateway", info.Gateway, "hosts", info.Hosts)
		if !info.Scannable && info.ScanError != "" {
			slog.Warn("varredura", "err", info.ScanError)
		}
	}

	srv := api.New(token, eng).HTTPServer(*listen)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	printURL(*listen)
	if generated {
		fmt.Printf("Token novo, gravado ao lado do banco: %s\n", tokenPath(*dbPath))
		fmt.Printf("Token: %s\n", token)
	}
	fmt.Println("ARP e DHCP examinam a rede desta máquina. No Linux isso pede cap_net_raw ou root.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http", "err", err)
			os.Exit(1)
		}
	case <-sig:
		_ = srv.Close()
	}
}

func loadToken(flagValue, dbPath string) (string, bool, error) {
	if strings.TrimSpace(flagValue) != "" {
		return strings.TrimSpace(flagValue), false, nil
	}
	path := tokenPath(dbPath)
	if b, err := os.ReadFile(path); err == nil {
		token := strings.TrimSpace(string(b))
		if token != "" {
			return token, false, nil
		}
	}
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", false, err
	}
	token := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", false, err
	}
	return token, true, nil
}

func tokenPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "nettools.token")
}

func printURL(listen string) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		fmt.Println("Escutando em", listen)
		return
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		fmt.Printf("Escutando em http://127.0.0.1:%s (todas as interfaces, porta %s)\n", port, port)
		return
	}
	fmt.Printf("Escutando em http://%s\n", net.JoinHostPort(host, port))
}
