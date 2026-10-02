package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nettools/internal/engine"
	"nettools/internal/model"
	"nettools/internal/netinfo"
	"nettools/internal/speed"
	"nettools/internal/store"
	"nettools/web"
)

type Server struct {
	token  string
	engine *engine.Engine
}

func New(token string, eng *engine.Engine) *Server {
	return &Server{token: token, engine: eng}
}

func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("POST /api/v1/session", s.session)
	mux.HandleFunc("GET /api/v1/network", s.auth(s.network))
	mux.HandleFunc("POST /api/v1/scans", s.auth(s.startScan))
	mux.HandleFunc("GET /api/v1/scans/latest", s.auth(s.latestScan))
	mux.HandleFunc("GET /api/v1/scans/{id}", s.auth(s.getScan))
	mux.HandleFunc("POST /api/v1/dhcp", s.auth(s.dhcp))
	mux.HandleFunc("POST /api/v1/stability", s.auth(s.stability))
	mux.HandleFunc("GET /api/v1/stability/latest", s.auth(s.latestStability))
	mux.HandleFunc("POST /api/v1/speed", s.auth(s.saveSpeed))
	mux.HandleFunc("GET /api/v1/speed/latest", s.auth(s.latestSpeed))
	mux.HandleFunc("GET /api/v1/lan", s.auth(s.lan))
	mux.HandleFunc("GET /api/v1/neighbors", s.auth(s.neighbors))
	mux.HandleFunc("POST /api/v1/tools/dns", s.auth(s.lookupDNS))
	mux.HandleFunc("POST /api/v1/tools/reach", s.auth(s.reach))
	mux.HandleFunc("POST /api/v1/tools/path", s.auth(s.path))
	mux.HandleFunc("POST /api/v1/tools/services", s.auth(s.services))
	mux.HandleFunc("POST /api/v1/tools/wol", s.auth(s.wake))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	speed.Register(mux, s.auth)
	mux.Handle("/", noCache(http.FileServer(http.FS(web.Files))))
	return s.log(mux)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("token ausente"))
		return
	}
	if !subtleMatch(body.Token, s.token) {
		writeJSON(w, http.StatusUnauthorized, errBody("token não confere"))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "nettools_token",
		Value:    s.token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) network(w http.ResponseWriter, r *http.Request) {
	netw, err := s.engine.Network()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, netw)
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	sc, err := s.engine.StartDiscover()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, sc)
}

func (s *Server) latestScan(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "discover"
	}
	sc, err := s.engine.LatestScan(kind)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	sc, err := s.engine.Scan(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) dhcp(w http.ResponseWriter, r *http.Request) {
	sc, err := s.engine.DHCP(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) stability(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
		Count  int    `json:"count"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, http.ErrBodyReadAfterClose) {
		if r.ContentLength > 0 {
			writeJSON(w, http.StatusBadRequest, errBody("corpo inválido"))
			return
		}
	}
	st, err := s.engine.Stability(r.Context(), strings.TrimSpace(body.Target), body.Count)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) latestStability(w http.ResponseWriter, r *http.Request) {
	st, err := s.engine.LatestStability()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) saveSpeed(w http.ResponseWriter, r *http.Request) {
	var sp model.Speed
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&sp); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("medição inválida"))
		return
	}
	saved, err := s.engine.SaveSpeed(sp)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) latestSpeed(w http.ResponseWriter, r *http.Request) {
	sp, err := s.engine.LatestSpeed()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sp)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !subtleMatch(tokenFrom(r), s.token) {
			writeJSON(w, http.StatusUnauthorized, errBody("token ausente ou inválido"))
			return
		}
		next(w, r)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, engine.ErrBusy):
		writeJSON(w, http.StatusConflict, errBody(err.Error()))
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody(err.Error()))
	default:
		var rejected *netinfo.Rejected
		if errors.As(err, &rejected) {
			writeJSON(w, http.StatusBadRequest, errBody(rejected.Error()))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
	}
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(sw, r)
		if strings.HasPrefix(r.URL.Path, "/speed/") || r.URL.Path == "/favicon.ico" {
			return
		}
		if sw.code == 0 {
			sw.code = http.StatusOK
		}
		slog.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.code, "ms", time.Since(start).Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func tokenFrom(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	if c, err := r.Cookie("nettools_token"); err == nil {
		return c.Value
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}

func subtleMatch(got, want string) bool {
	if want == "" || len(got) != len(want) {
		return false
	}
	var diff byte
	for i := 0; i < len(want); i++ {
		diff |= got[i] ^ want[i]
	}
	return diff == 0
}
