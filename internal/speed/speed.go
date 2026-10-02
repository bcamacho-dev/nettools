package speed

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

var noise = make([]byte, 64<<10)

func init() {
	if _, err := rand.Read(noise); err != nil {
		for i := range noise {
			noise[i] = byte(i)
		}
	}
}

func Register(mux *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /speed/download", auth(download))
	mux.HandleFunc("POST /speed/upload", auth(upload))
	mux.HandleFunc("GET /speed/empty", auth(empty))
}

func download(w http.ResponseWriter, r *http.Request) {
	n := 4 << 20
	if q := r.URL.Query().Get("bytes"); q != "" {
		v, err := strconv.Atoi(q)
		if err != nil || v < 1 {
			http.Error(w, "bytes inválido", http.StatusBadRequest)
			return
		}
		if v > 8<<20 {
			v = 8 << 20
		}
		n = v
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Encoding", "identity")
	flusher, _ := w.(http.Flusher)
	written := 0
	for written < n {
		chunk := noise
		if remain := n - written; remain < len(chunk) {
			chunk = chunk[:remain]
		}
		nw, err := w.Write(chunk)
		written += nw
		if flusher != nil {
			flusher.Flush()
		}
		if err != nil {
			return
		}
	}
}

func upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		http.Error(w, "envio grande demais", http.StatusRequestEntityTooLarge)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]int64{"bytes": n})
}

func empty(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
