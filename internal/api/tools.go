package api

import (
	"encoding/json"
	"net/http"

	"nettools/internal/model"
)

func (s *Server) lan(w http.ResponseWriter, r *http.Request) {
	lan, err := s.engine.LAN()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, lan)
}

func (s *Server) neighbors(w http.ResponseWriter, r *http.Request) {
	items, err := s.engine.Neighbors()
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []model.Neighbor{}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) lookupDNS(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decodeTool(w, r, &body) {
		return
	}
	result, err := s.engine.LookupDNS(r.Context(), body.Name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) reach(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if !decodeTool(w, r, &body) {
		return
	}
	result, err := s.engine.Reach(r.Context(), body.Host, body.Port)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) path(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
		Exit bool   `json:"exit"`
	}
	if !decodeTool(w, r, &body) {
		return
	}
	result, err := s.engine.Path(r.Context(), body.Host, body.Exit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	items, err := s.engine.Services(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []model.Service{}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) wake(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MAC string `json:"mac"`
	}
	if !decodeTool(w, r, &body) {
		return
	}
	result, err := s.engine.Wake(body.MAC)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func decodeTool(w http.ResponseWriter, r *http.Request, dest any) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(dest)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("corpo inválido"))
		return false
	}
	return true
}
