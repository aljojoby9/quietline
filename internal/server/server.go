package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aljojoby9/quietline/internal/protocol"
	"github.com/coder/websocket"
)

type Server struct {
	Store *Store
	mux   *http.ServeMux
	mu    sync.Mutex
	subs  map[string]map[*websocket.Conn]struct{}
}

func New(store *Store) *Server {
	s := &Server{
		Store: store,
		mux:   http.NewServeMux(),
		subs:  map[string]map[*websocket.Conn]struct{}{},
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("POST /v1/register", s.register)
	s.mux.HandleFunc("POST /v1/login", s.login)
	s.mux.HandleFunc("GET /v1/me", s.auth(s.me))
	s.mux.HandleFunc("GET /v1/users/{name}", s.auth(s.user))
	s.mux.HandleFunc("GET /v1/keys/{name}", s.auth(s.keys))
	s.mux.HandleFunc("PUT /v1/keys", s.auth(s.uploadKeys))
	s.mux.HandleFunc("POST /v1/envelopes", s.auth(s.send))
	s.mux.HandleFunc("GET /v1/envelopes", s.auth(s.sync))
	s.mux.HandleFunc("POST /v1/envelopes/ack", s.auth(s.ack))
	s.mux.HandleFunc("POST /v1/groups", s.auth(s.createGroup))
	s.mux.HandleFunc("GET /v1/groups/{id}", s.auth(s.getGroup))
	s.mux.HandleFunc("GET /v1/ws", s.ws)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if err := s.Store.Register(req); err != nil {
		switch {
		case errors.Is(err, ErrTaken):
			writeErr(w, http.StatusConflict, err)
		case errors.Is(err, ErrBadUser):
			writeErr(w, http.StatusBadRequest, err)
		default:
			writeErr(w, http.StatusBadRequest, err)
		}
		return
	}
	log.Printf("registered %s", req.Username)
	writeJSON(w, http.StatusCreated, map[string]string{"username": req.Username})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req protocol.LoginRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	tok, err := s.Store.Login(strings.ToLower(req.Username), req.Password)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, ErrAuth)
		return
	}
	writeJSON(w, http.StatusOK, protocol.LoginResponse{Token: tok, Username: strings.ToLower(req.Username)})
}

type handler func(http.ResponseWriter, *http.Request, *User)

func (s *Server) auth(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.userFromRequest(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, ErrAuth)
			return
		}
		h(w, r, u)
	}
}

func (s *Server) userFromRequest(r *http.Request) (*User, error) {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return s.Store.UserByToken(strings.TrimPrefix(h, "Bearer "))
	}
	if t := r.URL.Query().Get("token"); t != "" {
		return s.Store.UserByToken(t)
	}
	return nil, ErrAuth
}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, u *User) {
	n, _ := s.Store.OTKCount(u.ID)
	sid, _ := s.Store.CurrentSignedID(u.ID)
	writeJSON(w, http.StatusOK, protocol.MeResponse{
		Username:     u.Username,
		IdentityDH:   u.IdentityDH,
		IdentitySign: u.IdentitySign,
		OTKCount:     n,
		SignedID:     sid,
	})
}

func (s *Server) user(w http.ResponseWriter, r *http.Request, _ *User) {
	name := strings.ToLower(r.PathValue("name"))
	u, err := s.Store.UserByName(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, protocol.UserInfo{
		Username:     u.Username,
		IdentityDH:   u.IdentityDH,
		IdentitySign: u.IdentitySign,
	})
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request, _ *User) {
	name := strings.ToLower(r.PathValue("name"))
	b, err := s.Store.FetchBundle(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) uploadKeys(w http.ResponseWriter, r *http.Request, u *User) {
	var req protocol.UploadKeysRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.SignedPreKey != nil {
		if err := s.Store.RotateSigned(u.ID, *req.SignedPreKey); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	if len(req.OneTime) > 0 {
		if err := s.Store.AddOTKs(u.ID, req.OneTime); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (s *Server) send(w http.ResponseWriter, r *http.Request, u *User) {
	var req protocol.SendRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Body) == 0 || len(req.Body) > 256*1024 {
		writeErr(w, http.StatusBadRequest, errors.New("ciphertext size"))
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var recips []string
	switch {
	case req.GroupID != "":
		ok, err := s.Store.IsMember(req.GroupID, u.Username)
		if err != nil || !ok {
			writeErr(w, http.StatusForbidden, ErrNotMember)
			return
		}
		g, err := s.Store.Group(req.GroupID)
		if err != nil {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		for _, m := range g.Members {
			if m != u.Username {
				recips = append(recips, m)
			}
		}
		if req.Kind == "" {
			req.Kind = protocol.KindGroup
		}
	case req.Recipient != "":
		recips = []string{strings.ToLower(req.Recipient)}
		if _, err := s.Store.UserByName(recips[0]); err != nil {
			writeErr(w, http.StatusNotFound, ErrNotFound)
			return
		}
		if req.Kind == "" {
			req.Kind = protocol.KindMessage
		}
	default:
		writeErr(w, http.StatusBadRequest, errors.New("recipient or group_id required"))
		return
	}
	var ids []string
	for _, recip := range recips {
		id, err := newID()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		env := protocol.Envelope{
			ID:        id,
			Sender:    u.Username,
			Recipient: recip,
			DeviceID:  1,
			Kind:      req.Kind,
			GroupID:   req.GroupID,
			Body:      req.Body,
			CreatedAt: now,
		}
		if err := s.Store.PutEnvelope(env); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		ids = append(ids, id)
		s.push(recip, env)
	}
	log.Printf("envelope %s -> %v kind=%s bytes=%d", u.Username, recips, req.Kind, len(req.Body))
	writeJSON(w, http.StatusAccepted, protocol.SendResponse{IDs: ids})
}

func (s *Server) sync(w http.ResponseWriter, _ *http.Request, u *User) {
	envs, err := s.Store.Inbox(u.Username, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if envs == nil {
		envs = []protocol.Envelope{}
	}
	writeJSON(w, http.StatusOK, protocol.SyncResponse{Envelopes: envs})
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request, u *User) {
	var req protocol.AckRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Store.Ack(u.Username, req.IDs); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request, u *User) {
	var req protocol.CreateGroupRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	id, err := newID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	members := make([]string, 0, len(req.Members))
	for _, m := range req.Members {
		members = append(members, strings.ToLower(m))
	}
	if err := s.Store.CreateGroup(id, req.Name, u.Username, members); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	g, err := s.Store.Group(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	ok, err := s.Store.IsMember(id, u.Username)
	if err != nil || !ok {
		writeErr(w, http.StatusNotFound, ErrNotFound)
		return
	}
	g, err := s.Store.Group(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) ws(w http.ResponseWriter, r *http.Request) {
	u, err := s.userFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, ErrAuth)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	s.addSub(u.Username, c)
	defer func() {
		s.removeSub(u.Username, c)
		c.Close(websocket.StatusNormalClosure, "")
	}()
	ctx := r.Context()
	// Flush queued envelopes on connect.
	envs, _ := s.Store.Inbox(u.Username, 200)
	for _, e := range envs {
		env := e
		_ = writeWS(ctx, c, protocol.WSMessage{Op: "envelope", Envelope: &env})
	}
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		var msg protocol.WSMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.Op == "ack" {
			_ = s.Store.Ack(u.Username, msg.IDs)
		}
		if msg.Op == "ping" {
			_ = writeWS(ctx, c, protocol.WSMessage{Op: "pong"})
		}
	}
}

func (s *Server) addSub(user string, c *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subs[user] == nil {
		s.subs[user] = map[*websocket.Conn]struct{}{}
	}
	s.subs[user][c] = struct{}{}
}

func (s *Server) removeSub(user string, c *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs[user], c)
}

func (s *Server) push(user string, e protocol.Envelope) {
	s.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(s.subs[user]))
	for c := range s.subs[user] {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, c := range conns {
		_ = writeWS(ctx, c, protocol.WSMessage{Op: "envelope", Envelope: &e})
	}
}

func writeWS(ctx context.Context, c *websocket.Conn, msg protocol.WSMessage) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, b)
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, protocol.ErrorResponse{Error: err.Error()})
}
