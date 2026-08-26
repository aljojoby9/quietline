package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aljojoby9/quietline/internal/protocol"
	"github.com/coder/websocket"
)

type Transport struct {
	Base   string
	Token  string
	Client *http.Client
}

func NewTransport(base string) *Transport {
	return &Transport{
		Base: strings.TrimRight(base, "/"),
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (t *Transport) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.Base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	resp, err := t.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var er protocol.ErrorResponse
		_ = json.Unmarshal(data, &er)
		if er.Error != "" {
			return fmt.Errorf("http %d: %s", resp.StatusCode, er.Error)
		}
		return fmt.Errorf("http %d: %s", resp.StatusCode, bytes.TrimSpace(data))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (t *Transport) Register(ctx context.Context, req protocol.RegisterRequest) error {
	return t.do(ctx, http.MethodPost, "/v1/register", req, nil)
}

func (t *Transport) Login(ctx context.Context, user, pass string) (protocol.LoginResponse, error) {
	var out protocol.LoginResponse
	err := t.do(ctx, http.MethodPost, "/v1/login", protocol.LoginRequest{Username: user, Password: pass}, &out)
	if err == nil {
		t.Token = out.Token
	}
	return out, err
}

func (t *Transport) Me(ctx context.Context) (protocol.MeResponse, error) {
	var out protocol.MeResponse
	err := t.do(ctx, http.MethodGet, "/v1/me", nil, &out)
	return out, err
}

func (t *Transport) User(ctx context.Context, name string) (protocol.UserInfo, error) {
	var out protocol.UserInfo
	err := t.do(ctx, http.MethodGet, "/v1/users/"+url.PathEscape(name), nil, &out)
	return out, err
}

func (t *Transport) FetchBundle(ctx context.Context, name string) (protocol.PreKeyBundle, error) {
	var out protocol.PreKeyBundle
	err := t.do(ctx, http.MethodGet, "/v1/keys/"+url.PathEscape(name), nil, &out)
	return out, err
}

func (t *Transport) UploadKeys(ctx context.Context, req protocol.UploadKeysRequest) error {
	return t.do(ctx, http.MethodPut, "/v1/keys", req, nil)
}

func (t *Transport) Send(ctx context.Context, req protocol.SendRequest) (protocol.SendResponse, error) {
	var out protocol.SendResponse
	err := t.do(ctx, http.MethodPost, "/v1/envelopes", req, &out)
	return out, err
}

func (t *Transport) Sync(ctx context.Context) (protocol.SyncResponse, error) {
	var out protocol.SyncResponse
	err := t.do(ctx, http.MethodGet, "/v1/envelopes", nil, &out)
	return out, err
}

func (t *Transport) Ack(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return t.do(ctx, http.MethodPost, "/v1/envelopes/ack", protocol.AckRequest{IDs: ids}, nil)
}

func (t *Transport) CreateGroup(ctx context.Context, name string, members []string) (protocol.GroupInfo, error) {
	var out protocol.GroupInfo
	err := t.do(ctx, http.MethodPost, "/v1/groups", protocol.CreateGroupRequest{Name: name, Members: members}, &out)
	return out, err
}

func (t *Transport) GetGroup(ctx context.Context, id string) (protocol.GroupInfo, error) {
	var out protocol.GroupInfo
	err := t.do(ctx, http.MethodGet, "/v1/groups/"+url.PathEscape(id), nil, &out)
	return out, err
}

func (t *Transport) DialWS(ctx context.Context) (*websocket.Conn, error) {
	u := t.Base
	switch {
	case strings.HasPrefix(u, "https://"):
		u = "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		u = "ws://" + strings.TrimPrefix(u, "http://")
	}
	u = strings.TrimRight(u, "/") + "/v1/ws?token=" + url.QueryEscape(t.Token)
	c, _, err := websocket.Dial(ctx, u, nil)
	return c, err
}
