package client

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	qlcrypto "github.com/aljojoby9/quietline/internal/crypto"
	"github.com/aljojoby9/quietline/internal/protocol"
	"github.com/coder/websocket"
)

type Client struct {
	mu       sync.Mutex
	home     string
	path     string
	server   string
	username string
	tr       *Transport
	id       *qlcrypto.Identity
	spks     map[uint32]*qlcrypto.PreKey
	otks     map[uint32]*qlcrypto.PreKey
	nextSPK  uint32
	nextOTK  uint32
	sessions map[string]*qlcrypto.State
	peers    map[string]qlcrypto.PublicIdentity
	groups   map[string]*liveGroup
	seen     []string
	seenSet  map[string]bool
	log      []LogEntry
}

type liveGroup struct {
	Name    string
	Members []string
	Sender  *qlcrypto.SenderKey
	Chains  map[string]*qlcrypto.ReceiveChain
}

type Message struct {
	EnvelopeID string
	From       string
	GroupID    string
	Kind       string
	Body       string
	ID         string
	Ref        string
}

func newClient(home, server string) *Client {
	return &Client{
		home:     home,
		path:     accountPath(home),
		server:   strings.TrimRight(server, "/"),
		tr:       NewTransport(server),
		spks:     map[uint32]*qlcrypto.PreKey{},
		otks:     map[uint32]*qlcrypto.PreKey{},
		sessions: map[string]*qlcrypto.State{},
		peers:    map[string]qlcrypto.PublicIdentity{},
		groups:   map[string]*liveGroup{},
		seenSet:  map[string]bool{},
	}
}

func Load(home string) (*Client, error) {
	d, err := loadDisk(accountPath(home))
	if err != nil {
		return nil, err
	}
	return clientFromDisk(home, d)
}

func Register(ctx context.Context, home, server, user, pass string) (*Client, error) {
	user = strings.ToLower(strings.TrimSpace(user))
	if _, err := os.Stat(accountPath(home)); err == nil {
		return nil, fmt.Errorf("account already exists in %s; use login or a new --home", home)
	}
	seed, err := qlcrypto.GenerateSeed()
	if err != nil {
		return nil, err
	}
	id, err := qlcrypto.DeriveIdentity(seed)
	if err != nil {
		return nil, err
	}
	c := newClient(home, server)
	c.id = id
	c.username = user
	c.nextSPK = 2
	c.nextOTK = 1
	spk, err := qlcrypto.NewSignedPreKey(id, 1)
	if err != nil {
		return nil, err
	}
	c.spks[spk.ID] = spk
	otkPubs := make([]protocol.PublicPreKey, 0, 40)
	for i := 0; i < 40; i++ {
		k, err := qlcrypto.NewOneTimePreKey(c.nextOTK)
		if err != nil {
			return nil, err
		}
		c.nextOTK++
		c.otks[k.ID] = k
		otkPubs = append(otkPubs, protocol.PublicPreKey{ID: k.ID, Public: k.Public})
	}
	pub := id.Public()
	req := protocol.RegisterRequest{
		Username:     user,
		Password:     pass,
		IdentityDH:   pub.DH,
		IdentitySign: pub.Sign,
		SignedPreKey: protocol.PublicPreKey{ID: spk.ID, Public: spk.Public, Signature: spk.Signature},
		OneTime:      otkPubs,
	}
	if err := c.tr.Register(ctx, req); err != nil {
		return nil, err
	}
	if _, err := c.tr.Login(ctx, user, pass); err != nil {
		return nil, err
	}
	if err := c.saveLocked(); err != nil {
		return nil, err
	}
	return c, nil
}

func Login(ctx context.Context, home, server, user, pass string) (*Client, error) {
	c, err := Load(home)
	if err != nil {
		return nil, fmt.Errorf("no local identity (register on this device first): %w", err)
	}
	if user != "" && c.username != strings.ToLower(user) {
		return nil, fmt.Errorf("local account is %s, not %s", c.username, user)
	}
	if server != "" {
		c.server = strings.TrimRight(server, "/")
		c.tr.Base = c.server
	}
	if _, err := c.tr.Login(ctx, c.username, pass); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c, c.saveLocked()
}

func (c *Client) Username() string { return c.username }
func (c *Client) Home() string     { return c.home }
func (c *Client) Server() string   { return c.server }

func (c *Client) PublicIdentity() qlcrypto.PublicIdentity {
	return c.id.Public()
}

func (c *Client) Me(ctx context.Context) (protocol.MeResponse, error) {
	return c.tr.Me(ctx)
}

func (c *Client) Log() []LogEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]LogEntry, len(c.log))
	copy(out, c.log)
	return out
}

func (c *Client) Groups() map[string]liveGroup {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]liveGroup{}
	for id, g := range c.groups {
		cp := *g
		cp.Members = append([]string(nil), g.Members...)
		out[id] = cp
	}
	return out
}

func (c *Client) Safety(ctx context.Context, name string) (string, error) {
	name = strings.ToLower(name)
	c.mu.Lock()
	peer, ok := c.peers[name]
	c.mu.Unlock()
	if !ok {
		u, err := c.tr.User(ctx, name)
		if err != nil {
			return "", err
		}
		peer = qlcrypto.PublicIdentity{
			DH:   u.IdentityDH,
			Sign: ed25519.PublicKey(append([]byte(nil), u.IdentitySign...)),
		}
		c.mu.Lock()
		c.peers[name] = peer
		_ = c.saveLocked()
		c.mu.Unlock()
	}
	return qlcrypto.SafetyNumber(c.id.Public(), peer, c.username, name), nil
}

func (c *Client) Refill(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refillLocked(ctx)
}

func (c *Client) refillLocked(ctx context.Context) error {
	me, err := c.tr.Me(ctx)
	if err != nil {
		return err
	}
	if me.OTKCount >= 20 {
		return nil
	}
	n := 40
	pubs := make([]protocol.PublicPreKey, 0, n)
	for i := 0; i < n; i++ {
		k, err := qlcrypto.NewOneTimePreKey(c.nextOTK)
		if err != nil {
			return err
		}
		c.nextOTK++
		c.otks[k.ID] = k
		pubs = append(pubs, protocol.PublicPreKey{ID: k.ID, Public: k.Public})
	}
	if err := c.tr.UploadKeys(ctx, protocol.UploadKeysRequest{OneTime: pubs}); err != nil {
		return err
	}
	return c.saveLocked()
}

func (c *Client) Send(ctx context.Context, to, text string) error {
	to = strings.ToLower(to)
	c.mu.Lock()
	defer c.mu.Unlock()
	p := qlcrypto.NewText(newID(), text)
	if err := c.sendPayloadLocked(ctx, to, p); err != nil {
		return err
	}
	c.appendLog(LogEntry{TS: p.TS, From: c.username, To: to, Kind: p.Kind, Body: text})
	return c.saveLocked()
}

func (c *Client) sendPayloadLocked(ctx context.Context, to string, p qlcrypto.Payload) error {
	pt, err := p.Marshal()
	if err != nil {
		return err
	}
	kind := protocol.KindMessage
	var init *qlcrypto.InitialMessage
	sess := c.sessions[to]
	if sess == nil {
		b, err := c.tr.FetchBundle(ctx, to)
		if err != nil {
			return err
		}
		sk, ad, im, err := qlcrypto.InitiateX3DH(c.id, bundleFrom(b))
		if err != nil {
			return err
		}
		sess, err = qlcrypto.InitAlice(sk, b.SignedPreKey.Public, ad)
		if err != nil {
			return err
		}
		c.sessions[to] = sess
		c.peers[to] = qlcrypto.PublicIdentity{
			DH:   append([]byte(nil), b.IdentityDH...),
			Sign: ed25519.PublicKey(append([]byte(nil), b.IdentitySign...)),
		}
		init = &im
		kind = protocol.KindPrekey
	}
	h, ct, err := sess.Encrypt(pt)
	if err != nil {
		return err
	}
	wire := protocol.Ciphertext{Type: "message", Header: h, Ciphertext: ct}
	if init != nil {
		wire.Type = "prekey"
		wire.IdentityDH = init.IdentityDH
		wire.IdentitySign = init.IdentitySign
		wire.Ephemeral = init.Ephemeral
		wire.SignedPreKeyID = init.SignedPreKeyID
		wire.OneTimePreKeyID = init.OneTimePreKeyID
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	if err := c.saveLocked(); err != nil {
		return err
	}
	_, err = c.tr.Send(ctx, protocol.SendRequest{Recipient: to, Kind: kind, Body: body})
	return err
}

func (c *Client) Recv(ctx context.Context) ([]Message, error) {
	sync, err := c.tr.Sync(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Message
	var ack []string
	for _, env := range sync.Envelopes {
		m, err := c.handle(env)
		if err != nil {
			// leave unacked so a later SKDM can unblock a group message
			continue
		}
		c.noteSeen(env.ID)
		ack = append(ack, env.ID)
		if m != nil {
			m.EnvelopeID = env.ID
			out = append(out, *m)
		}
	}
	_ = c.saveLocked()
	_ = c.tr.Ack(ctx, ack)
	_ = c.refillLocked(ctx)
	return out, nil
}

func (c *Client) Listen(ctx context.Context, fn func(Message)) error {
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := c.listenOnce(ctx, fn)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			if backoff < 8*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func (c *Client) listenOnce(ctx context.Context, fn func(Message)) error {
	conn, err := c.tr.DialWS(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	readErr := make(chan error, 1)
	type wsEnv struct {
		raw []byte
	}
	incoming := make(chan wsEnv, 8)
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			select {
			case incoming <- wsEnv{raw: append([]byte(nil), data...)}:
			case <-ctx.Done():
				readErr <- ctx.Err()
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return err
		case <-ping.C:
			b, _ := json.Marshal(protocol.WSMessage{Op: "ping"})
			_ = conn.Write(ctx, websocket.MessageText, b)
		case in := <-incoming:
			var msg protocol.WSMessage
			if json.Unmarshal(in.raw, &msg) != nil || msg.Envelope == nil {
				continue
			}
			c.mu.Lock()
			out, err := c.handle(*msg.Envelope)
			if err != nil {
				c.mu.Unlock()
				continue
			}
			c.noteSeen(msg.Envelope.ID)
			_ = c.saveLocked()
			c.mu.Unlock()
			ack, _ := json.Marshal(protocol.WSMessage{Op: "ack", IDs: []string{msg.Envelope.ID}})
			_ = conn.Write(ctx, websocket.MessageText, ack)
			if out != nil && fn != nil {
				out.EnvelopeID = msg.Envelope.ID
				fn(*out)
			}
		}
	}
}

func (c *Client) CreateGroup(ctx context.Context, name string, members []string) (protocol.GroupInfo, error) {
	g, err := c.tr.CreateGroup(ctx, name, members)
	if err != nil {
		return protocol.GroupInfo{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	lg := c.ensureGroup(g)
	sk, err := qlcrypto.NewSenderKey()
	if err != nil {
		return protocol.GroupInfo{}, err
	}
	lg.Sender = sk
	dist := sk.Distribution(g.ID)
	p := qlcrypto.NewSKDM(newID(), g.ID, dist)
	for _, m := range g.Members {
		if m == c.username {
			continue
		}
		if err := c.sendPayloadLocked(ctx, m, p); err != nil {
			return protocol.GroupInfo{}, err
		}
	}
	if err := c.saveLocked(); err != nil {
		return protocol.GroupInfo{}, err
	}
	return g, nil
}

func (c *Client) SendGroup(ctx context.Context, groupID, text string) error {
	info, err := c.tr.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	g := c.ensureGroup(info)
	if g.Sender == nil {
		sk, err := qlcrypto.NewSenderKey()
		if err != nil {
			return err
		}
		g.Sender = sk
		dist := sk.Distribution(groupID)
		p := qlcrypto.NewSKDM(newID(), groupID, dist)
		for _, m := range info.Members {
			if m == c.username {
				continue
			}
			if err := c.sendPayloadLocked(ctx, m, p); err != nil {
				return err
			}
		}
	}
	payload := qlcrypto.NewGroupText(newID(), groupID, text)
	pt, err := payload.Marshal()
	if err != nil {
		return err
	}
	iter, ct, sig, err := g.Sender.Encrypt(pt, []byte(groupID))
	if err != nil {
		return err
	}
	wire := protocol.GroupCiphertext{
		GroupID:    groupID,
		Sender:     c.username,
		SeedID:     g.Sender.SeedID,
		Iteration:  iter,
		SigningPub: append([]byte(nil), g.Sender.SigningPub...),
		Ciphertext: ct,
		Signature:  sig,
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	if err := c.saveLocked(); err != nil {
		return err
	}
	if _, err := c.tr.Send(ctx, protocol.SendRequest{GroupID: groupID, Kind: protocol.KindGroup, Body: body}); err != nil {
		return err
	}
	c.appendLog(LogEntry{TS: payload.TS, From: c.username, To: "", GroupID: groupID, Kind: payload.Kind, Body: text})
	return c.saveLocked()
}

func (c *Client) ensureGroup(info protocol.GroupInfo) *liveGroup {
	g := c.groups[info.ID]
	if g == nil {
		g = &liveGroup{Chains: map[string]*qlcrypto.ReceiveChain{}}
		c.groups[info.ID] = g
	}
	g.Name = info.Name
	g.Members = append([]string(nil), info.Members...)
	if g.Chains == nil {
		g.Chains = map[string]*qlcrypto.ReceiveChain{}
	}
	return g
}

func (c *Client) handle(env protocol.Envelope) (*Message, error) {
	if c.seenSet[env.ID] {
		return nil, nil
	}
	switch env.Kind {
	case protocol.KindGroup:
		return c.handleGroup(env)
	default:
		return c.handleDirect(env)
	}
}

func (c *Client) handleDirect(env protocol.Envelope) (*Message, error) {
	var wire protocol.Ciphertext
	if err := json.Unmarshal(env.Body, &wire); err != nil {
		return nil, err
	}
	isPre := env.Kind == protocol.KindPrekey || wire.Type == "prekey"
	var sess *qlcrypto.State
	if isPre {
		spk, err := c.spkPriv(wire.SignedPreKeyID)
		if err != nil {
			return nil, err
		}
		var otk *ecdh.PrivateKey
		if wire.OneTimePreKeyID != nil {
			otk, err = c.takeOTK(*wire.OneTimePreKeyID)
			if err != nil {
				return nil, err
			}
		}
		init := qlcrypto.InitialMessage{
			IdentityDH:      wire.IdentityDH,
			IdentitySign:    wire.IdentitySign,
			Ephemeral:       wire.Ephemeral,
			SignedPreKeyID:  wire.SignedPreKeyID,
			OneTimePreKeyID: wire.OneTimePreKeyID,
		}
		sk, ad, err := qlcrypto.CompleteX3DH(c.id, spk, otk, init)
		if err != nil {
			return nil, err
		}
		sess = qlcrypto.InitBob(sk, spk, ad)
		c.sessions[env.Sender] = sess
		c.peers[env.Sender] = qlcrypto.PublicIdentity{
			DH:   append([]byte(nil), wire.IdentityDH...),
			Sign: ed25519.PublicKey(append([]byte(nil), wire.IdentitySign...)),
		}
	} else {
		sess = c.sessions[env.Sender]
		if sess == nil {
			return nil, qlcrypto.ErrNoSession
		}
	}
	pt, err := sess.Decrypt(wire.Header, wire.Ciphertext)
	if err != nil {
		return nil, err
	}
	p, err := qlcrypto.UnmarshalPayload(pt)
	if err != nil {
		return nil, err
	}
	return c.applyPayload(env.Sender, p)
}

func (c *Client) handleGroup(env protocol.Envelope) (*Message, error) {
	var wire protocol.GroupCiphertext
	if err := json.Unmarshal(env.Body, &wire); err != nil {
		return nil, err
	}
	g := c.groups[wire.GroupID]
	if g == nil || g.Chains[env.Sender] == nil {
		return nil, fmt.Errorf("no sender key for %s in group %s", env.Sender, wire.GroupID)
	}
	ch := g.Chains[env.Sender]
	if ch.SeedID != wire.SeedID {
		return nil, fmt.Errorf("sender key seed mismatch")
	}
	pt, err := ch.Decrypt(wire.Iteration, wire.Ciphertext, wire.Signature, []byte(wire.GroupID))
	if err != nil {
		return nil, err
	}
	p, err := qlcrypto.UnmarshalPayload(pt)
	if err != nil {
		return nil, err
	}
	if p.GroupID == "" {
		p.GroupID = wire.GroupID
	}
	return c.applyPayload(env.Sender, p)
}

func (c *Client) applyPayload(from string, p qlcrypto.Payload) (*Message, error) {
	switch p.Kind {
	case qlcrypto.KindSKDM:
		if p.SKDM == nil {
			return nil, fmt.Errorf("empty skdm")
		}
		g := c.groups[p.GroupID]
		if g == nil {
			g = &liveGroup{Chains: map[string]*qlcrypto.ReceiveChain{}}
			c.groups[p.GroupID] = g
		}
		g.Chains[from] = qlcrypto.NewReceiveChain(*p.SKDM)
	}
	body := p.Body
	if p.Kind == qlcrypto.KindReceipt {
		body = strings.TrimSpace(p.Status + " " + p.Ref)
	}
	if p.Kind == qlcrypto.KindSKDM {
		body = "sender-key"
	}
	c.appendLog(LogEntry{TS: p.TS, From: from, To: c.username, GroupID: p.GroupID, Kind: p.Kind, Body: body})
	return &Message{From: from, GroupID: p.GroupID, Kind: p.Kind, Body: p.Body, ID: p.ID, Ref: p.Ref}, nil
}

func (c *Client) spkPriv(id uint32) (*ecdh.PrivateKey, error) {
	k, ok := c.spks[id]
	if !ok {
		return nil, fmt.Errorf("unknown signed prekey %d", id)
	}
	return k.Private, nil
}

func (c *Client) takeOTK(id uint32) (*ecdh.PrivateKey, error) {
	k, ok := c.otks[id]
	if !ok {
		return nil, fmt.Errorf("unknown one-time prekey %d", id)
	}
	delete(c.otks, id)
	return k.Private, nil
}

func (c *Client) noteSeen(id string) {
	if c.seenSet[id] {
		return
	}
	c.seenSet[id] = true
	c.seen = append(c.seen, id)
	if len(c.seen) > 2000 {
		drop := c.seen[:len(c.seen)-2000]
		for _, d := range drop {
			delete(c.seenSet, d)
		}
		c.seen = c.seen[len(c.seen)-2000:]
	}
}

func (c *Client) appendLog(e LogEntry) {
	c.log = append(c.log, e)
	if len(c.log) > 500 {
		c.log = c.log[len(c.log)-500:]
	}
}

func bundleFrom(b protocol.PreKeyBundle) qlcrypto.Bundle {
	out := qlcrypto.Bundle{
		Identity: qlcrypto.PublicIdentity{
			DH:   append([]byte(nil), b.IdentityDH...),
			Sign: ed25519.PublicKey(append([]byte(nil), b.IdentitySign...)),
		},
		Signed: qlcrypto.PublicPreKey{
			ID:        b.SignedPreKey.ID,
			Public:    b.SignedPreKey.Public,
			Signature: b.SignedPreKey.Signature,
		},
	}
	if b.OneTime != nil {
		out.OneTime = &qlcrypto.PublicPreKey{ID: b.OneTime.ID, Public: b.OneTime.Public}
	}
	return out
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
