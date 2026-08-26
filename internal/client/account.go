package client

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	qlcrypto "github.com/aljojoby9/quietline/internal/crypto"
)

type diskAccount struct {
	Version        int                        `json:"version"`
	Server         string                     `json:"server"`
	Username       string                     `json:"username"`
	Token          string                     `json:"token"`
	Seed           []byte                     `json:"seed"`
	SignedPreKeys  []diskPreKey               `json:"signed_prekeys"`
	OneTimePreKeys []diskPreKey               `json:"one_time_prekeys"`
	NextSPK        uint32                     `json:"next_spk"`
	NextOTK        uint32                     `json:"next_otk"`
	Sessions       map[string]json.RawMessage `json:"sessions"`
	Peers          map[string]diskPeer        `json:"peers"`
	Groups         map[string]diskGroup       `json:"groups"`
	Seen           []string                   `json:"seen"`
	Log            []LogEntry                 `json:"log"`
}

type diskPreKey struct {
	ID        uint32 `json:"id"`
	Private   []byte `json:"private"`
	Public    []byte `json:"public"`
	Signature []byte `json:"signature,omitempty"`
}

type diskPeer struct {
	DH   []byte `json:"dh"`
	Sign []byte `json:"sign"`
}

type diskGroup struct {
	Name    string               `json:"name"`
	Members []string             `json:"members"`
	Sender  *diskSender          `json:"sender,omitempty"`
	Chains  map[string]diskChain `json:"chains,omitempty"`
}

type diskSender struct {
	SeedID     uint32 `json:"seed_id"`
	Iteration  uint32 `json:"iteration"`
	ChainKey   []byte `json:"chain_key"`
	Sign       []byte `json:"sign"`
	SigningPub []byte `json:"signing_pub"`
}

type diskChain struct {
	SeedID     uint32        `json:"seed_id"`
	Iteration  uint32        `json:"iteration"`
	ChainKey   []byte        `json:"chain_key"`
	SigningPub []byte        `json:"signing_pub"`
	Skipped    []diskSkipped `json:"skipped,omitempty"`
}

type diskSkipped struct {
	N  uint32 `json:"n"`
	MK []byte `json:"mk"`
}

type LogEntry struct {
	TS      int64  `json:"ts"`
	From    string `json:"from"`
	To      string `json:"to"`
	GroupID string `json:"group_id,omitempty"`
	Kind    string `json:"kind"`
	Body    string `json:"body"`
}

func DefaultHome() string {
	if h := os.Getenv("QL_HOME"); h != "" {
		return h
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".quietline")
	}
	return filepath.Join(dir, "quietline")
}

func accountPath(home string) string {
	return filepath.Join(home, "account.json")
}

func (c *Client) snapshot() (*diskAccount, error) {
	d := &diskAccount{
		Version:  1,
		Server:   c.server,
		Username: c.username,
		Token:    c.tr.Token,
		Seed:     append([]byte(nil), c.id.Seed...),
		NextSPK:  c.nextSPK,
		NextOTK:  c.nextOTK,
		Sessions: map[string]json.RawMessage{},
		Peers:    map[string]diskPeer{},
		Groups:   map[string]diskGroup{},
		Seen:     append([]string(nil), c.seen...),
		Log:      append([]LogEntry(nil), c.log...),
	}
	for _, k := range c.spks {
		d.SignedPreKeys = append(d.SignedPreKeys, diskPreKey{
			ID: k.ID, Private: k.Private.Bytes(), Public: append([]byte(nil), k.Public...), Signature: append([]byte(nil), k.Signature...),
		})
	}
	for _, k := range c.otks {
		d.OneTimePreKeys = append(d.OneTimePreKeys, diskPreKey{
			ID: k.ID, Private: k.Private.Bytes(), Public: append([]byte(nil), k.Public...),
		})
	}
	for name, st := range c.sessions {
		b, err := st.Dump()
		if err != nil {
			return nil, err
		}
		d.Sessions[name] = b
	}
	for name, p := range c.peers {
		d.Peers[name] = diskPeer{DH: append([]byte(nil), p.DH...), Sign: append([]byte(nil), p.Sign...)}
	}
	for id, g := range c.groups {
		dg := diskGroup{Name: g.Name, Members: append([]string(nil), g.Members...), Chains: map[string]diskChain{}}
		if g.Sender != nil {
			dg.Sender = &diskSender{
				SeedID:     g.Sender.SeedID,
				Iteration:  g.Sender.Iteration,
				ChainKey:   append([]byte(nil), g.Sender.ChainKey...),
				Sign:       append([]byte(nil), g.Sender.Sign...),
				SigningPub: append([]byte(nil), g.Sender.SigningPub...),
			}
		}
		for sender, ch := range g.Chains {
			dc := diskChain{
				SeedID:     ch.SeedID,
				Iteration:  ch.Iteration,
				ChainKey:   append([]byte(nil), ch.ChainKey...),
				SigningPub: append([]byte(nil), ch.SigningPub...),
			}
			for n, mk := range ch.Skipped {
				dc.Skipped = append(dc.Skipped, diskSkipped{N: n, MK: append([]byte(nil), mk...)})
			}
			dg.Chains[sender] = dc
		}
		d.Groups[id] = dg
	}
	return d, nil
}

func (c *Client) saveLocked() error {
	d, err := c.snapshot()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.home, 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func loadDisk(path string) (*diskAccount, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d diskAccount
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}
	return &d, nil
}

func clientFromDisk(home string, d *diskAccount) (*Client, error) {
	id, err := qlcrypto.DeriveIdentity(d.Seed)
	if err != nil {
		return nil, err
	}
	c := newClient(home, d.Server)
	c.id = id
	c.username = d.Username
	c.tr.Token = d.Token
	c.nextSPK = d.NextSPK
	c.nextOTK = d.NextOTK
	c.seen = append([]string(nil), d.Seen...)
	for _, id := range c.seen {
		c.seenSet[id] = true
	}
	c.log = append([]LogEntry(nil), d.Log...)
	for _, k := range d.SignedPreKeys {
		priv, err := qlcrypto.PrivateFromBytes(k.Private)
		if err != nil {
			return nil, err
		}
		c.spks[k.ID] = &qlcrypto.PreKey{ID: k.ID, Private: priv, Public: k.Public, Signature: k.Signature}
	}
	for _, k := range d.OneTimePreKeys {
		priv, err := qlcrypto.PrivateFromBytes(k.Private)
		if err != nil {
			return nil, err
		}
		c.otks[k.ID] = &qlcrypto.PreKey{ID: k.ID, Private: priv, Public: k.Public}
	}
	for name, raw := range d.Sessions {
		st, err := qlcrypto.LoadState(raw)
		if err != nil {
			return nil, err
		}
		c.sessions[name] = st
	}
	for name, p := range d.Peers {
		c.peers[name] = qlcrypto.PublicIdentity{
			DH:   append([]byte(nil), p.DH...),
			Sign: ed25519.PublicKey(append([]byte(nil), p.Sign...)),
		}
	}
	for id, g := range d.Groups {
		lg := &liveGroup{Name: g.Name, Members: append([]string(nil), g.Members...), Chains: map[string]*qlcrypto.ReceiveChain{}}
		if g.Sender != nil {
			lg.Sender = &qlcrypto.SenderKey{
				SeedID:     g.Sender.SeedID,
				Iteration:  g.Sender.Iteration,
				ChainKey:   append([]byte(nil), g.Sender.ChainKey...),
				Sign:       ed25519.PrivateKey(append([]byte(nil), g.Sender.Sign...)),
				SigningPub: ed25519.PublicKey(append([]byte(nil), g.Sender.SigningPub...)),
			}
		}
		for sender, ch := range g.Chains {
			rc := &qlcrypto.ReceiveChain{
				SeedID:     ch.SeedID,
				Iteration:  ch.Iteration,
				ChainKey:   append([]byte(nil), ch.ChainKey...),
				SigningPub: ed25519.PublicKey(append([]byte(nil), ch.SigningPub...)),
				Skipped:    map[uint32][]byte{},
			}
			for _, sk := range ch.Skipped {
				rc.Skipped[sk.N] = append([]byte(nil), sk.MK...)
			}
			lg.Chains[sender] = rc
		}
		c.groups[id] = lg
	}
	return c, nil
}
