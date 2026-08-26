package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aljojoby9/quietline/internal/protocol"
	"golang.org/x/crypto/argon2"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrTaken     = errors.New("username taken")
	ErrAuth      = errors.New("authentication failed")
	ErrBadUser   = errors.New("invalid username")
	ErrNotMember = errors.New("not a group member")
)

type Store struct {
	db       *sql.DB
	postgres bool
}

func OpenStore(dsn string) (*Store, error) {
	var (
		driver string
		open   string
		pg     bool
	)
	switch {
	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		driver = "pgx"
		open = dsn
		pg = true
	case strings.HasPrefix(dsn, "sqlite:"):
		driver = "sqlite"
		open = strings.TrimPrefix(dsn, "sqlite:")
	default:
		driver = "sqlite"
		open = dsn
	}
	if driver == "sqlite" && open != ":memory:" {
		if !strings.Contains(open, "?") {
			open += "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
		}
	}
	db, err := sql.Open(driver, open)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
	}
	s := &Store{db: db, postgres: pg}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			fmt.Fprintf(&b, "$%d", n)
			n++
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			identity_dh BLOB NOT NULL,
			identity_sign BLOB NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS signed_prekeys (
			user_id INTEGER NOT NULL,
			key_id INTEGER NOT NULL,
			public_key BLOB NOT NULL,
			signature BLOB NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY (user_id, key_id)
		)`,
		`CREATE TABLE IF NOT EXISTS one_time_prekeys (
			user_id INTEGER NOT NULL,
			key_id INTEGER NOT NULL,
			public_key BLOB NOT NULL,
			PRIMARY KEY (user_id, key_id)
		)`,
		`CREATE TABLE IF NOT EXISTS tokens (
			token_hash BLOB PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS envelopes (
			id TEXT PRIMARY KEY,
			sender TEXT NOT NULL,
			recipient TEXT NOT NULL,
			device_id INTEGER NOT NULL DEFAULT 1,
			kind TEXT NOT NULL,
			group_id TEXT,
			body BLOB NOT NULL,
			created_at TEXT NOT NULL,
			acked INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS envelopes_inbox ON envelopes (recipient, acked, created_at)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			creator TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id TEXT NOT NULL,
			username TEXT NOT NULL,
			PRIMARY KEY (group_id, username)
		)`,
	}
	if s.postgres {
		stmts = []string{
			`CREATE TABLE IF NOT EXISTS users (
				id BIGSERIAL PRIMARY KEY,
				username TEXT UNIQUE NOT NULL,
				password_hash TEXT NOT NULL,
				identity_dh BYTEA NOT NULL,
				identity_sign BYTEA NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS signed_prekeys (
				user_id BIGINT NOT NULL,
				key_id INTEGER NOT NULL,
				public_key BYTEA NOT NULL,
				signature BYTEA NOT NULL,
				created_at TEXT NOT NULL,
				PRIMARY KEY (user_id, key_id)
			)`,
			`CREATE TABLE IF NOT EXISTS one_time_prekeys (
				user_id BIGINT NOT NULL,
				key_id INTEGER NOT NULL,
				public_key BYTEA NOT NULL,
				PRIMARY KEY (user_id, key_id)
			)`,
			`CREATE TABLE IF NOT EXISTS tokens (
				token_hash BYTEA PRIMARY KEY,
				user_id BIGINT NOT NULL,
				expires_at TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS envelopes (
				id TEXT PRIMARY KEY,
				sender TEXT NOT NULL,
				recipient TEXT NOT NULL,
				device_id INTEGER NOT NULL DEFAULT 1,
				kind TEXT NOT NULL,
				group_id TEXT,
				body BYTEA NOT NULL,
				created_at TEXT NOT NULL,
				acked INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE INDEX IF NOT EXISTS envelopes_inbox ON envelopes (recipient, acked, created_at)`,
			`CREATE TABLE IF NOT EXISTS groups (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				creator TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS group_members (
				group_id TEXT NOT NULL,
				username TEXT NOT NULL,
				PRIMARY KEY (group_id, username)
			)`,
		}
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

func validUsername(u string) bool {
	if len(u) < 2 || len(u) > 32 {
		return false
	}
	for _, c := range u {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return false
	}
	return true
}

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, 1, 64*1024, 1, 32)
	return fmt.Sprintf("argon2id$v=19$m=65536,t=1,p=1$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

func checkPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	salt, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, 1, 64*1024, 1, 32)
	return subtle.ConstantTimeCompare(want, got) == 1
}

func tokenHash(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

type User struct {
	ID           int64
	Username     string
	IdentityDH   []byte
	IdentitySign []byte
}

func (s *Store) Register(req protocol.RegisterRequest) error {
	if !validUsername(req.Username) {
		return ErrBadUser
	}
	if len(req.Password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len(req.IdentityDH) != 32 || len(req.IdentitySign) != 32 {
		return errors.New("identity keys must be 32 bytes")
	}
	if len(req.OneTime) < 1 {
		return errors.New("need at least one one-time prekey")
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(s.q(`INSERT INTO users (username, password_hash, identity_dh, identity_sign, created_at) VALUES (?, ?, ?, ?, ?)`),
		req.Username, hash, req.IdentityDH, req.IdentitySign, now)
	if err != nil {
		if isUnique(err) {
			return ErrTaken
		}
		return err
	}
	uid, err := res.LastInsertId()
	if err != nil && s.postgres {
		if err := tx.QueryRow(s.q(`SELECT id FROM users WHERE username = ?`), req.Username).Scan(&uid); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	spk := req.SignedPreKey
	if _, err := tx.Exec(s.q(`INSERT INTO signed_prekeys (user_id, key_id, public_key, signature, created_at) VALUES (?, ?, ?, ?, ?)`),
		uid, spk.ID, spk.Public, spk.Signature, now); err != nil {
		return err
	}
	for _, k := range req.OneTime {
		if _, err := tx.Exec(s.q(`INSERT INTO one_time_prekeys (user_id, key_id, public_key) VALUES (?, ?, ?)`),
			uid, k.ID, k.Public); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func isUnique(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}

func (s *Store) Login(username, password string) (string, error) {
	var id int64
	var hash string
	err := s.db.QueryRow(s.q(`SELECT id, password_hash FROM users WHERE username = ?`), username).Scan(&id, &hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrAuth
		}
		return "", err
	}
	if !checkPassword(hash, password) {
		return "", ErrAuth
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	exp := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339Nano)
	if _, err := s.db.Exec(s.q(`INSERT INTO tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)`), tokenHash(tok), id, exp); err != nil {
		return "", err
	}
	return tok, nil
}

func (s *Store) UserByToken(tok string) (*User, error) {
	var u User
	var exp string
	err := s.db.QueryRow(s.q(`
		SELECT users.id, users.username, users.identity_dh, users.identity_sign, tokens.expires_at
		FROM tokens JOIN users ON users.id = tokens.user_id
		WHERE tokens.token_hash = ?`), tokenHash(tok)).Scan(&u.ID, &u.Username, &u.IdentityDH, &u.IdentitySign, &exp)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAuth
		}
		return nil, err
	}
	t, err := time.Parse(time.RFC3339Nano, exp)
	if err != nil || time.Now().UTC().After(t) {
		return nil, ErrAuth
	}
	return &u, nil
}

func (s *Store) UserByName(name string) (*User, error) {
	var u User
	err := s.db.QueryRow(s.q(`SELECT id, username, identity_dh, identity_sign FROM users WHERE username = ?`), name).
		Scan(&u.ID, &u.Username, &u.IdentityDH, &u.IdentitySign)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (s *Store) FetchBundle(username string) (*protocol.PreKeyBundle, error) {
	u, err := s.UserByName(username)
	if err != nil {
		return nil, err
	}
	b := &protocol.PreKeyBundle{
		Username:     u.Username,
		IdentityDH:   u.IdentityDH,
		IdentitySign: u.IdentitySign,
	}
	err = s.db.QueryRow(s.q(`SELECT key_id, public_key, signature FROM signed_prekeys WHERE user_id = ? ORDER BY key_id DESC LIMIT 1`), u.ID).
		Scan(&b.SignedPreKey.ID, &b.SignedPreKey.Public, &b.SignedPreKey.Signature)
	if err != nil {
		return nil, fmt.Errorf("signed prekey: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var otk protocol.PublicPreKey
	err = tx.QueryRow(s.q(`SELECT key_id, public_key FROM one_time_prekeys WHERE user_id = ? LIMIT 1`), u.ID).
		Scan(&otk.ID, &otk.Public)
	if err == nil {
		if _, err := tx.Exec(s.q(`DELETE FROM one_time_prekeys WHERE user_id = ? AND key_id = ?`), u.ID, otk.ID); err != nil {
			return nil, err
		}
		b.OneTime = &otk
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Store) OTKCount(userID int64) (int, error) {
	var n int
	err := s.db.QueryRow(s.q(`SELECT COUNT(*) FROM one_time_prekeys WHERE user_id = ?`), userID).Scan(&n)
	return n, err
}

func (s *Store) CurrentSignedID(userID int64) (uint32, error) {
	var id uint32
	err := s.db.QueryRow(s.q(`SELECT key_id FROM signed_prekeys WHERE user_id = ? ORDER BY key_id DESC LIMIT 1`), userID).Scan(&id)
	return id, err
}

func (s *Store) AddOTKs(userID int64, keys []protocol.PublicPreKey) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, k := range keys {
		if _, err := tx.Exec(s.q(`INSERT INTO one_time_prekeys (user_id, key_id, public_key) VALUES (?, ?, ?)`),
			userID, k.ID, k.Public); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RotateSigned(userID int64, k protocol.PublicPreKey) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(s.q(`INSERT INTO signed_prekeys (user_id, key_id, public_key, signature, created_at) VALUES (?, ?, ?, ?, ?)`),
		userID, k.ID, k.Public, k.Signature, now)
	return err
}

func (s *Store) PutEnvelope(e protocol.Envelope) error {
	_, err := s.db.Exec(s.q(`INSERT INTO envelopes (id, sender, recipient, device_id, kind, group_id, body, created_at, acked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`),
		e.ID, e.Sender, e.Recipient, e.DeviceID, e.Kind, nullStr(e.GroupID), e.Body, e.CreatedAt)
	return err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Store) Inbox(recipient string, limit int) ([]protocol.Envelope, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(s.q(`SELECT id, sender, recipient, device_id, kind, COALESCE(group_id, ''), body, created_at
		FROM envelopes WHERE recipient = ? AND acked = 0 ORDER BY created_at ASC LIMIT ?`), recipient, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Envelope
	for rows.Next() {
		var e protocol.Envelope
		if err := rows.Scan(&e.ID, &e.Sender, &e.Recipient, &e.DeviceID, &e.Kind, &e.GroupID, &e.Body, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Ack(recipient string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec(s.q(`UPDATE envelopes SET acked = 1 WHERE id = ? AND recipient = ?`), id, recipient); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AllEnvelopes returns every stored envelope (ciphertext + routing). Used by
// tests and the sealed-relay proof. Never decrypts.
func (s *Store) AllEnvelopes() ([]protocol.Envelope, error) {
	rows, err := s.db.Query(`SELECT id, sender, recipient, device_id, kind, COALESCE(group_id, ''), body, created_at FROM envelopes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Envelope
	for rows.Next() {
		var e protocol.Envelope
		if err := rows.Scan(&e.ID, &e.Sender, &e.Recipient, &e.DeviceID, &e.Kind, &e.GroupID, &e.Body, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) CreateGroup(id, name, creator string, members []string) error {
	seen := map[string]bool{}
	var unique []string
	for _, m := range append([]string{creator}, members...) {
		if seen[m] {
			continue
		}
		seen[m] = true
		if _, err := s.UserByName(m); err != nil {
			return fmt.Errorf("member %s: %w", m, err)
		}
		unique = append(unique, m)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(s.q(`INSERT INTO groups (id, name, creator, created_at) VALUES (?, ?, ?, ?)`), id, name, creator, now); err != nil {
		return err
	}
	for _, m := range unique {
		if _, err := tx.Exec(s.q(`INSERT INTO group_members (group_id, username) VALUES (?, ?)`), id, m); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Group(id string) (*protocol.GroupInfo, error) {
	g := &protocol.GroupInfo{ID: id}
	err := s.db.QueryRow(s.q(`SELECT name, creator FROM groups WHERE id = ?`), id).Scan(&g.Name, &g.Creator)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rows, err := s.db.Query(s.q(`SELECT username FROM group_members WHERE group_id = ?`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		g.Members = append(g.Members, u)
	}
	return g, rows.Err()
}

func (s *Store) IsMember(groupID, username string) (bool, error) {
	var n int
	err := s.db.QueryRow(s.q(`SELECT COUNT(*) FROM group_members WHERE group_id = ? AND username = ?`), groupID, username).Scan(&n)
	return n > 0, err
}
