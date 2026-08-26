package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	KeySize = 32

	infoIdentityDH   = "quietline-identity-x25519"
	infoIdentitySign = "quietline-identity-ed25519"
)

var (
	ErrInvalidKey    = errors.New("quietline: invalid key")
	ErrBadSignature  = errors.New("quietline: bad signature")
	ErrPrekeyVerify  = errors.New("quietline: signed prekey failed verification")
	ErrNoOneTime     = errors.New("quietline: one-time prekey not found")
	ErrDecryptFailed = errors.New("quietline: decrypt failed")
	ErrSkippedLimit  = errors.New("quietline: skipped-message key limit exceeded")
	ErrNoSession     = errors.New("quietline: no ratchet session")
	ErrBadHeader     = errors.New("quietline: malformed ratchet header")
)

// Identity is a long-term key pair: X25519 for DH, Ed25519 for signatures.
// Both are derived from a single 32-byte seed so the identity is one object.
type Identity struct {
	Seed []byte
	DH   *ecdh.PrivateKey
	Sign ed25519.PrivateKey
}

type PublicIdentity struct {
	DH   []byte
	Sign ed25519.PublicKey
}

type PreKey struct {
	ID        uint32
	Private   *ecdh.PrivateKey
	Public    []byte
	Signature []byte // Ed25519 over signed-prekey encoding; empty for one-time
}

func GenerateSeed() ([]byte, error) {
	seed := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func DeriveIdentity(seed []byte) (*Identity, error) {
	if len(seed) != KeySize {
		return nil, ErrInvalidKey
	}
	dhBytes, err := hkdfExpand(seed, []byte(infoIdentityDH), KeySize)
	if err != nil {
		return nil, err
	}
	// X25519.NewPrivateKey accepts 32 bytes; ECDH clamps per RFC 7748.
	dh, err := ecdh.X25519().NewPrivateKey(dhBytes)
	if err != nil {
		return nil, fmt.Errorf("identity dh: %w", err)
	}
	signSeed, err := hkdfExpand(seed, []byte(infoIdentitySign), KeySize)
	if err != nil {
		return nil, err
	}
	sign := ed25519.NewKeyFromSeed(signSeed)
	out := &Identity{
		Seed: append([]byte(nil), seed...),
		DH:   dh,
		Sign: sign,
	}
	return out, nil
}

func (id *Identity) Public() PublicIdentity {
	return PublicIdentity{
		DH:   append([]byte(nil), id.DH.PublicKey().Bytes()...),
		Sign: append(ed25519.PublicKey(nil), id.Sign.Public().(ed25519.PublicKey)...),
	}
}

func GenerateDH() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func PublicFromBytes(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != KeySize {
		return nil, ErrInvalidKey
	}
	return ecdh.X25519().NewPublicKey(b)
}

func PrivateFromBytes(b []byte) (*ecdh.PrivateKey, error) {
	if len(b) != KeySize {
		return nil, ErrInvalidKey
	}
	return ecdh.X25519().NewPrivateKey(b)
}

func DH(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	if priv == nil || pub == nil {
		return nil, ErrInvalidKey
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func DHBytes(priv *ecdh.PrivateKey, pubBytes []byte) ([]byte, error) {
	pub, err := PublicFromBytes(pubBytes)
	if err != nil {
		return nil, err
	}
	return DH(priv, pub)
}

// SignedPreKeyEncoding is what the identity signs: label || id || public.
func SignedPreKeyEncoding(id uint32, pub []byte) []byte {
	buf := make([]byte, 0, 16+4+len(pub))
	buf = append(buf, []byte("Quietline-SPK-v1")...)
	buf = binary.BigEndian.AppendUint32(buf, id)
	buf = append(buf, pub...)
	return buf
}

func NewSignedPreKey(id *Identity, keyID uint32) (*PreKey, error) {
	priv, err := GenerateDH()
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()
	sig := ed25519.Sign(id.Sign, SignedPreKeyEncoding(keyID, pub))
	return &PreKey{
		ID:        keyID,
		Private:   priv,
		Public:    pub,
		Signature: sig,
	}, nil
}

func NewOneTimePreKey(keyID uint32) (*PreKey, error) {
	priv, err := GenerateDH()
	if err != nil {
		return nil, err
	}
	return &PreKey{
		ID:      keyID,
		Private: priv,
		Public:  priv.PublicKey().Bytes(),
	}, nil
}

func VerifySignedPreKey(signPub ed25519.PublicKey, keyID uint32, pub, sig []byte) error {
	if len(signPub) != ed25519.PublicKeySize || len(pub) != KeySize || len(sig) != ed25519.SignatureSize {
		return ErrPrekeyVerify
	}
	if !ed25519.Verify(signPub, SignedPreKeyEncoding(keyID, pub), sig) {
		return ErrPrekeyVerify
	}
	return nil
}

func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func hkdfExpand(secret, info []byte, n int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
