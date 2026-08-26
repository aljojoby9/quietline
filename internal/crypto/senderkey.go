package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// SenderKey is the Signal/WhatsApp sender-keys construction: a symmetric
// chain per group member plus an Ed25519 key that authenticates that
// member's group ciphertexts. Distribution happens over 1:1 Double Ratchet
// sessions; the relay never sees chain keys.
type SenderKey struct {
	SeedID     uint32
	Iteration  uint32
	ChainKey   []byte
	Sign       ed25519.PrivateKey
	SigningPub ed25519.PublicKey
}

type SenderKeyDistribution struct {
	GroupID    string
	SeedID     uint32
	Iteration  uint32
	ChainKey   []byte
	SigningPub []byte
}

type ReceiveChain struct {
	SeedID     uint32
	Iteration  uint32
	ChainKey   []byte
	SigningPub ed25519.PublicKey
	Skipped    map[uint32][]byte
}

func NewSenderKey() (*SenderKey, error) {
	ck := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, ck); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var seedID uint32
	var b [4]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return nil, err
	}
	seedID = binary.BigEndian.Uint32(b[:])
	return &SenderKey{
		SeedID:     seedID,
		ChainKey:   ck,
		Sign:       priv,
		SigningPub: pub,
	}, nil
}

func (s *SenderKey) Distribution(groupID string) SenderKeyDistribution {
	return SenderKeyDistribution{
		GroupID:    groupID,
		SeedID:     s.SeedID,
		Iteration:  s.Iteration,
		ChainKey:   append([]byte(nil), s.ChainKey...),
		SigningPub: append([]byte(nil), s.SigningPub...),
	}
}

func (s *SenderKey) Encrypt(plaintext, ad []byte) (iteration uint32, ciphertext, signature []byte, err error) {
	next, mk := senderKDF(s.ChainKey)
	iter := s.Iteration
	s.ChainKey = next
	s.Iteration++
	ct, err := encryptAEAD(mk, plaintext, ad)
	if err != nil {
		return 0, nil, nil, err
	}
	sig := ed25519.Sign(s.Sign, senderSignInput(s.SeedID, iter, ct, ad))
	return iter, ct, sig, nil
}

func (r *ReceiveChain) Decrypt(iteration uint32, ciphertext, signature, ad []byte) ([]byte, error) {
	if !ed25519.Verify(r.SigningPub, senderSignInput(r.SeedID, iteration, ciphertext, ad), signature) {
		return nil, ErrBadSignature
	}
	if r.Skipped == nil {
		r.Skipped = map[uint32][]byte{}
	}
	if mk, ok := r.Skipped[iteration]; ok {
		delete(r.Skipped, iteration)
		return decryptAEAD(mk, ciphertext, ad)
	}
	if iteration < r.Iteration {
		return nil, ErrDecryptFailed
	}
	if r.Iteration+MaxSkip < iteration {
		return nil, ErrSkippedLimit
	}
	for r.Iteration < iteration {
		next, mk := senderKDF(r.ChainKey)
		r.Skipped[r.Iteration] = mk
		r.ChainKey = next
		r.Iteration++
	}
	next, mk := senderKDF(r.ChainKey)
	r.ChainKey = next
	r.Iteration++
	return decryptAEAD(mk, ciphertext, ad)
}

func NewReceiveChain(d SenderKeyDistribution) *ReceiveChain {
	return &ReceiveChain{
		SeedID:     d.SeedID,
		Iteration:  d.Iteration,
		ChainKey:   append([]byte(nil), d.ChainKey...),
		SigningPub: ed25519.PublicKey(append([]byte(nil), d.SigningPub...)),
		Skipped:    map[uint32][]byte{},
	}
}

func senderKDF(ck []byte) (nextCK, mk []byte) {
	mac := hmac.New(sha256.New, ck)
	mac.Write([]byte{0x01})
	mk = mac.Sum(nil)
	mac = hmac.New(sha256.New, ck)
	mac.Write([]byte{0x02})
	nextCK = mac.Sum(nil)
	return nextCK, mk
}

func senderSignInput(seedID, iter uint32, ct, ad []byte) []byte {
	buf := make([]byte, 0, 8+len(ct)+len(ad)+len(infoSender))
	buf = append(buf, []byte(infoSender)...)
	buf = binary.BigEndian.AppendUint32(buf, seedID)
	buf = binary.BigEndian.AppendUint32(buf, iter)
	buf = append(buf, ct...)
	buf = append(buf, ad...)
	return buf
}
