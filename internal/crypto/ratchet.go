package crypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const MaxSkip = 1000

// Header is a Double Ratchet message header (unencrypted; spec §3).
type Header struct {
	DH []byte `json:"dh"`
	PN uint32 `json:"pn"`
	N  uint32 `json:"n"`
}

func (h Header) Marshal() []byte {
	buf := make([]byte, 0, KeySize+8)
	buf = append(buf, h.DH...)
	buf = binary.BigEndian.AppendUint32(buf, h.PN)
	buf = binary.BigEndian.AppendUint32(buf, h.N)
	return buf
}

func concatAD(ad []byte, h Header) []byte {
	// CONCAT(ad, header): length-prefix ad so the pair is uniquely parseable.
	buf := make([]byte, 0, 4+len(ad)+KeySize+8)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(ad)))
	buf = append(buf, ad...)
	buf = append(buf, h.Marshal()...)
	return buf
}

type skippedKey struct {
	DH []byte `json:"dh"`
	N  uint32 `json:"n"`
	MK []byte `json:"mk"`
}

// State is a Double Ratchet session. Zero CKs/CKr means "None" as in the spec.
type State struct {
	DHs       []byte       `json:"dhs"` // private
	DHsPub    []byte       `json:"dhs_pub"`
	DHr       []byte       `json:"dhr,omitempty"`
	RK        []byte       `json:"rk"`
	CKs       []byte       `json:"cks,omitempty"`
	CKr       []byte       `json:"ckr,omitempty"`
	Ns        uint32       `json:"ns"`
	Nr        uint32       `json:"nr"`
	PN        uint32       `json:"pn"`
	AD        []byte       `json:"ad"`
	MKSkipped []skippedKey `json:"mk_skipped,omitempty"`
}

func (s *State) clone() *State {
	cp := *s
	cp.DHs = bytesClone(s.DHs)
	cp.DHsPub = bytesClone(s.DHsPub)
	cp.DHr = bytesClone(s.DHr)
	cp.RK = bytesClone(s.RK)
	cp.CKs = bytesClone(s.CKs)
	cp.CKr = bytesClone(s.CKr)
	cp.AD = bytesClone(s.AD)
	if s.MKSkipped != nil {
		cp.MKSkipped = make([]skippedKey, len(s.MKSkipped))
		for i, k := range s.MKSkipped {
			cp.MKSkipped[i] = skippedKey{DH: bytesClone(k.DH), N: k.N, MK: bytesClone(k.MK)}
		}
	}
	return &cp
}

func bytesClone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

// InitAlice is RatchetInitAlice: SK from X3DH, bobDH is Bob's signed prekey.
func InitAlice(sk, bobDH, ad []byte) (*State, error) {
	dhs, err := GenerateDH()
	if err != nil {
		return nil, err
	}
	dhOut, err := DHBytes(dhs, bobDH)
	if err != nil {
		return nil, err
	}
	rk, cks, err := kdfRK(sk, dhOut)
	if err != nil {
		return nil, err
	}
	return &State{
		DHs:    dhs.Bytes(),
		DHsPub: dhs.PublicKey().Bytes(),
		DHr:    append([]byte(nil), bobDH...),
		RK:     rk,
		CKs:    cks,
		AD:     append([]byte(nil), ad...),
	}, nil
}

// InitBob is RatchetInitBob: SK from X3DH, bobDHPair is Bob's signed prekey pair.
func InitBob(sk []byte, bobDH *ecdh.PrivateKey, ad []byte) *State {
	return &State{
		DHs:    bobDH.Bytes(),
		DHsPub: bobDH.PublicKey().Bytes(),
		RK:     append([]byte(nil), sk...),
		AD:     append([]byte(nil), ad...),
	}
}

func (s *State) Encrypt(plaintext []byte) (Header, []byte, error) {
	if len(s.CKs) != KeySize {
		return Header{}, nil, ErrNoSession
	}
	next, mk := kdfCK(s.CKs)
	s.CKs = next
	h := Header{DH: bytesClone(s.DHsPub), PN: s.PN, N: s.Ns}
	s.Ns++
	ct, err := encryptAEAD(mk, plaintext, concatAD(s.AD, h))
	if err != nil {
		return Header{}, nil, err
	}
	return h, ct, nil
}

func (s *State) Decrypt(h Header, ciphertext []byte) ([]byte, error) {
	saved := s.clone()
	pt, err := s.decrypt(h, ciphertext)
	if err != nil {
		*s = *saved
		return nil, err
	}
	return pt, nil
}

func (s *State) decrypt(h Header, ciphertext []byte) ([]byte, error) {
	if len(h.DH) != KeySize {
		return nil, ErrBadHeader
	}
	if mk := s.takeSkipped(h); mk != nil {
		return decryptAEAD(mk, ciphertext, concatAD(s.AD, h))
	}
	if !bytes.Equal(h.DH, s.DHr) {
		if err := s.skipMessageKeys(h.PN); err != nil {
			return nil, err
		}
		if err := s.dhRatchet(h); err != nil {
			return nil, err
		}
	}
	if err := s.skipMessageKeys(h.N); err != nil {
		return nil, err
	}
	if len(s.CKr) != KeySize {
		return nil, ErrNoSession
	}
	next, mk := kdfCK(s.CKr)
	s.CKr = next
	s.Nr++
	return decryptAEAD(mk, ciphertext, concatAD(s.AD, h))
}

func (s *State) takeSkipped(h Header) []byte {
	for i, k := range s.MKSkipped {
		if k.N == h.N && bytes.Equal(k.DH, h.DH) {
			mk := k.MK
			s.MKSkipped = append(s.MKSkipped[:i], s.MKSkipped[i+1:]...)
			return mk
		}
	}
	return nil
}

func (s *State) skipMessageKeys(until uint32) error {
	if s.Nr+MaxSkip < until {
		return ErrSkippedLimit
	}
	if len(s.CKr) != KeySize {
		return nil
	}
	for s.Nr < until {
		next, mk := kdfCK(s.CKr)
		s.CKr = next
		s.MKSkipped = append(s.MKSkipped, skippedKey{DH: bytesClone(s.DHr), N: s.Nr, MK: mk})
		s.Nr++
		if len(s.MKSkipped) > MaxSkip {
			return ErrSkippedLimit
		}
	}
	return nil
}

func (s *State) dhRatchet(h Header) error {
	dhs, err := PrivateFromBytes(s.DHs)
	if err != nil {
		return err
	}
	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0
	s.DHr = bytesClone(h.DH)

	dhOut, err := DHBytes(dhs, s.DHr)
	if err != nil {
		return err
	}
	rk, ckr, err := kdfRK(s.RK, dhOut)
	if err != nil {
		return err
	}
	s.RK, s.CKr = rk, ckr

	newDH, err := GenerateDH()
	if err != nil {
		return err
	}
	s.DHs = newDH.Bytes()
	s.DHsPub = newDH.PublicKey().Bytes()
	dhOut2, err := DHBytes(newDH, s.DHr)
	if err != nil {
		return err
	}
	rk, cks, err := kdfRK(s.RK, dhOut2)
	if err != nil {
		return err
	}
	s.RK, s.CKs = rk, cks
	return nil
}

func (s *State) MarshalJSON() ([]byte, error) {
	type alias State
	return json.Marshal((*alias)(s))
}

func (s *State) UnmarshalJSON(b []byte) error {
	type alias State
	return json.Unmarshal(b, (*alias)(s))
}

func (s *State) Dump() ([]byte, error) {
	return json.Marshal(s)
}

func LoadState(b []byte) (*State, error) {
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("ratchet state: %w", err)
	}
	return &s, nil
}
