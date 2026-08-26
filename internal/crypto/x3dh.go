package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
)

// Bundle is the public prekey material a client publishes for others to
// start a session. The server hands out at most one one-time prekey per fetch
// and deletes it.
type Bundle struct {
	Identity PublicIdentity
	Signed   PublicPreKey
	OneTime  *PublicPreKey // optional
}

type PublicPreKey struct {
	ID        uint32
	Public    []byte
	Signature []byte
}

// InitialMessage is what Alice sends alongside her first Double Ratchet
// ciphertext so Bob can run X3DH without a round trip.
type InitialMessage struct {
	IdentityDH      []byte
	IdentitySign    []byte
	Ephemeral       []byte
	SignedPreKeyID  uint32
	OneTimePreKeyID *uint32
}

// InitiateX3DH is Alice's side. Returns SK, AD, and the initial-message
// fields Bob needs. The ephemeral private key is discarded.
func InitiateX3DH(alice *Identity, bundle Bundle) (sk, ad []byte, init InitialMessage, err error) {
	if err := VerifySignedPreKey(bundle.Identity.Sign, bundle.Signed.ID, bundle.Signed.Public, bundle.Signed.Signature); err != nil {
		return nil, nil, InitialMessage{}, err
	}
	ek, err := GenerateDH()
	if err != nil {
		return nil, nil, InitialMessage{}, err
	}
	var opkb []byte
	if bundle.OneTime != nil {
		opkb = bundle.OneTime.Public
	}
	sk, err = x3dhAlice(alice.DH, ek, bundle.Identity.DH, bundle.Signed.Public, opkb)
	if err != nil {
		return nil, nil, InitialMessage{}, err
	}
	ad = EncodeAD(alice.Public(), bundle.Identity)
	init = InitialMessage{
		IdentityDH:     alice.Public().DH,
		IdentitySign:   alice.Public().Sign,
		Ephemeral:      ek.PublicKey().Bytes(),
		SignedPreKeyID: bundle.Signed.ID,
	}
	if bundle.OneTime != nil {
		id := bundle.OneTime.ID
		init.OneTimePreKeyID = &id
	}
	return sk, ad, init, nil
}

// CompleteX3DH is Bob's side. spkPriv is the private key for the signed
// prekey Alice cited; otkPriv is nil if she did not use a one-time prekey.
func CompleteX3DH(bob *Identity, spkPriv *ecdh.PrivateKey, otkPriv *ecdh.PrivateKey, msg InitialMessage) (sk, ad []byte, err error) {
	if len(msg.IdentityDH) != KeySize || len(msg.Ephemeral) != KeySize {
		return nil, nil, ErrInvalidKey
	}
	if len(msg.IdentitySign) != ed25519.PublicKeySize {
		return nil, nil, ErrInvalidKey
	}
	ekPub, err := PublicFromBytes(msg.Ephemeral)
	if err != nil {
		return nil, nil, err
	}
	alicePub, err := PublicFromBytes(msg.IdentityDH)
	if err != nil {
		return nil, nil, err
	}
	sk, err = x3dhBob(bob.DH, spkPriv, otkPriv, alicePub, ekPub)
	if err != nil {
		return nil, nil, err
	}
	alice := PublicIdentity{
		DH:   append([]byte(nil), msg.IdentityDH...),
		Sign: ed25519.PublicKey(append([]byte(nil), msg.IdentitySign...)),
	}
	ad = EncodeAD(alice, bob.Public())
	return sk, ad, nil
}

func x3dhAlice(ika, eka *ecdh.PrivateKey, ikb, spkb, opkb []byte) ([]byte, error) {
	dh1, err := DHBytes(ika, spkb)
	if err != nil {
		return nil, fmt.Errorf("dh1: %w", err)
	}
	dh2, err := DHBytes(eka, ikb)
	if err != nil {
		return nil, fmt.Errorf("dh2: %w", err)
	}
	dh3, err := DHBytes(eka, spkb)
	if err != nil {
		return nil, fmt.Errorf("dh3: %w", err)
	}
	km := concat(dh1, dh2, dh3)
	if len(opkb) == KeySize {
		dh4, err := DHBytes(eka, opkb)
		if err != nil {
			return nil, fmt.Errorf("dh4: %w", err)
		}
		km = concat(km, dh4)
	}
	return x3dhKDF(km)
}

func x3dhBob(ikb, spkb, opkb *ecdh.PrivateKey, ika, eka *ecdh.PublicKey) ([]byte, error) {
	dh1, err := DH(spkb, ika)
	if err != nil {
		return nil, fmt.Errorf("dh1: %w", err)
	}
	dh2, err := DH(ikb, eka)
	if err != nil {
		return nil, fmt.Errorf("dh2: %w", err)
	}
	dh3, err := DH(spkb, eka)
	if err != nil {
		return nil, fmt.Errorf("dh3: %w", err)
	}
	km := concat(dh1, dh2, dh3)
	if opkb != nil {
		dh4, err := DH(opkb, eka)
		if err != nil {
			return nil, fmt.Errorf("dh4: %w", err)
		}
		km = concat(km, dh4)
	}
	return x3dhKDF(km)
}

// EncodeAD is X3DH associated data: Encode(IKA) || Encode(IKB), covering
// both the DH and signing halves of each identity.
func EncodeAD(alice, bob PublicIdentity) []byte {
	out := make([]byte, 0, 2*KeySize+2*ed25519.PublicKeySize)
	out = append(out, alice.DH...)
	out = append(out, alice.Sign...)
	out = append(out, bob.DH...)
	out = append(out, bob.Sign...)
	return out
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
