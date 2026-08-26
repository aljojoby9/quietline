package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Domain-separated HKDF info strings. Distinct from other Quietline HKDF uses
// and from libsignal's "Whisper*" labels — this is not wire-compatible with
// Signal Messenger; it follows the same algorithms.
const (
	infoX3DH    = "QuietlineX3DH"
	infoRoot    = "QuietlineRatchet"
	infoMessage = "QuietlineMessageKeys"
	infoSender  = "QuietlineSenderKeys"
	infoAttach  = "QuietlineAttachment"
)

// x3dhKDF implements the X3DH KDF: HKDF-SHA-256 with a 32-byte 0xFF prefix
// (X25519) concatenated onto the DH outputs. See X3DH §2.2 / §3.3.
func x3dhKDF(km []byte) ([]byte, error) {
	f := make([]byte, 32)
	for i := range f {
		f[i] = 0xFF
	}
	ikm := append(f, km...)
	salt := make([]byte, 32)
	r := hkdf.New(sha256.New, ikm, salt, []byte(infoX3DH))
	sk := make([]byte, 32)
	if _, err := io.ReadFull(r, sk); err != nil {
		return nil, err
	}
	return sk, nil
}

// kdfRK is Double Ratchet KDF_RK: HKDF-SHA-256 with salt=rk, ikm=dhOut.
func kdfRK(rk, dhOut []byte) (rootKey, chainKey []byte, err error) {
	r := hkdf.New(sha256.New, dhOut, rk, []byte(infoRoot))
	out := make([]byte, 64)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, nil, err
	}
	return out[:32], out[32:], nil
}

// kdfCK is Double Ratchet KDF_CK: HMAC-SHA-256 with constants 0x01 / 0x02.
func kdfCK(ck []byte) (nextCK, mk []byte) {
	mkMac := hmac.New(sha256.New, ck)
	mkMac.Write([]byte{0x01})
	mk = mkMac.Sum(nil)

	ckMac := hmac.New(sha256.New, ck)
	ckMac.Write([]byte{0x02})
	nextCK = ckMac.Sum(nil)
	return nextCK, mk
}

// encryptAEAD derives a ChaCha20-Poly1305 key+nonce from the message key
// (Double Ratchet §7.2 allows deriving the AEAD nonce from mk).
func encryptAEAD(mk, plaintext, ad []byte) ([]byte, error) {
	key, nonce, err := messageKeyMaterial(mk)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

func decryptAEAD(mk, ciphertext, ad []byte) ([]byte, error) {
	key, nonce, err := messageKeyMaterial(mk)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}

func messageKeyMaterial(mk []byte) (key, nonce []byte, err error) {
	salt := make([]byte, 32)
	r := hkdf.New(sha256.New, mk, salt, []byte(infoMessage))
	out := make([]byte, 32+12)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, nil, err
	}
	return out[:32], out[32:], nil
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
