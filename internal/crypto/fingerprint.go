package crypto

import (
	"crypto/sha512"
	"fmt"
	"strings"
)

// SafetyNumber is a 60-digit fingerprint of two identities, in the spirit
// of Signal's numeric safety numbers (iterated SHA-512). It is not
// interchangeable with Signal Messenger's display format.
func SafetyNumber(local, remote PublicIdentity, localName, remoteName string) string {
	a := formatDigits(fingerprint(local, localName))
	b := formatDigits(fingerprint(remote, remoteName))
	if a > b {
		a, b = b, a
	}
	return a + "  " + b
}

func fingerprint(id PublicIdentity, name string) []byte {
	h := sha512.New()
	var digest []byte
	idBytes := append(append([]byte{}, id.DH...), id.Sign...)
	nameBytes := []byte(strings.ToLower(name))
	for i := 0; i < 5200; i++ {
		h.Reset()
		if i == 0 {
			h.Write([]byte{0x00})
			h.Write(idBytes)
			h.Write(nameBytes)
		} else {
			h.Write(digest)
			h.Write(idBytes)
		}
		digest = h.Sum(nil)
	}
	return digest
}

func formatDigits(digest []byte) string {
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		off := i * 5
		chunk := uint64(digest[off])<<32 |
			uint64(digest[off+1])<<24 |
			uint64(digest[off+2])<<16 |
			uint64(digest[off+3])<<8 |
			uint64(digest[off+4])
		parts[i] = fmt.Sprintf("%05d", chunk%100000)
	}
	return strings.Join(parts, " ")
}
