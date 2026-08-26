package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestX3DHAndRatchetRoundTrip(t *testing.T) {
	alice := mustIdentity(t)
	bob := mustIdentity(t)
	spk, err := NewSignedPreKey(bob, 1)
	if err != nil {
		t.Fatal(err)
	}
	otk, err := NewOneTimePreKey(7)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{
		Identity: bob.Public(),
		Signed:   PublicPreKey{ID: spk.ID, Public: spk.Public, Signature: spk.Signature},
		OneTime:  &PublicPreKey{ID: otk.ID, Public: otk.Public},
	}

	skA, adA, init, err := InitiateX3DH(alice, bundle)
	if err != nil {
		t.Fatal(err)
	}
	skB, adB, err := CompleteX3DH(bob, spk.Private, otk.Private, init)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skA, skB) {
		t.Fatal("X3DH SK mismatch")
	}
	if !bytes.Equal(adA, adB) {
		t.Fatal("X3DH AD mismatch")
	}

	sessA, err := InitAlice(skA, spk.Public, adA)
	if err != nil {
		t.Fatal(err)
	}
	sessB := InitBob(skB, spk.Private, adB)

	h, ct, err := sessA.Encrypt([]byte("hello bob"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := sessB.Decrypt(h, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello bob" {
		t.Fatalf("got %q", pt)
	}

	h, ct, err = sessB.Encrypt([]byte("hi alice"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err = sessA.Decrypt(h, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hi alice" {
		t.Fatalf("got %q", pt)
	}
}

func TestX3DHWithoutOneTime(t *testing.T) {
	alice := mustIdentity(t)
	bob := mustIdentity(t)
	spk, err := NewSignedPreKey(bob, 2)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{
		Identity: bob.Public(),
		Signed:   PublicPreKey{ID: spk.ID, Public: spk.Public, Signature: spk.Signature},
	}
	skA, _, init, err := InitiateX3DH(alice, bundle)
	if err != nil {
		t.Fatal(err)
	}
	skB, _, err := CompleteX3DH(bob, spk.Private, nil, init)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skA, skB) {
		t.Fatal("SK mismatch without OTK")
	}
}

func TestSignedPreKeyRejectsForgery(t *testing.T) {
	alice := mustIdentity(t)
	bob := mustIdentity(t)
	spk, err := NewSignedPreKey(bob, 1)
	if err != nil {
		t.Fatal(err)
	}
	spk.Signature[0] ^= 0xff
	bundle := Bundle{
		Identity: bob.Public(),
		Signed:   PublicPreKey{ID: spk.ID, Public: spk.Public, Signature: spk.Signature},
	}
	if _, _, _, err := InitiateX3DH(alice, bundle); err == nil {
		t.Fatal("forged signed prekey accepted")
	}
}

func TestOutOfOrderAndSkippedKeys(t *testing.T) {
	a, b := paired(t)
	type msg struct {
		h  Header
		ct []byte
	}
	var sent []msg
	for i := 0; i < 5; i++ {
		h, ct, err := a.Encrypt([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		sent = append(sent, msg{h, ct})
	}
	// Deliver 0, 4, 2, 1, 3
	order := []int{0, 4, 2, 1, 3}
	for _, i := range order {
		pt, err := b.Decrypt(sent[i].h, sent[i].ct)
		if err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
		if pt[0] != byte(i) {
			t.Fatalf("want %d got %d", i, pt[0])
		}
	}
}

func TestForwardSecrecyMessageKeysDeleted(t *testing.T) {
	a, b := paired(t)
	h, ct, err := a.Encrypt([]byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decrypt(h, ct); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decrypt(h, ct); err == nil {
		t.Fatal("replay of consumed message key succeeded")
	}
}

func TestDHRatchetPingPong(t *testing.T) {
	a, b := paired(t)
	for i := 0; i < 8; i++ {
		h, ct, err := a.Encrypt([]byte("a"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Decrypt(h, ct); err != nil {
			t.Fatal(err)
		}
		h, ct, err = b.Encrypt([]byte("b"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Decrypt(h, ct); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDecryptFailureDoesNotAdvanceState(t *testing.T) {
	a, b := paired(t)
	h, ct, err := a.Encrypt([]byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0x01
	ns := b.Ns
	nr := b.Nr
	if _, err := b.Decrypt(h, ct); err == nil {
		t.Fatal("tamper accepted")
	}
	if b.Ns != ns || b.Nr != nr {
		t.Fatal("state advanced on failed decrypt")
	}
}

func TestCannotDecryptWithoutRecipientState(t *testing.T) {
	a, b := paired(t)
	h, ct, err := a.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// A third party with only the ciphertext and public header.
	blank := &State{AD: b.AD}
	if _, err := blank.Decrypt(h, ct); err == nil {
		t.Fatal("decrypted with empty state")
	}
	// Even Alice's sending state cannot decrypt her own ciphertext
	// (CKr is empty / different chain).
	if _, err := a.Decrypt(h, ct); err == nil {
		t.Fatal("sender decrypted own ciphertext with sending chain")
	}
}

func TestSenderKeysOutOfOrder(t *testing.T) {
	sk, err := NewSenderKey()
	if err != nil {
		t.Fatal(err)
	}
	recv := NewReceiveChain(sk.Distribution("g1"))
	ad := []byte("g1")
	var cts []struct {
		iter    uint32
		ct, sig []byte
	}
	for i := 0; i < 4; i++ {
		iter, ct, sig, err := sk.Encrypt([]byte{byte('A' + i)}, ad)
		if err != nil {
			t.Fatal(err)
		}
		cts = append(cts, struct {
			iter    uint32
			ct, sig []byte
		}{iter, ct, sig})
	}
	order := []int{0, 3, 1, 2}
	for _, i := range order {
		pt, err := recv.Decrypt(cts[i].iter, cts[i].ct, cts[i].sig, ad)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if pt[0] != byte('A'+i) {
			t.Fatalf("want %c got %c", 'A'+i, pt[0])
		}
	}
}

func TestSenderKeyRejectsBadSignature(t *testing.T) {
	sk, err := NewSenderKey()
	if err != nil {
		t.Fatal(err)
	}
	recv := NewReceiveChain(sk.Distribution("g"))
	_, ct, sig, err := sk.Encrypt([]byte("x"), []byte("g"))
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	if _, err := recv.Decrypt(0, ct, sig, []byte("g")); err == nil {
		t.Fatal("bad group signature accepted")
	}
}

func TestSafetyNumberStableAndSymmetric(t *testing.T) {
	a := mustIdentity(t)
	b := mustIdentity(t)
	n1 := SafetyNumber(a.Public(), b.Public(), "alice", "bob")
	n2 := SafetyNumber(b.Public(), a.Public(), "bob", "alice")
	if n1 != n2 {
		t.Fatalf("not symmetric:\n%s\n%s", n1, n2)
	}
	if n1 == SafetyNumber(a.Public(), b.Public(), "alice", "eve") {
		t.Fatal("username not bound")
	}
	if len(n1) < 20 {
		t.Fatalf("too short: %q", n1)
	}
}

func TestIdentitySignRoundTrip(t *testing.T) {
	id := mustIdentity(t)
	spk, err := NewSignedPreKey(id, 9)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedPreKey(id.Public().Sign, 9, spk.Public, spk.Signature); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedPreKey(id.Public().Sign, 8, spk.Public, spk.Signature); err == nil {
		t.Fatal("wrong id accepted")
	}
	_ = ed25519.PublicKey(id.Public().Sign)
}

func mustIdentity(t *testing.T) *Identity {
	t.Helper()
	seed, err := GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	id, err := DeriveIdentity(seed)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func paired(t *testing.T) (*State, *State) {
	t.Helper()
	alice := mustIdentity(t)
	bob := mustIdentity(t)
	spk, err := NewSignedPreKey(bob, 1)
	if err != nil {
		t.Fatal(err)
	}
	otk, err := NewOneTimePreKey(1)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{
		Identity: bob.Public(),
		Signed:   PublicPreKey{ID: 1, Public: spk.Public, Signature: spk.Signature},
		OneTime:  &PublicPreKey{ID: 1, Public: otk.Public},
	}
	skA, adA, init, err := InitiateX3DH(alice, bundle)
	if err != nil {
		t.Fatal(err)
	}
	skB, adB, err := CompleteX3DH(bob, spk.Private, otk.Private, init)
	if err != nil {
		t.Fatal(err)
	}
	a, err := InitAlice(skA, spk.Public, adA)
	if err != nil {
		t.Fatal(err)
	}
	b := InitBob(skB, spk.Private, adB)
	return a, b
}
