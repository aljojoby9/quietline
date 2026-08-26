package protocol

import qlcrypto "github.com/aljojoby9/quietline/internal/crypto"

// Envelope is what the relay stores and forwards. Body is opaque ciphertext
// (a PreKeyMessage or RatchetMessage JSON). The relay does not parse Body
// beyond the Kind field the client sets for routing.
type Envelope struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	DeviceID  int    `json:"device_id"`
	Kind      string `json:"kind"` // prekey, message, group
	GroupID   string `json:"group_id,omitempty"`
	Body      []byte `json:"body"`
	CreatedAt string `json:"created_at"`
}

const (
	KindPrekey  = "prekey"
	KindMessage = "message"
	KindGroup   = "group"
)

type RegisterRequest struct {
	Username     string         `json:"username"`
	Password     string         `json:"password"`
	IdentityDH   []byte         `json:"identity_dh"`
	IdentitySign []byte         `json:"identity_sign"`
	SignedPreKey PublicPreKey   `json:"signed_prekey"`
	OneTime      []PublicPreKey `json:"one_time_prekeys"`
}

type PublicPreKey struct {
	ID        uint32 `json:"id"`
	Public    []byte `json:"public"`
	Signature []byte `json:"signature,omitempty"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

type PreKeyBundle struct {
	Username     string        `json:"username"`
	IdentityDH   []byte        `json:"identity_dh"`
	IdentitySign []byte        `json:"identity_sign"`
	SignedPreKey PublicPreKey  `json:"signed_prekey"`
	OneTime      *PublicPreKey `json:"one_time_prekey,omitempty"`
}

type UploadKeysRequest struct {
	SignedPreKey *PublicPreKey  `json:"signed_prekey,omitempty"`
	OneTime      []PublicPreKey `json:"one_time_prekeys,omitempty"`
}

type MeResponse struct {
	Username     string `json:"username"`
	IdentityDH   []byte `json:"identity_dh"`
	IdentitySign []byte `json:"identity_sign"`
	OTKCount     int    `json:"otk_count"`
	SignedID     uint32 `json:"signed_prekey_id"`
}

type SendRequest struct {
	Recipient string `json:"recipient,omitempty"`
	GroupID   string `json:"group_id,omitempty"`
	Kind      string `json:"kind"`
	Body      []byte `json:"body"`
}

type SendResponse struct {
	IDs []string `json:"ids"`
}

type SyncResponse struct {
	Envelopes []Envelope `json:"envelopes"`
}

type AckRequest struct {
	IDs []string `json:"ids"`
}

type CreateGroupRequest struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

type GroupInfo struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Creator string   `json:"creator"`
	Members []string `json:"members"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type UserInfo struct {
	Username     string `json:"username"`
	IdentityDH   []byte `json:"identity_dh"`
	IdentitySign []byte `json:"identity_sign"`
}

// Ciphertext is the client-side body of a 1:1 envelope.
type Ciphertext struct {
	Type            string          `json:"type"` // prekey | message
	IdentityDH      []byte          `json:"identity_dh,omitempty"`
	IdentitySign    []byte          `json:"identity_sign,omitempty"`
	Ephemeral       []byte          `json:"ephemeral,omitempty"`
	SignedPreKeyID  uint32          `json:"spk_id,omitempty"`
	OneTimePreKeyID *uint32         `json:"otk_id,omitempty"`
	Header          qlcrypto.Header `json:"header"`
	Ciphertext      []byte          `json:"ciphertext"`
}

type GroupCiphertext struct {
	GroupID    string `json:"group_id"`
	Sender     string `json:"sender"`
	SeedID     uint32 `json:"seed_id"`
	Iteration  uint32 `json:"iteration"`
	SigningPub []byte `json:"signing_pub"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  []byte `json:"signature"`
}

type WSMessage struct {
	Op       string    `json:"op"`
	Envelope *Envelope `json:"envelope,omitempty"`
	IDs      []string  `json:"ids,omitempty"`
	Error    string    `json:"error,omitempty"`
}
