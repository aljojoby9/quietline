package crypto

import (
	"encoding/json"
	"time"
)

// Inner payloads are what the Double Ratchet encrypts. Delivery receipts
// are themselves encrypted payloads — the server only sees another envelope.
const (
	KindText    = "text"
	KindReceipt = "receipt"
	KindSKDM    = "skdm"
	KindGroup   = "group-text"
)

type Payload struct {
	V       int                    `json:"v"`
	Kind    string                 `json:"kind"`
	ID      string                 `json:"id"`
	TS      int64                  `json:"ts"`
	Body    string                 `json:"body,omitempty"`
	Ref     string                 `json:"ref,omitempty"`
	Status  string                 `json:"status,omitempty"`
	GroupID string                 `json:"group_id,omitempty"`
	SKDM    *SenderKeyDistribution `json:"skdm,omitempty"`
}

func NewText(id, body string) Payload {
	return Payload{V: 1, Kind: KindText, ID: id, TS: time.Now().UnixMilli(), Body: body}
}

func NewReceipt(id, ref, status string) Payload {
	return Payload{V: 1, Kind: KindReceipt, ID: id, TS: time.Now().UnixMilli(), Ref: ref, Status: status}
}

func NewSKDM(id, groupID string, d SenderKeyDistribution) Payload {
	d.GroupID = groupID
	return Payload{V: 1, Kind: KindSKDM, ID: id, TS: time.Now().UnixMilli(), GroupID: groupID, SKDM: &d}
}

func NewGroupText(id, groupID, body string) Payload {
	return Payload{V: 1, Kind: KindGroup, ID: id, TS: time.Now().UnixMilli(), GroupID: groupID, Body: body}
}

func (p Payload) Marshal() ([]byte, error) { return json.Marshal(p) }

func UnmarshalPayload(b []byte) (Payload, error) {
	var p Payload
	err := json.Unmarshal(b, &p)
	return p, err
}
