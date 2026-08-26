# protocol

Relay is a sealed store-and-forward. It sees usernames, group membership, and
opaque envelope bodies. It does not see message keys.

## HTTP

| method | path | auth | notes |
| --- | --- | --- | --- |
| GET | /healthz | no | |
| POST | /v1/register | no | identity pubs + signed prekey + one-time pubs |
| POST | /v1/login | no | returns bearer token |
| GET | /v1/me | yes | otk count, identity pubs |
| GET | /v1/users/{name} | yes | identity pubs, does not consume a prekey |
| GET | /v1/keys/{name} | yes | prekey bundle; pops one one-time prekey |
| PUT | /v1/keys | yes | upload more OTKs / rotate signed prekey |
| POST | /v1/envelopes | yes | 1:1 or group fan-out of ciphertext |
| GET | /v1/envelopes | yes | unacked inbox |
| POST | /v1/envelopes/ack | yes | |
| POST | /v1/groups | yes | membership only |
| GET | /v1/groups/{id} | yes | members |
| GET | /v1/ws | yes (query token) | live envelopes + ack/ping |

## Body

1:1 `protocol.Ciphertext`: `type=prekey` carries X3DH (IK, EK, SPK id, OTK id)
plus a Double Ratchet header+ciphertext. `type=message` is header+ciphertext only.

Group `protocol.GroupCiphertext`: sender-key iteration, ciphertext, Ed25519
signature. The chain key is distributed as an inner 1:1 payload (`kind=skdm`).

Inner plaintext is `crypto.Payload` JSON (text / receipt / skdm / group-text).

## Crypto

X3DH and the Double Ratchet follow the specs (HKDF-SHA-256, HMAC chain keys,
ChaCha20-Poly1305). Domain strings are Quietline's; this is not wire-compatible
with Signal Messenger.
