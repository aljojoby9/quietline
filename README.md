# quietline

I wanted a messenger whose crypto I could actually read. Not a Signal
fork, not a toy that AES-wraps a JSON blob and calls it E2E.

Sessions start with X3DH. After that the Double Ratchet (DH ratchet +
symmetric chains + skipped-message keys). Groups use sender keys,
distributed over the 1:1 ratchets. The relay stores envelopes. It does
not get a key that would open one.

Name stays quietline. License is AGPL-3.0.

## Threat model

**In scope.** A honest-but-curious relay: it sees who talks to whom, when,
group membership, and ciphertext size. It must not recover plaintext,
message keys, or identity private keys. Compromise of the server after a
message is delivered should not decrypt that message (forward secrecy of
the ratchet). Safety numbers bind both halves of each identity (X25519 +
Ed25519) and the usernames.

**Out of scope.** A compromised client. A compromised device. Metadata
hiding (no mixnet, no sealed sender). Multi-device. Password-reset that
preserves identity (there isn't one: the seed never leaves the client
home directory). An active attacker who can MITM the first prekey fetch
and you never compare safety numbers. Quantum computers.

**Passwords** only gate the relay account. They are not the identity.
Steal `account.json` and you steal the user.

## Two-terminal demo

Terminal 1, the relay (sqlite, no docker):

```
go run ./cmd/server
```

Or the whole stack:

```
docker compose up --build
```

Terminal 1, alice:

```
export QL_SERVER=http://127.0.0.1:8080
export QL_HOME=/tmp/ql-alice
go run ./cmd/ql register alice password1
go run ./cmd/ql listen
```

Terminal 2, bob:

```
export QL_SERVER=http://127.0.0.1:8080
export QL_HOME=/tmp/ql-bob
go run ./cmd/ql register bob password1
go run ./cmd/ql send alice hello from bob
go run ./cmd/ql safety alice
```

Alice's listen prints `bob: hello from bob`. Compare safety numbers —
alice runs `ql safety bob`, they must match.

Offline: skip listen. Bob sends. Alice later runs `ql recv`.

Groups (optional):

```
go run ./cmd/ql group-create room bob
go run ./cmd/ql group-send <id> hello group
```

`scripts/demo.sh` does the offline path in one shot.

## Layout

| path | what |
| --- | --- |
| `internal/crypto` | X3DH, Double Ratchet, sender keys, safety numbers |
| `internal/protocol` | wire types. Body is opaque to the server |
| `internal/server` | HTTP+WebSocket relay, sqlite or postgres |
| `internal/client` | identity, sessions, API+WS. Keys stay here |
| `cmd/server` | relay |
| `cmd/ql` | CLI |

Env: `QUIETLINE_DSN` (`sqlite:quietline.db` or a `postgres://` URL),
`QUIETLINE_LISTEN`, `QL_HOME`, `QL_SERVER`. See `.env.example`.

`go test ./...` covers the ratchet and a sealed-relay proof: the store
sees ciphertext, the recipient sees the secret.
