# PlutoNetwork relay

Zero-knowledge relay with accounts. Stores password hashes, public key
packages and queued ciphertext — never message content.

Deliberately **not** Phoenix — there's no HTML here. Bandit + Plug + WebSock
is the whole stack, supervised by OTP. Accounts/key packages/mailboxes live
in DETS (disk, survives restarts); session tokens are ETS (clients just
sign in again after a restart).

## Run

```sh
mix deps.get
iex -S mix        # or: mix run --no-halt
# PORT=4001 to change port (default 4000)
```

## API

| Endpoint | Auth | What |
|----------|------|------|
| `POST /register` `{user, pass}` | — | create account → `{user, token}` |
| `POST /login` `{user, pass}` | — | sign in → `{user, token}` |
| `GET /me` | Bearer | validate a token → `{user}` |
| `POST /keypackages` `{key_package}` | Bearer | publish a key package (owner = token user) |
| `GET /keypackages/:user` | Bearer | fetch one — **consumes it** (one-time use) |
| `GET /ws?token=<token>` | token | WebSocket; queued mail is flushed on connect |
| `GET /health` | — | liveness |

Passwords: pbkdf2-sha256, 100k rounds, per-user salt (OTP `:crypto`, no NIF deps).
Names: `^[a-z0-9_]{2,24}$`.

WebSocket frames (JSON):

```jsonc
// send:    {"to": ["bob", "carol"], "blob": "<base64 ciphertext>", "kind": "msg" | "welcome"}
// receive: {"from": "alice", "blob": "<base64 ciphertext>", "kind": "..."}
// keepalive: {"ping": 1} (any frame resets the 5min idle timer)
```

The sender addresses recipients explicitly — MLS clients already know the
group roster, the server doesn't need to (and shouldn't).

## Test

```sh
node smoke.mjs   # needs node 22+, server running
```

## v1 honesty list

- tokens don't expire and live in memory only
- no rate limiting on register/login
- single node: Registry is local; clustering = pg/Horde later
- DETS is fine for now; swap for Postgres when concurrency demands it
