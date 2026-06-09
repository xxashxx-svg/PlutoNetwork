# veil relay

Zero-knowledge relay. Stores public key packages, queues ciphertext for
offline users, fans messages out over WebSocket. Cannot read anything.

Deliberately **not** Phoenix — there's no HTML here. Bandit + Plug + WebSock
is the whole stack, supervised by OTP.

## Run

```sh
mix deps.get
iex -S mix        # or: mix run --no-halt
# PORT=4001 to change port (default 4000)
```

## API

| Endpoint | What |
|----------|------|
| `POST /keypackages` `{user, key_package}` | publish a key package (base64) |
| `GET /keypackages/:user` | fetch one — **consumes it** (one-time use) |
| `GET /ws?user=<id>` | WebSocket connect; queued mail is flushed on connect |
| `GET /health` | liveness |

WebSocket frames (JSON):

```jsonc
// send:    {"to": ["bob", "carol"], "blob": "<base64 ciphertext>"}
// receive: {"from": "alice", "blob": "<base64 ciphertext>"}
```

The sender addresses recipients explicitly — MLS clients already know the
group roster, the server doesn't need to (and shouldn't).

## v1 honesty list

- ETS only: queued mail dies on restart (it's ciphertext; confidentiality
  is never at risk — durability needs the Postgres swap)
- no auth yet: anyone can claim any user id — identity binding comes with
  credential verification in the client + signed key packages
- single node: Registry is local; clustering = pg/Horde later
