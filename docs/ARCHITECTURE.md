# PlutoNetwork Architecture

## Trust model

The server is a **zero-knowledge relay**. It sees and stores:

- key packages (public key material, published by clients so others can invite them)
- ciphertext blobs queued for offline delivery
- routing metadata (who's connected, which group id a blob belongs to)

It can never read message content. All encryption/decryption happens on devices,
inside the Rust core. Losing the entire server database leaks no message content.

## Why MLS (RFC 9420)

Researched against Signal Protocol (X3DH + Double Ratchet) and raw libsodium.
Full multi-source fact-check was done before this repo existed; the short version:

- **IETF standard** (RFC 9420, Proposed Standard, July 2023) — Signal Protocol has no RFC
- **Forward secrecy + post-compromise security** for groups of 2 to thousands
- **log(N) group key updates** via TreeKEM — Signal-style sender keys need ~N² key
  update messages to recover post-compromise security in groups
- **OpenMLS is Rust** → compiles to WASM for web, binds to mobile via UniFFI.
  libsignal notably ships *no* official WASM/web binding (open feature request),
  which kills it for a web-first app
- 1:1 chats are just groups of 2 — one code path for everything

Tradeoff we accepted: MLS needs us to build our own Delivery Service (the relay).
Signal's ecosystem is more turnkey there, but the relay is the easy part.

## Layers

```
┌─────────────┐  ┌─────────────┐  ┌──────────────┐
│   Web UI    │  │  iOS UI     │  │  Android UI  │   thin, dumb UIs
│  (JS/TS)    │  │  (SwiftUI)  │  │  (Compose)   │
└──────┬──────┘  └──────┬──────┘  └──────┬───────┘
       │ wasm-bindgen   │ UniFFI         │ UniFFI
┌──────┴────────────────┴────────────────┴───────┐
│                plutonetwork-core (Rust)                │   ALL crypto + protocol
│       identity · groups · seal/open · MLS      │   state lives here
└──────────────────────┬─────────────────────────┘
                       │ ciphertext only
            ┌──────────┴──────────┐
            │   relay (Elixir)    │   zero-knowledge:
            │  WebSocket fan-out  │   key package directory,
            │  offline queues     │   ciphertext mailboxes
            └─────────────────────┘
```

## Message flow (happy path)

1. Bob publishes key packages to the relay (public material)
2. Alice fetches one, calls `invite()` → gets a **commit** (for existing members)
   and a **welcome** (for Bob), both opaque bytes
3. Relay queues the welcome for Bob, fans the commit out to the group
4. Bob's client calls `join(welcome)` → he's in, keys established
5. `send()` → ciphertext → relay → everyone's `recv()` → plaintext, locally only

## Backend choice

Elixir/BEAM relay, Rust NIFs only if a hotspot shows up (the Discord pattern —
they ran 12M+ concurrent users, 26M+ WebSocket events/sec on ~450 Elixir nodes).
Postgres first for storage; Scylla is a scale problem we're nowhere near having.

Transport: plain WebSocket. The only transport with production evidence at
messenger scale. QUIC/WebTransport can be revisited later.

## Client storage (planned)

- Mobile/desktop: SQLite + SQLCipher (encrypted at rest, key in platform keystore)
- Web: OPFS/IndexedDB with an encryption layer; weakest platform for at-rest
  storage, accepted tradeoff for web-first reach

## Known risks

- MLS implementations are younger than libsignal — pin OpenMLS, track advisories
- Browser at-rest storage is inherently weaker than mobile keystores
- This codebase is unaudited. Audit before any real-world use.
