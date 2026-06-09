# Veil

Open-source end-to-end encrypted messenger. Web first, mobile next, one shared crypto core.

> ⚠️ **Status: early development.** The crypto engine works but nothing here has been audited. Do not trust it with real secrets yet.

## How it's built

The whole design philosophy: write the hard part (crypto + protocol) **once** in Rust, keep everything else thin.

| Layer | Choice | Why |
|-------|--------|-----|
| E2EE protocol | **MLS (RFC 9420)** via [OpenMLS](https://github.com/openmls/openmls) | IETF standard, forward secrecy + post-compromise security, group keys scale log(N) |
| Crypto core | **Rust** (`crates/veil-core`) | Same architecture Signal (libsignal) and Element (matrix-rust-sdk) ship in production |
| Web | Rust core compiled to **WASM** + lightweight UI | Crypto never reimplemented in JS |
| Mobile (planned) | Same core via **UniFFI** → Swift/Kotlin, native UIs | The Element X playbook |
| Relay server (planned) | **Elixir/Phoenix** | BEAM is the proven runtime for massive real-time messaging (Discord: 12M+ concurrent on it) |
| Transport | WebSocket | Boring and battle-tested |

The server is a **zero-knowledge relay**: it stores key packages (public) and routes/queues ciphertext. It can never read messages.

## Repo layout

```
crates/
  veil-core/   # MLS engine — identity, groups, encrypt/decrypt
  veil-wasm/   # wasm-bindgen bridge for the web client
server/        # Elixir relay (phase 2)
web/           # web client (phase 3)
docs/          # architecture notes
```

## Quick start

```sh
cargo test -p veil-core        # run the crypto round-trip tests
wasm-pack build crates/veil-wasm --target web   # build the wasm bundle
```

## Roadmap

- [x] Stack research (multi-source, fact-checked — see docs/ARCHITECTURE.md)
- [ ] Phase 1: Rust core wrapping OpenMLS + WASM bridge
- [ ] Phase 2: Elixir relay — key package directory, ciphertext queue, WebSocket fan-out
- [ ] Phase 3: Web client with encrypted local storage
- [ ] Phase 4: iOS/Android via UniFFI bindings
- [ ] Security audit before anyone uses this for real

## License

AGPL-3.0 (planned — file pending). Server and clients stay open, forks stay open.
