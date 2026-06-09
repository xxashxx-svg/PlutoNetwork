# Contributing

PRs welcome. Ground rules, kept short:

- **crypto changes need extra scrutiny** — anything touching `veil-core`
  gets a slower, pickier review than UI work. That's a feature.
- don't reimplement crypto in JS/Swift/Kotlin. If a platform needs a
  primitive, it goes in the Rust core and gets exposed through bindings.
- `cargo test` and `cargo clippy` clean before pushing
- keep the relay dumb. If a feature requires the server to understand
  message content, the design is wrong.

## Dev setup

- Rust (stable) + `wasm-pack` for the core
- Elixir ≥ 1.15 for the relay
- Node for the web client

See README for the build commands.
