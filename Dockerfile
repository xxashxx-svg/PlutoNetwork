# ---- stage 1: compile the crypto core to wasm ----
FROM rust:1.88-slim AS wasm
RUN apt-get update -qq && apt-get install -y -qq curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl -sSfL https://github.com/rustwasm/wasm-pack/releases/download/v0.13.1/wasm-pack-v0.13.1-x86_64-unknown-linux-musl.tar.gz \
  | tar xz --strip-components=1 -C /usr/local/bin wasm-pack-v0.13.1-x86_64-unknown-linux-musl/wasm-pack
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN wasm-pack build crates/plutonetwork-wasm --target web --release --out-dir /out

# ---- stage 2: the relay, serving the web client ----
FROM elixir:1.17-slim
RUN apt-get update -qq && apt-get install -y -qq ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV MIX_ENV=prod
COPY server/mix.exs server/mix.lock ./
RUN mix local.hex --force && mix local.rebar --force && mix deps.get --only prod
COPY server/lib ./lib
RUN mix compile
COPY web/app ./static
COPY --from=wasm /out ./static/pkg
EXPOSE 4000
CMD ["mix", "run", "--no-halt"]
