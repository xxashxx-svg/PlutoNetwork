# Security

## Current status: UNAUDITED

PlutoNetwork has not had a third-party security audit. Until it does, treat it as a
research project — do not rely on it for anything sensitive.

What we do claim today:

- all message content is encrypted client-side with MLS (RFC 9420) via OpenMLS
- the relay only ever handles public key packages and ciphertext
- no telemetry, no analytics, nothing phones home

What we explicitly do NOT claim yet:

- metadata protection (the relay sees who talks to whom and when)
- identity verification (key packages aren't bound to verified identities yet)
- resistance to a malicious relay actively dropping/reordering commits

## Reporting a vulnerability

Open a private security advisory on the repo (preferred) or email the
maintainer. Please don't open public issues for vulns before a fix exists.
