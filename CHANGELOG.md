# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-02

First public release: the Diffie-Hellman case study, from the honest key
exchange to an encrypted channel compromised by the Young–Yung SETUP.

### Library (`kleptography.math`, `kleptography.crypto`)

- Number theory: modular exponentiation and inverse, safe primes and
  generators of the prime-order subgroup.
- Honest finite-field Diffie-Hellman over safe-prime groups: validated
  parameters, toy groups (labelled insecure) and the RFC 7919 groups
  FFDHE2048 to FFDHE8192, a participant with generated or loaded keys, and
  a five-phase exchange traced as a timeline of events.
- Young–Yung SETUP on Diffie-Hellman (EUROCRYPT '97): a backdoored device
  that is a drop-in replacement for the honest participant, and the
  attacker that recovers the next private exponent and shared secret from
  public values alone. Every intermediate value is exposed through
  immutable records.
- Primitives from `pyca/cryptography`: the NIST SP 800-56C one-step KDF
  with SHA-256 and AES-256-GCM.
- Encrypted channel: several sessions of ephemeral Diffie-Hellman, key
  derivation and AES-256-GCM, with a private and a public (transcript) view,
  and the channel attacker, which decrypts every session but the first.
- Isolation tests that keep honest code from importing kleptographic code,
  and 100% test coverage of the cryptographic and mathematical core.

### Interactive application

- Home page with the introduction, the methodology and the roadmap.
- Diffie-Hellman section: toy or RFC 7919 group, random or chosen keys, and
  a step-by-step timeline of the exchange.
- Young–Yung SETUP section: the idea, the complete derivation and an
  experiment with two exchanges and the attacker's recovery.
- Encrypted channel section: the channel as a participant, with an honest
  or compromised device, and the attacker's workbench to recover keys and
  decrypt messages.
- Section navigation: "On this page" sidebar and sticky tabs.
- The SETUP and channel sections offer RFC 7919 groups of up to 4096 bits,
  so that a run never stalls the app for other visitors.
- Deployment on Streamlit Community Cloud:
  <https://dpr-kleptography.streamlit.app/>.

### Documentation

- Developer documentation in `docs/`: architecture, number theory,
  Diffie-Hellman, the SETUP, the primitives, the channel and the interface,
  with runnable examples and diagrams.

[1.0.0]: https://github.com/danielsp13/kleptography/releases/tag/v1.0.0
