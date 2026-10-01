# Kleptography documentation

This folder documents the library behind the interactive app: what each
package implements, how the pieces connect, and why they are built that
way. It complements the [project README](../README.md), which covers what
kleptography is, how to run the app and a first example.

The documentation is for readers who want to study the code: students
following the math into the implementation, and developers who want to
reuse a package or add a new target.

## Pages

| Page | What you will find |
| --- | --- |
| [Architecture](architecture.md) | The three layers, which package may import which, how honest and kleptographic code stay apart, and the shared conventions. **Start here.** |
| [Number theory (`math`)](math.md) | Modular arithmetic and the generation of safe primes and subgroup generators. |
| [Diffie-Hellman (`crypto.dh`)](dh.md) | The honest exchange: parameters and validation, participants, the five phases of the protocol, tracing and the RFC 7919 groups. |
| [Young–Yung SETUP (`crypto.dh.setup`)](setup.md) | The kleptographic device and attacker: equations, configuration, recovery and test vectors. |
| [Primitives (`crypto.kdf`, `crypto.aead`)](primitives.md) | The key derivation function and authenticated encryption used by the channel. |
| [Encrypted channel (`crypto.channel`)](channel.md) | Sessions built from DH, KDF and AEAD, the public transcript, and the attacker that reads it. |
| [Interface (`app`)](app.md) | How each interactive section uses the library, without the visual design. |

## Reading paths

- **"How does Diffie-Hellman work in code?"** Architecture → Number
  theory → Diffie-Hellman.
- **"How does the backdoor work?"** Diffie-Hellman → Young–Yung SETUP.
  The [interactive SETUP section](../README.md#interactive-sections) shows
  the same values step by step.
- **"What does the attacker gain in a real protocol?"** Young–Yung SETUP →
  Primitives → Encrypted channel.
- **"I want to add a new target (RSA, ML-DSA)."** Architecture, then the
  SETUP page as a model of how a kleptographic package is isolated and
  tested.

## Conventions used in these pages

- Code identifiers are in `monospace`. Mathematical notation follows the
  source: `p`, `g`, `q` for the group, `x` for a private exponent. The SETUP
  page keeps the paper's names (`c1`, `m1`, `a`, `b`, `W`, `t`, `H`).
- Examples use the toy group `p = 23`, `g = 2`, `q = 11`, the same one the
  tests use, so every value can be checked by hand. It is **insecure** and
  only meant for reading.
- Every page states its sources. Kleptographic constructions follow A. L.
  Young and M. Yung, "Kleptography: Using Cryptography Against
  Cryptography", EUROCRYPT '97, LNCS 1233, Springer, 1997.

## Diagrams

The diagrams live in [`images/diagrams/`](images/diagrams/). Each one is
written by hand as an SVG (the source, which you can edit) and exported to
PNG (the image the pages show). To regenerate a PNG after editing its SVG,
use a headless Chrome or Chromium from the repository root:

```bash
google-chrome --headless=new --hide-scrollbars --force-device-scale-factor=2 \
  --window-size=1400,1000 \
  --screenshot="$PWD/docs/images/diagrams/architecture.png" \
  "file://$PWD/docs/images/diagrams/architecture.svg"
```

Set `--window-size` to the `width` and `height` of the SVG.
