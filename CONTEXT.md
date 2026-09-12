# CONTEXT.md

## Project

`kleptography` is an open-source educational project for studying and
demonstrating **kleptographic techniques** — deliberate SETUP backdoors
embedded in cryptographic schemes that look normal but let an attacker
recover secret information.

Primary reference: Young, A. & Yung, M. — *Kleptography: Using Cryptography
Against Cryptography*.

Initial target: Diffie-Hellman. Future targets: RSA, post-quantum (e.g.
ML-DSA).

Purpose is education/analysis, not operational attack tooling. The project is
meant to teach, at multiple levels, both the legitimate cryptosystems it
touches and how kleptography subverts them:

* **Theoretical framework**: what the legitimate scheme's security relies
  on (hard problems, assumptions), and what SETUP mechanisms are as a
  general adversarial model — not just "here's an exploit", but why the
  attacker's construction is possible at all (e.g. rejection sampling,
  biased randomness, subliminal channels).
* **Concrete construction**: how a specific paper's SETUP mechanism modifies
  a specific scheme (e.g. DH key generation), step by step.
* **Implementation**: a working, testable Python implementation of both the
  legitimate scheme and its kleptographic counterpart, so behavior can be
  compared directly rather than taken on faith.
* **Interactive demonstration**: a Streamlit UI that makes the normally
  invisible parts of the attack visible — public/private values, SETUP
  parameters, leaked information, attacker-side reconstruction — so a
  learner can see *why* the kleptographic output is indistinguishable from
  normal output, not just be told that it is.

Explanations should assume little to no prior cryptography background and
build up from intuition → math → algorithm → code → demo → security
analysis, without sacrificing technical accuracy.

## Core principles

1. **Education first.** Code alone is not sufficient documentation. Every
   construction needs an explanation of what the legitimate scheme does,
   what it assumes, how the kleptographic version alters it, what gets
   leaked, and why it's hard to detect.
2. **Legitimate vs. kleptographic stays explicit**, in code layout,
   docs, tests, and UI. No hiding malicious/SETUP behavior inside a
   generic-looking crypto API.
3. **Toy vs. realistic implementations are never conflated.** Toy examples
   (small, insecure, for teaching) must be labeled as such; realistic
   examples must document parameter choices, assumptions, and limitations.
4. **No invented cryptography.** Constructions must trace back to published
   literature or be clearly flagged as educational simplification. When a
   construction isn't well understood yet, it becomes a research issue
   before implementation, not a guess.
5. **No unjustified security claims.** Don't call an educational
   implementation "secure" without explicitly justifying it; state clearly
   when production-grade protections are intentionally omitted.
6. **Kleptographic constructions must document**: the targeted legitimate
   cryptosystem, the adversarial objective, the SETUP mechanism, what
   information the attacker has access to, what's recoverable, and the
   educational point being demonstrated.
7. **Research issues are first-class artifacts.** When implementing from a
   paper, capture the bibliographic reference, relevant definitions,
   assumptions, and open questions before/while coding — implementation
   should not start from unverified assumptions about the construction.
8. **Standardized parameters must remain distinguishable from generated
   educational parameters.** RFC-defined groups are imported as fixed,
   authoritative parameters; toy groups are generated dynamically and are
   explicitly insecure.

## Current status

The project has progressed beyond the initial mathematical utilities and
now contains the first part of the legitimate Diffie-Hellman parameter layer.

Currently implemented:

* Modular arithmetic helpers.
* Prime and safe-prime generation.
* Subgroup-generator generation.
* A `DiffieHellmanParameters` immutable data model.
* Generation of deliberately insecure educational DH parameters.
* Construction of DH parameters from standardized groups.
* RFC 7919 FFDHE groups from 2048 through 8192 bits.
* Tests covering the mathematical layer and the DH parameter/group layer.

The actual Diffie-Hellman key-exchange protocol and the kleptographic/SETUP
counterpart are **not yet part of the current implementation described here**.
They should be added as explicit components rather than being hidden inside
the parameter layer.

## Current directory structure

```text
.
├── CONTEXT.md
├── docs
│   └── images
│       └── kleptofox.png
├── LICENSE
├── pyproject.toml
├── README.md
├── src
│   └── kleptography
│       ├── __init__.py
│       ├── crypto
│       │   ├── __init__.py
│       │   └── dh
│       │       ├── __init__.py
│       │       ├── parameters.py
│       │       └── groups
│       │           ├── __init__.py
│       │           └── rfc7919
│       │               ├── __init__.py
│       │               ├── ffdhe2048.py
│       │               ├── ffdhe3072.py
│       │               ├── ffdhe4096.py
│       │               ├── ffdhe6144.py
│       │               └── ffdhe8192.py
│       └── math
│           ├── __init__.py
│           ├── modular.py
│           └── primes.py
├── tests
│   ├── crypto
│   │   └── dh
│   │       ├── test_parameters.py
│   │       └── groups
│   │           ├── test_ffdhe2048.py
│   │           ├── test_ffdhe3072.py
│   │           ├── test_ffdhe4096.py
│   │           ├── test_ffdhe6144.py
│   │           └── test_ffdhe8192.py
│   └── math
│       ├── test_modular.py
│       └── test_primes.py
└── uv.lock
```

## Component API

Public API currently exposed by each component. This section should remain
concise and serve as a quick reference for implementations and consumers.

### `math`

#### `math.modular`

Location:

```text
src/kleptography/math/modular.py
```

| Function                           | Purpose                                              |
| ---------------------------------- | ---------------------------------------------------- |
| `mod_pow(base, exponent, modulus)` | Compute modular exponentiation.                      |
| `mod_inverse(value, modulus)`      | Compute the multiplicative inverse modulo `modulus`. |
| `is_coprime(a, b)`                 | Check whether two integers are coprime.              |

#### `math.primes`

Location:

```text
src/kleptography/math/primes.py
```

| Function                             | Purpose                                                                         |
| ------------------------------------ | ------------------------------------------------------------------------------- |
| `generate_safe_prime(bits)`          | Generate a random safe prime with the requested bit length.                     |
| `generate_subgroup_generator(prime)` | Generate a generator for the intended prime-order subgroup modulo a safe prime. |

> Note: the current implementation/API uses
> `generate_subgroup_generator`. Any previous documentation referring to
> `generate_generator` should be considered outdated.

### `crypto.dh`

#### `crypto.dh.parameters`

Location:

```text
src/kleptography/crypto/dh/parameters.py
```

`DiffieHellmanParameters` is the current domain model for finite-field
Diffie-Hellman group parameters.

It is defined as a frozen, slotted dataclass:

```python
@dataclass(frozen=True, slots=True)
class DiffieHellmanParameters:
    prime: int
    generator: int
    subgroup_order: int
```

| API                                                            | Purpose                                                                |
| -------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `DiffieHellmanParameters(prime, generator, subgroup_order)`    | Construct an immutable DH parameter set.                               |
| `.bit_length`                                                  | Return the bit length of the prime modulus.                            |
| `.generate_toy(bits=32)`                                       | Generate deliberately insecure educational DH parameters.              |
| `.from_standard(prime=..., generator=..., subgroup_order=...)` | Construct parameters from externally supplied standardized parameters. |

### `crypto.dh.parameters.DiffieHellmanParameters`

The parameter object represents:

* `prime` — the prime modulus `p`.
* `generator` — the generator `g` of the subgroup used by DH.
* `subgroup_order` — the order `q` of the subgroup generated by `g`.

For the current toy parameter generation:

```text
p = 2q + 1
```

where both `p` and `q` are prime, and `generator` has order `q`.

`generate_toy()` is intentionally insecure and exists for demonstrations and
tests. Its output must never be described or treated as production-grade
cryptographic parameters.

`from_standard()` does not itself validate that the supplied values originate
from a particular standard. The caller is responsible for supplying
parameters obtained from a trusted specification or authoritative source.

## Tooling and infrastructure

* Python `>=3.12`.
* Environment/dependencies: **uv** (no manual pip/venv without documented reason).
* Formatting/linting: **Ruff** (`line-length = 88`, rules `E`, `F`, `I`).
* Static typing: **ty**.
* Tests: **pytest**, `testpaths = ["tests"]`; deterministic, no dependency
  on Streamlit running unless specifically testing the UI.
* Coverage: `coverage`, source = `src/kleptography`.
* Current main dependency: `sympy`.
* Dev deps: `pytest`, `coverage`, `ruff`, `ty`, `pre-commit`.
* Build backend: `hatchling`.