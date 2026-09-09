# AGENTS.md

## Project Overview

Kleptography is an open-source educational software project for studying and demonstrating kleptographic techniques.

The project is primarily inspired by:

> Young, A. & Yung, M. — *Kleptography: Using Cryptography Against Cryptography*

The initial cryptographic target is Diffie-Hellman (DH). Future implementations may cover other cryptographic mechanisms, including RSA and post-quantum cryptography such as ML-DSA.

The project is written in Python and is intended to become an interactive educational web application built with Streamlit.

The primary goal is **education and analysis**, not the development of deployable malicious cryptographic implementations.

The project should make the distinction between legitimate cryptographic schemes and their kleptographic counterparts explicit at every level: code, documentation, tests, examples, and UI.

---

## Core Principles

### 1. Education First

Every implementation must have a clear educational purpose.

The project should explain:

- what the legitimate cryptosystem does;
- what security assumptions it relies on;
- how the corresponding kleptographic construction modifies or abuses it;
- what information is leaked;
- why the construction can remain difficult to detect;
- which assumptions or implementation properties make the construction possible.

Code alone is not considered sufficient educational material.

### 2. Separate Legitimate Cryptography from Kleptography

A legitimate cryptographic implementation and its corresponding kleptographic construction must be clearly separated.

Avoid designs where malicious or kleptographic behavior is hidden inside an otherwise generic cryptographic API.

Prefer explicit conceptual boundaries such as:

```text
crypto/
    legitimate/
    kleptographic/
```

or an equivalent architecture that makes the distinction obvious.

The exact package structure may evolve as the project develops.

### 3. Toy vs. Realistic Implementations

The project may contain two levels of cryptographic examples:

- **Toy examples** — intentionally small, simplified, insecure, and suitable for explaining concepts.
- **Realistic examples** — representative of modern cryptographic practice and using appropriately sized parameters where practical.

These must never be conflated.

Toy parameters must be explicitly identified as educational and insecure.

Realistic examples must document their assumptions, parameter choices, limitations, and performance implications.

### 4. Do Not Invent Cryptography

Cryptographic constructions must be based on published literature or clearly identified educational simplifications.

When implementing a construction from a paper:

- identify the source;
- document the relevant construction;
- preserve the terminology used by the source where practical;
- distinguish the paper's construction from project-specific adaptations;
- do not silently modify security-relevant details.

If the construction is not sufficiently understood, create or use a research issue before implementing it.

---

## Repository Architecture

The repository should evolve around clear conceptual boundaries.

At a high level, expect the project to contain areas corresponding to:

```text
Kleptography
├── cryptographic primitives and schemes
├── kleptographic constructions
├── mathematical utilities
├── educational material
├── demonstrations and experiments
├── visualization
├── tests
└── Streamlit application
```

The architecture should avoid coupling cryptographic logic directly to the Streamlit UI.

Cryptographic and mathematical components must remain usable independently from the web application.

The UI should consume well-defined project APIs rather than implementing cryptographic logic itself.

---

## Python Tooling

The project uses the Astral Python ecosystem where appropriate.

### Environment and Dependencies

Use `uv` for:

- Python version management;
- virtual environments;
- dependency management;
- lockfile management;
- running project commands.

Do not manually create or maintain dependency state outside the project configuration unless there is a documented reason.

The canonical project configuration should live in `pyproject.toml`.

The `uv.lock` file should be committed to the repository.

### Formatting and Linting

Use Ruff for:

- code formatting;
- linting;
- import organization and related static checks.

Formatting should be automated rather than manually enforced.

### Type Checking

Use `ty` for static type checking where supported by the project configuration.

Type annotations should be introduced progressively, with particular emphasis on public APIs, mathematical components, and cryptographic interfaces.

### Testing

Use `pytest` as the test runner.

Tests should be deterministic and should not depend on the Streamlit application being started unless the test specifically targets the UI layer.

Additional testing tools may be introduced when justified by project requirements.

---

## Cryptographic Code

Cryptographic code requires a higher standard of review than ordinary application code.

When adding or modifying cryptographic functionality:

1. Identify the underlying cryptographic construction.
2. Identify the relevant specification or paper.
3. Document security assumptions.
4. Document parameter choices.
5. Add tests for mathematical and behavioral correctness.
6. Add educational documentation where appropriate.
7. Clearly distinguish toy implementations from realistic implementations.
8. Avoid ambiguous APIs that could hide security-relevant behavior.

Do not describe an educational implementation as "secure" unless that claim is explicitly justified.

When an implementation intentionally omits production-grade protections, state this clearly.

---

## Kleptographic Constructions

Kleptographic functionality must remain explicit.

A kleptographic implementation should document:

- the legitimate cryptosystem being targeted;
- the adversarial objective;
- the SETUP mechanism;
- the information available to the attacker;
- the information leaked or recoverable;
- the intended educational demonstration;
- relevant assumptions and limitations.

The project should make it possible to compare:

```text
Legitimate scheme
        │
        ├── normal execution
        │
        └── expected outputs

Kleptographic scheme
        │
        ├── normal-looking execution
        │
        ├── SETUP-dependent behavior
        │
        └── recoverable leaked information
```

The project should prioritize transparency and reproducibility over operational deployment.

---

## Research and Papers

Research issues are first-class project artifacts.

When a construction is derived from a paper, the implementation should not begin with assumptions about the construction that have not been verified.

Research issues should record, where relevant:

- paper and bibliographic reference;
- construction being studied;
- relevant definitions;
- assumptions;
- important equations or algorithms;
- interpretation of the construction;
- open questions;
- implementation considerations.

The original Young & Yung paper should be treated as a primary reference for the project's initial kleptography work.

Follow-up papers and post-quantum literature should be tracked separately using the project's paper labels.

---

## Educational Content

Educational content is part of the product, not secondary documentation.

Explanations should support multiple audiences, including readers who may have little or no prior knowledge of cryptography.

When appropriate, explanations should progress from:

```text
Intuition
    ↓
Mathematical formulation
    ↓
Algorithm
    ↓
Python implementation
    ↓
Interactive demonstration
    ↓
Security analysis
```

Avoid assuming that readers already understand group theory, discrete logarithms, public-key cryptography, or cryptographic security terminology.

Technical accuracy must not be sacrificed for simplicity.

---

## Visualization and Streamlit

The final user-facing application is expected to use Streamlit.

Streamlit code belongs to the presentation layer and should not contain core cryptographic or mathematical logic.

Interactive demonstrations should make security-relevant state visible when doing so improves understanding.

Examples include:

- public parameters;
- private values;
- generated values;
- protocol messages;
- SETUP parameters;
- leaked information;
- attacker-side reconstruction.

Sensitive or adversarial concepts should be presented explicitly as part of the educational model rather than disguised as ordinary application behavior.

---

## Testing Philosophy

Tests should verify more than whether code executes.

Depending on the component, tests should cover:

- mathematical correctness;
- protocol correctness;
- deterministic toy examples;
- randomized properties;
- boundary conditions;
- invalid inputs;
- consistency between legitimate and kleptographic variants;
- educational invariants;
- regression cases.

For cryptographic constructions, tests should make important security assumptions observable where possible.

A test that merely checks that a function returns a value is generally insufficient for cryptographic code.

---

## Documentation

Documentation should explain both **how** something works and **why** it works.

For cryptographic material, documentation should distinguish:

- mathematical facts;
- implementation decisions;
- security assumptions;
- educational simplifications;
- claims supported by literature;
- project-specific interpretations.

Do not present project-specific terminology or abstractions as established cryptographic terminology without qualification.

---

## Agent Behavior

Agents working on this repository should:

1. Read this file before modifying the repository.
2. Inspect existing code and documentation before introducing new abstractions.
3. Prefer the smallest change that satisfies the issue.
4. Follow existing project conventions unless the issue explicitly changes them.
5. Never invent cryptographic constructions or paper results.
6. Verify cryptographic claims against the relevant source material.
7. Add tests for behavioral changes.
8. Keep UI concerns separate from core logic.
9. Update documentation when behavior or educational interpretation changes.
10. Report uncertainty instead of silently making assumptions.

When requirements are ambiguous, prefer creating or proposing a focused issue rather than introducing speculative architecture.

---

## Security and Safety

This project exists for educational research and demonstration.

Implementations must be clearly identified according to their intended educational purpose.

Do not add functionality whose purpose is unrelated to the project's educational objectives.

When a feature could reasonably be interpreted as an operational attack capability, its implementation and documentation should remain explicitly scoped to controlled educational demonstrations.