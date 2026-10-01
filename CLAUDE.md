# CLAUDE.md

Guidance for AI agents working on this repository. Read it fully before
changing anything. This file is the single source of project context: there
is no separate `CONTEXT.md` or `AGENTS.md`.

## 1. Project

`kleptography` is an open-source **educational** web application that
demonstrates kleptography: SETUP backdoors (Secretly Embedded Trapdoor with
Universal Protection) embedded in cryptographic schemes whose output looks
normal, but which let an attacker holding a trapdoor recover secret
information.

- Primary reference: A. L. Young and M. Yung, "Kleptography: Using
  Cryptography Against Cryptography", EUROCRYPT '97, LNCS 1233, pp. 62–74,
  Springer, 1997.
- First target: finite-field Diffie-Hellman (DH). Future targets: RSA and
  post-quantum schemes (e.g. ML-DSA).
- Purpose: education and analysis, never operational attack tooling.
- Audience: learners with little or no cryptography background. Content
  builds up intuition → math → algorithm → code → interactive demo →
  security analysis, without sacrificing technical accuracy.
- Maintainer: Daniel Pérez Ruiz. Repository: `github.com/danielsp13/kleptography`.

### Domain background (for orientation only)

- **Honest DH** in a prime-order subgroup: public `(p, g, q)` with
  `p = 2q + 1`. Each party picks a secret `x ∈ [1, q-1]`, publishes
  `g^x mod p`, and computes the shared secret `(g^y)^x mod p`. Security
  relies on the hardness of the discrete logarithm / Diffie-Hellman
  problems in the subgroup.
- **SETUP (Young–Yung)**: a black-box device whose outputs are
  computationally indistinguishable from honest outputs to everyone except
  the attacker, who embedded a public key in the device and alone holds the
  matching private key. Leaked information is recoverable only with that
  private key. The paper distinguishes weak, regular and strong SETUPs.
- **The DH case study**: across successive key exchanges, the compromised
  device derives a later private exponent from an earlier one combined with
  the attacker's public key. The public values still look uniformly random,
  but the attacker can recover the later exponent and therefore the shared
  secret. The precise algorithm (constants, hash, and the correction step)
  **must be taken from the paper through a research issue, not from this
  summary** (principle 4).

## 2. Core principles

These are non-negotiable. When a task conflicts with one, stop and report.

1. **Education first.** Code alone is not documentation. Every construction
   explains what the legitimate scheme does, what it assumes, how the
   kleptographic version alters it, what leaks, and why it is hard to detect.
2. **Legitimate vs. kleptographic stays explicit** in code layout, naming,
   docs, tests and UI. Never hide SETUP behavior inside the honest API
   (e.g. never add a "malicious mode" flag to `DiffieHellmanParticipant`).
3. **Toy vs. realistic is never conflated.** Toy parameters are labeled
   insecure; realistic ones document parameter choices and limitations.
4. **No invented cryptography.** Every construction traces back to published
   literature, or is flagged as an educational simplification. Preserve the
   paper's terminology and do not silently change security-relevant details.
5. **No unjustified security claims.** Never call educational code "secure";
   state when production protections are intentionally omitted.
6. **Kleptographic constructions document**: targeted cryptosystem,
   adversarial objective, SETUP mechanism, attacker knowledge, what is
   recoverable, and the educational point.
7. **Research before implementation.** A construction from a paper starts as
   a research issue (reference, definitions, assumptions, equations, open
   questions). If the construction is not understood, do not guess: report
   the uncertainty.
8. **Standardized parameters stay distinguishable from generated ones.**
   RFC groups are fixed, authoritative constants; toy groups are generated
   dynamically and are explicitly insecure.

## 3. Current status

| Area | State |
| --- | --- |
| Math utilities (`math/`) | Done, fully tested. |
| DH parameters, validation, RFC 7919 groups | Done. |
| Honest DH participant and protocol | Done. Five-phase execution model; supports known (loaded) and generated keys. |
| Protocol tracing (observer + event timeline) | Done. Consumed by the Diffie-Hellman section. |
| Streamlit shell: header, footer, home page, content composer | Done. Composer supports LaTeX. |
| Hidden navigation (home ↔ sections) | Done. |
| In-section navigation (sidebar "On this page" + sticky tabs) | Done for all three sections (DH has no tabs: sidebar only). |
| Interactive honest DH section (`/diffie-hellman`) | Done. Toy or RFC 7919 group, random or chosen keys, step-by-step timeline. |
| Young–Yung SETUP section (`/young-yung-setup`) | Done. Tabs: idea (SETUP, (1,2)-leakage), formulae (full derivation), experiment (two exchanges + attacker recovery, 8 steps). |
| Young–Yung DH SETUP (kleptographic DH) | Done, fully tested. Its former open points are closed by the maintainer's decision (see 4.6). |
| Encrypted channel compromised by the SETUP (DH + KDF + AES-256-GCM) | Done (see 4.7): AEAD, KDF, channel and channel attacker fully tested; interactive section `/encrypted-channel` with idea, participant and attacker tabs. |
| RSA / post-quantum targets | Future. |

Roadmap, as stated on the home page (`app/content/home.py`):

1. Mathematical and implementation foundations. **(done)**
2. Reference DH construction. **(done)**, including its interactive section.
3. Study and implement the Young–Yung construction. **(done)**
4. Interactive experiments around it, mirroring the honest DH section.
   **(done)**
5. Expose intermediate values and attacker knowledge. **(done for DH and
   the encrypted channel)**
6. Document security assumptions and limitations.
7. Apply the same methodology to other constructions.

Every case study follows the same page progression: mathematical background
→ reference construction → kleptographic construction → experiment
(both constructions under comparable conditions) → observation (what each
participant can see) → analysis.

Test suite: 837 tests, all passing (295 of them in `tests/crypto/dh/setup/`,
50 in `tests/crypto/aead/`, 43 in `tests/crypto/kdf/`, 71 in
`tests/crypto/channel/` and 59 in `tests/crypto/channel/setup/`).
`crypto/` and `math/` are at 100% coverage. On
the maintainer's request, the new UI modules (`navigation.py`,
`components/{navigation,protocol,controls,young_yung_setup,encrypted_channel}.py`,
`content/{diffie_hellman,young_yung_setup,encrypted_channel,numbers}.py`,
`pages/*`) **have no tests yet. Do not add page or component tests unless a task asks for them.**

## 4. Architecture and interrelations

```text
src/kleptography/
├── math/                    # pure number theory, no project imports
│   ├── modular.py           # mod_pow, mod_inverse, is_coprime
│   └── primes.py            # generate_safe_prime, generate_subgroup_generator (sympy)
├── crypto/                  # schemes; never imports streamlit or app
│   ├── dh/                  # honest finite-field Diffie-Hellman
│   │   ├── exceptions.py    # DiffieHellmanError hierarchy (leaf, imports nothing)
│   │   ├── validation.py    # validate_parameters/_private_key/_public_key
│   │   ├── parameters.py    # DiffieHellmanParameters
│   │   ├── participant.py   # DiffieHellmanParticipant
│   │   ├── exchange.py      # DiffieHellmanExchangeResult
│   │   ├── protocol.py      # perform_key_exchange
│   │   ├── tracing/         # events.py, observer.py, context.py
│   │   ├── groups/rfc7919/  # ffdhe2048() … ffdhe8192()
│   │   └── setup/           # KLEPTOGRAPHIC: Young–Yung SETUP on DH (see 4.6)
│   ├── kdf/                 # one-step KDF (SP 800-56C), SHA-256: derive_key (4.7)
│   ├── aead/                # AES-256-GCM: encrypt/decrypt, EncryptedMessage (4.7)
│   └── channel/             # ephemeral DH + KDF + AEAD sessions: run_channel (4.7)
│       └── setup/           # KLEPTOGRAPHIC: intercept_channel, the attacker (4.7)
└── app/                     # Streamlit presentation layer
    ├── main.py              # entry point: page config + hidden st.navigation
    ├── navigation.py        # page registry: home_page(), diffie_hellman_page(),
    │                        # young_yung_setup_page(), encrypted_channel_page(),
    │                        # all_pages()
    ├── pages/               # home.py; one package per section (see 4.5):
    │                        # diffie_hellman/, young_yung_setup/,
    │                        # encrypted_channel/
    ├── components/          # header, footer, navigation (back link, section card,
    │                        # section tabs and sidebar),
    │                        # controls (shared DH widgets), protocol, young_yung_setup,
    │                        # encrypted_channel
    ├── content/             # composer, callouts, home, diffie_hellman,
    │                        # young_yung_setup, encrypted_channel, numbers
    ├── html/                # templates/*.html, loader.py, renderer.py
    ├── css/                 # styles/{header,footer,protocol,section_cards,
    │                        # section_navigation}.css, loader.py
    └── assets/              # logos/kleptofox.png, loader.py
```

Dependency direction is strictly `app → crypto → math`. `math` and `crypto`
must stay usable without Streamlit, and `app` must not contain cryptographic
or mathematical logic.

### 4.1 Import graph inside `crypto/dh`

```text
exceptions  ◄── validation ◄── parameters ◄── participant ◄── protocol
                    │               │               │             │
                    └── math.modular│               │             ├── exchange
                                    └── math.primes │             └── tracing.{events,observer}
groups/rfc7919/* ── parameters
tracing.context ── tracing.{events,observer}   (tracing never imports DH modules)
```

- `validation.py` works on raw integers and does **not** import
  `parameters.py`, which avoids a circular import.
- `tracing/` is independent of DH classes. The protocol depends on tracing,
  never the reverse.

### 4.2 `math`

- `mod_pow(base, exponent, modulus)` wraps `pow` and raises `ValueError` if
  `modulus <= 0`. Crypto code uses it instead of calling `pow` directly.
- `mod_inverse(value, modulus)` raises `ValueError` if `modulus <= 1` or the
  inverse does not exist. `is_coprime(a, b)` checks `gcd(a, b) == 1`.
- `generate_safe_prime(bits)` requires `bits >= 3`. It samples a prime `q`
  of `bits-1` bits with `sympy.randprime` until `2q+1` is prime.
- `generate_subgroup_generator(prime)` checks that `prime` is a safe prime,
  then returns `primitive_root(p)^2 mod p`, an element of order `q`. The
  result is deterministic for a given `p` because sympy returns the
  smallest primitive root.

### 4.3 `crypto.dh`

- **`DiffieHellmanParameters(prime, generator, subgroup_order)`** is a
  frozen, slotted and hashable dataclass. `__post_init__` calls
  `validate_parameters`, so every instance satisfies
  `p > 2`, `q > 1`, `1 < g < p`, `p == 2q + 1` and `g^q ≡ 1 (mod p)`.
  Only safe-prime groups are supported.
  - `.bit_length` is the bit length of `p`; `.byte_length` is
    `ceil(bit_length / 8)`, the fixed width used to encode values mod p.
  - `generate_toy(bits=32)` returns random, **insecure** parameters for
    demos and tests.
  - `from_standard(*, prime, generator, subgroup_order)` is the entry point
    for standardized groups. It does not check where the values come from;
    the caller is responsible for that.
- **Validation** raises `InvalidDiffieHellmanParameters`,
  `InvalidPrivateKey` (unless `1 <= x < q`) or `InvalidPublicKey` (unless
  `1 < y < p` and `y^q ≡ 1`, a subgroup membership check).
- **Exceptions**: `DiffieHellmanError` is the base. `Invalid*` and
  `DiffieHellmanParametersMismatch` also subclass `ValueError`, and
  `DiffieHellmanStateError` also subclasses `RuntimeError`.
- **`DiffieHellmanParticipant(parameters)`** is a slotted dataclass whose
  key pair is stored in `_private_key` / `_public_key` and exposed through
  **read-only** properties `private_key`, `public_key` (both `None` until
  set) and `has_keypair`. `_private_key` is excluded from `repr`. The key
  pair can only change through the two methods below, and both derive the
  public value from the exponent, so the invariant `public_key == g^x mod p`
  always holds. Never assign key material directly.
  - `generate_keypair()` sets a fresh `x = secrets.randbelow(q-1) + 1` and
    `y = g^x mod p`, replacing any previous pair.
  - `load_private_key(x)` validates `x` (`InvalidPrivateKey` unless
    `1 <= x < q`) and sets `(x, g^x mod p)`, replacing any previous pair.
    Use it for reproducible demos and deterministic tests.
  - `compute_shared_secret(peer_public_key)` raises
    `DiffieHellmanStateError` if the peer key or its own key pair is
    missing, validates the peer key, and returns `peer^x mod p`.
  - The private helpers `_generate_private_key` and `_compute_public_key`
    are the natural points where a SETUP variant differs. A kleptographic
    participant must be a **separate, explicitly named class**, not a flag
    (principle 2).
- **`DiffieHellmanExchangeResult(alice_shared_secret, bob_shared_secret)`**
  is frozen. `.successful` returns whether both secrets are equal.
- **`perform_key_exchange(alice, bob, *, observer=None)`** runs the
  exchange in five explicit phases, each implemented as a private helper in
  `protocol.py`:
  1. `_agree_parameters`: raises `DiffieHellmanParametersMismatch` if
     `alice.parameters != bob.parameters` (value equality, so distinct but
     equal objects are accepted). On failure nothing is generated or traced.
  2. `_prepare_keypair` (Alice, then Bob): a participant that already
     `has_keypair` keeps it (**provided key**); otherwise
     `generate_keypair()` is called (**generated key**).
  3. `_send_public_key` (Alice→Bob, then Bob→Alice).
  4. `_compute_shared_secret` (Alice, then Bob), which validates the peer's
     public value.
  5. Verification: builds the `DiffieHellmanExchangeResult` and emits
     `SHARED_SECRET_VERIFIED`.

  Key pairs stay on the participants after the exchange, so running a
  second exchange with the same participants reuses the same keys (static
  DH). For fresh ephemeral keys, use new participants or call
  `generate_keypair()` first; that key is then traced as provided. Events
  are forwarded through `_emit(observer, ...)`, which does nothing when
  `observer` is `None`.
- **RFC 7919 groups**: `ffdhe2048()`, `ffdhe3072()`, `ffdhe4096()`,
  `ffdhe6144()` and `ffdhe8192()` are functions (not constants) that return
  `DiffieHellmanParameters.from_standard(...)` built from the hex constants
  copied from the RFC, with `g = 2`. Each call re-runs validation. The 8192
  group is slow, so avoid calling it in hot paths.

### 4.4 `crypto.dh.tracing`

- `Actor` (`StrEnum`): `SYSTEM`, `ALICE`, `BOB`. There is no attacker
  actor: SETUP internals are exposed through value objects instead (see
  4.6).
- `ProtocolEventType` (`StrEnum`) defines the semantic steps. The
  `MODULAR_EXPONENTIATION_{STARTED,STEP,COMPLETED}` types are defined but
  **never emitted yet**; they are reserved for step-by-step visualization
  of square-and-multiply.
- `ProtocolEvent(sequence, event_type, actor, data)` is frozen. It requires
  `sequence >= 1`, and `data` is copied into a read-only `MappingProxyType`.
- `OperationObserver` is an ABC with a single method,
  `observe(event_type, *, actor, data=None)`.
- `ProtocolExecutionContext(OperationObserver)` appends events with
  sequence numbers starting at 1. `.events` returns an immutable tuple
  snapshot.
- Timeline emitted by `perform_key_exchange` when an observer is given (13
  events): `PARAMETERS_SELECTED`, `PARAMETERS_VALIDATED` (SYSTEM) →
  `PRIVATE_KEY_GENERATED` **or** `PRIVATE_KEY_PROVIDED`,
  `PUBLIC_KEY_COMPUTED` (ALICE, then BOB) →
  `PUBLIC_KEY_SENT` / `PUBLIC_KEY_RECEIVED` (ALICE→BOB, then BOB→ALICE) →
  `SHARED_SECRET_COMPUTED` (ALICE, BOB) → `SHARED_SECRET_VERIFIED`
  (SYSTEM).
- `PUBLIC_KEY_COMPUTED` and `SHARED_SECRET_COMPUTED` carry an `expression`
  string such as `"2^6 mod 23"`. `PARAMETERS_VALIDATED` means that both
  participants use the same group. The group's own invariants were already
  validated when the `DiffieHellmanParameters` were constructed.
- `PRIVATE_KEY_PROVIDED` vs `PRIVATE_KEY_GENERATED` records whether the
  exponent existed before the exchange started or was sampled during it.
  This matters for the SETUP work, where a compromised device chooses
  exponents that look like freshly generated ones.
- Events deliberately include private values, because showing them is the
  educational goal. Keep events presentation-agnostic: raw values only, no
  HTML or formatting. The UI is expected to render a DH walkthrough from
  `ProtocolExecutionContext.events`. Tracing is unchanged by the SETUP: a
  device exchange emits exactly the same timeline as an honest one, which is
  part of what the tests check.

### 4.5 `app` (Streamlit)

Launch with `uv run streamlit run src/kleptography/app/main.py`. The app
imports `kleptography.*` as an installed package, which `uv sync` sets up.

#### Navigation

`main.main()` calls `st.set_page_config(...)` and then
`st.navigation(all_pages(), position="hidden").run()`. Streamlit's page
menu is hidden: pages link to each other with `st.page_link`. The home page
has no sidebar; a section may render its own (see "Section navigation").

- `app/navigation.py` defines one factory per page: `home_page()` (default,
  URL `/`), `diffie_hellman_page()` (URL `/diffie-hellman`),
  `young_yung_setup_page()` (URL `/young-yung-setup`) and
  `encrypted_channel_page()` (URL `/encrypted-channel`). Streamlit
  identifies a page by its `url_path`, so a factory can be called wherever a
  link is needed.
- Page modules import `navigation.py` to build links, so the factories
  import the page renderers **inside the function body**. This is the
  deliberate cycle-breaker; do not move those imports to module level.
- **Page packages.** Every section is a package in `pages/` with one module
  per concern, so its layout reads at a glance in `page.py`; `home.py` stays
  a single module. Modules: `page.py` (`render_page_<name>`: intro, tabs or
  sections, sidebar, footer; layout only), `outline.py` (the tabs and
  headings for the tabs and the sidebar), `state.py` (session state and
  widget keys shared by several modules), `experiment.py` (the run of the
  crypto API, never `st.*`), and one module per tab or part (`sections.py`
  and `timeline.py` in DH and SETUP; `participant.py`, `attacker.py` and
  `workbench.py` in the channel). `__init__.py` holds the section docstring
  and re-exports `render_page_<name>`, so `navigation.py` imports it from
  the package. Names used by another module of the package are public (no
  underscore); helpers used by one module stay private, and so do keys used
  by one module only (e.g. `ch_device_kind`), which stay inline there.
- To add a page: create its package in `pages/` (`render_page_<name>()` in
  `page.py`), add a factory in `navigation.py`, add it to `all_pages()`, add
  a `SectionCard` for it in `pages/home.py` and a `st.page_link` in
  `components/navigation._render_sidebar_sections`. Start the page with
  `render_component_back_home()`.
- Home → section uses plain HTML links (see the home page section below),
  which cause a full page load: session state does not survive it.
  Section → home uses `st.page_link`, which navigates client-side.
- Outside a running Streamlit script, `st.Page` returns an empty stub, so
  page objects cannot be inspected in plain unit tests.

#### Home page

```text
pages.home.render_page_home()
   ├── components.header.render_component_header()
   │     assets.asset_data_uri("logos","kleptofox.png")   # logo as base64 data URI
   │     html.render_template("header.html", **ctx)       # Jinja2
   │     html.render_html(html, css=css.load_css("header.css"))  # st.html with <style>
   ├── st.markdown(CalloutComposer.css(), unsafe_allow_html=True)
   ├── _render_sections()        # "Interactive sections"
   │     render_component_section_cards([SectionCard(...), ...])
   │       render_template("section_cards.html") + load_css("section_cards.css")
   ├── st.markdown(content.home.build_home_content(), unsafe_allow_html=True)
   └── components.footer.render_component_footer()
```

**Section cards**: `SectionCard(title, description, status, url_path)`, where
`url_path` comes from the page factory (e.g. `diffie_hellman_page().url_path`)
or is `None` for an unavailable section. The whole card is one `<a>`
element with a relative `href`. Cards sit in a CSS grid (`auto-fit`,
stretch), so all cards in a row have the same height, and they use the
header palette. Unavailable cards are a disabled `<div>` showing "Coming
soon". `st.html` sanitizes with DOMPurify: `href` survives but `target` is
stripped unless it is `_blank`. The description is plain text, because it
is inserted into HTML and not rendered as Markdown.

#### Diffie-Hellman section (`pages/diffie_hellman/`)

The page only orchestrates the `crypto` API and delegates text to `content/`
and rendering to `components/`. Modules (see "Page packages"):

```text
pages/diffie_hellman/
├── page.py         # render_page_diffie_hellman: intro, sections, timeline, sidebar
├── outline.py      # ANCHORS (no tabs)
├── state.py        # dh, dh_run, dh_revealed
├── sections.py     # render_{parameters,private_keys,run}_section: sections 1–3
├── experiment.py   # ExchangeRun, run_exchange (crypto orchestration, no st.*)
└── timeline.py     # render_timeline_section
```

```text
render_page_diffie_hellman()
   ├── render_html("", css=load_css("protocol.css")) + CalloutComposer.css()
   ├── render_component_back_home()
   ├── title + build_dh_intro_content()
   ├── number format control (Decimal / Hexadecimal)         key dh_number_format
   ├── 1 · public parameters (render_component_group_selection) key dh_group_kind
   │     toy:      number input 8–64 bits (dh_toy_bits) + "Generate a new group"
   │               → DiffieHellmanParameters.generate_toy(bits), kept in
   │                 session_state["dh_toy_parameters"] until bits change or regenerate
   │     standard: selectbox FFDHE2048…8192 (dh_group) → ffdheNNNN()
   │     p, g, q shown with render_component_parameters
   ├── 2 · private keys: Random | Chosen by me                key dh_key_mode
   │     chosen: range shown as LaTeX (1 ≤ a ≤ q − 1, never as a raw number),
   │     text inputs dh_alice_key / dh_bob_key parsed with parse_integer
   │     (decimal, or hex with 0x; spaces ignored). Text, not number_input,
   │     because JS numbers lose precision above 2^53.
   ├── 3 · run: run_exchange(parameters, private_keys): DiffieHellmanParticipant
   │     ×2 (+ load_private_key if chosen) → perform_key_exchange(observer=
   │     ProtocolExecutionContext()) → ExchangeRun(parameters,
   │     build_protocol_steps(events)) in session_state["dh_run"];
   │     session_state["dh_revealed"] = 1; InvalidPrivateKey → st.error
   ├── 4 · timeline: progress bar, steps[:revealed] via
         render_component_protocol_step, then render_component_step_navigation
         (Next step / Show all steps / Start over; on_click callbacks update
         dh_revealed; button keys dh_revealed_{next,all,restart}). If the current
         parameters differ from ExchangeRun.parameters, the run is stale:
         an info message replaces the timeline.
   └── render_component_page_sidebar(ANCHORS, key_prefix="dh") (no tabs)
```

- **`content/diffie_hellman.py`** turns the timeline into teaching material
  without doing any cryptography. `STEP_DEFINITIONS` holds five
  `StepDefinition(title, explanation, formula)` objects; the explanation is
  Markdown with inline LaTeX, and the formula is a display LaTeX string.
  `build_protocol_steps(events)` maps event types to steps 1–5 (parameters,
  key pairs, exchange, shared secrets, verification) and ignores unmapped
  types such as `MODULAR_EXPONENTIATION_*`. Each `ProtocolStep` exposes
  `event(type, actor)` and `events_of(*types)`.
  `public_key_formula` / `shared_secret_formula` substitute concrete values
  only when `is_small(...)` holds (at most 12 digits), and otherwise return
  the symbolic form. The notation is the textbook one: `a`/`A` for Alice,
  `b`/`B` for Bob, `s_A`/`s_B` for the secrets, and Eve for the
  eavesdropper. The module also provides the callout builders for toy
  groups, standard groups and the eavesdropper.
- **`components/controls.py`** holds the widgets shared by the DH-based
  sections, parametrized by the section's `key_prefix` (`dh`, `yy`), so keys
  and session state never collide: `GroupKind`, `KeyMode`,
  `STANDARD_GROUPS`, the toy bit limits (8–64, default 16),
  `render_component_number_format(*, key_prefix)`,
  `render_component_group_selection(*, key_prefix, number_format)` (toy or
  RFC group, callouts, and p/g/q; the toy group is cached in
  `<prefix>_toy_parameters`, and each RFC group is built once per process
  by `_standard_group`) and
  `render_component_step_navigation(*, state_key, revealed, total)`.
- **`content/numbers.py`**: `NumberFormat` (DECIMAL, HEXADECIMAL);
  `parse_integer(text)`; `is_small(*values)`; `format_bytes(data)` (upper-case
  hex in groups of 4 bytes, whatever the number format) and
  `parse_bytes(text)` (hex, spaces and `0x` ignored).
  `format_integer(value, fmt, *, width_bits=None)` separates groups with
  spaces:
  - Decimal uses groups of 3 from the right, as a thousands separator.
    Spaces are used, not `.` or `,`, because they are locale-neutral
    (ISO 80000) and give the line-wrapping points.
  - Hexadecimal uses upper-case groups of 8 **from the left**,
    zero-padded to `ceil(width_bits / 4)` digits, as in RFC 7919. All
    values modulo `p` then have the same length, so their groups line up in
    columns when wrapped.
- **`components/protocol.py`**: `ValueDisplay(number_format, width_bits)`
  bundles display settings (`width_bits` = bit length of `p`).
  `render_component_parameters(*, prime, generator, subgroup_order,
  display)` shows `p`, `g` and `q`; `g` is never padded. It is shared by
  the parameter section and step 1.
  `render_component_value(label, value, *, visibility, number_format,
  width_bits=None)` renders a label, a `Visibility` badge
  (Public / Private / Shared secret, plus Hidden in the device and Attacker
  only for the SETUP section), the bit size, and an
  `st.code(..., language="text", wrap_lines=True)` block. Blocks longer than
  400 characters get a fixed height and scroll vertically.
  `render_component_protocol_step(step, *, display)` draws a bordered
  container with the title, explanation and formula, then a step-specific
  body: side-by-side Alice/Bob containers for key pairs and secrets,
  sender→recipient cards plus the eavesdropper callout for the exchange,
  and `st.success` for validation and verification.
- **`css/styles/protocol.css`** makes code blocks (`[data-testid="stCode"]`)
  wrap **only at spaces** (`word-break: normal`, `overflow-wrap: anywhere`
  as a fallback), which keeps digit groups aligned. Do not use
  `break-all`: it splits groups and breaks the alignment. Long KaTeX
  display formulas scroll inside themselves. It also enlarges the
  navigation controls, using the selectors of Streamlit 1.63: tabs
  (`[data-testid="stTab"]`, indicator `.react-aria-SelectionIndicator`),
  segmented controls (`button[data-variant="segmented_control"]`), the
  progress bar and the step navigation buttons, which
  `render_component_step_navigation` wraps in a container keyed
  `step-navigation-<state_key>`. Recheck these selectors after a Streamlit
  upgrade.

#### Young–Yung SETUP section (`pages/young_yung_setup/`)

Mirrors the DH section, told from the attacker's point of view. Session and
widget keys use the `yy_` prefix. Modules (see "Page packages"):

```text
pages/young_yung_setup/
├── page.py         # render_page_young_yung_setup: intro, tabs, sidebar, footer
├── outline.py      # TABS (SectionTab + PageAnchor)
├── state.py        # yy, yy_tab, yy_backdoor, yy_run, yy_revealed
├── sections.py     # render_experiment: the Experiment tab, sections 1–4
├── experiment.py   # ChosenKeys, run_experiment (no st.*)
└── timeline.py     # render_timeline_section
```

```text
render_page_young_yung_setup()
   ├── css + back link + title + build_setup_intro_content()
   ├── render_component_section_tabs(TABS, state_key="yy_tab"), and after
   │   them render_component_section_sidebar (all headings, always shown)
   │   ├── "The idea":   build_setup_concept_content()   SETUP definition
   │   │                 (paraphrased), public key vs naive backdoor, roles,
   │   │                 (m, n)-leakage and why this one is (1,2), detection, stakes
   │   ├── "Formulae":   build_setup_formulae_content()  notation, subgroup
   │   │                 arithmetic, device/attacker algorithms, six-step proof of
   │   │                 recovery, the hidden DH exchange (Y^(αa1+β) = r^X), why
   │   │                 others cannot (CDH), (1,2)-leakage (why s1 is safe),
   │   │                 worked example (test vectors, toy H flagged),
   │   │                 implementation choices
   │   └── "Experiment": render_experiment()
   │         number format + 1 · group (shared controls, prefix yy)
   │         2 · backdoor: Backdoor.generate(parameters) in
   │             session_state["yy_backdoor"], regenerated when the group
   │             changes or on "Generate a new backdoor"
   │         3 · keys: Random | Chosen (a1, b1, b2 → ChosenKeys)
   │         4 · run: run_experiment() follows the 4.6 flow (device plays
   │             Alice, a new honest Bob per exchange) → SetupRun in yy_run
   │         timeline: 8 steps via render_component_setup_step, stale if the
   │             group or configuration changed
   └── footer
```

- **`content/young_yung_setup.py`**: the intro, concept and formulae
  builders, `SETUP_STEP_DEFINITIONS` (8 `StepDefinition`s: parameters,
  backdoor, exchange 1, derivation, exchange 2, transcript, recovery,
  recovered secret), callouts (reverse engineer, Eve vs attacker,
  (1,2)-leakage), `ExchangeSummary` + `summarize_exchange(events)` (reads the
  device's and Bob's values from a timeline where the device is Alice), and
  formula helpers (`power_formula`, `z_formula`, `hash_formula`,
  `r_formula`, `z1_formula`, `z2_formula`) that substitute values only when
  `is_small`; `r_formula` and `z1_formula` take an optional `first_symbol`
  (default `A_1`), which the encrypted channel sets to `A_{i-1}`. **UI notation is adapted to DH, not the paper's**: protocol
  roles follow the honest section (device = Alice: `a1, a2` / `A1, A2`;
  Bob: `b1, b2` / `B1, B2`; secrets `s1, s2`), the paper's constants `a, b`
  become `α, β`, and the SETUP machinery keeps the paper's symbols
  (`X, Y, W, t, H, z, r`). Attacker candidates are `â_i = H(z_i)`. The
  formulae tab shows the correspondence table (paper `c_i, m_i, a, b`). The
  `crypto` code and its comments and test vectors keep the paper's names
  (`c1`, `m1`, `multiplier_a`, `offset_b`).
- **`components/young_yung_setup.py`**: `Backdoor(attacker, configuration)`
  with `Backdoor.generate(parameters)` (a new attacker and its
  configuration), shared by the SETUP and channel sections, which each keep
  their own caching in session state; `SetupRun` (parameters, attacker,
  configuration, both `ExchangeSummary`s, `SetupDerivation`,
  `SetupRecovery`, recovered secret), `render_component_backdoor` and
  `render_component_setup_step(number, run, *, display)`. The rejected
  candidate's check is symbolic, since the app never exponentiates. If the
  inferred t differs from the real one (both candidates hash to the same key
  in a tiny group), the recovery step explains it.

#### Encrypted channel section (`pages/encrypted_channel/`)

The last step of the Young–Yung case study (4.7): the same SETUP inside a
complete channel. Session and widget keys use the `ch_` prefix. Three tabs.

Modules (see "Page packages"):

```text
pages/encrypted_channel/
├── page.py         # render_page_encrypted_channel: intro, tabs, sidebar, footer
├── outline.py      # TABS (SectionTab + PageAnchor) and sidebar_tabs()
├── state.py        # session state and widget keys shared by several modules
├── participant.py  # render_participant: sections 1–4 and the session tabs
├── experiment.py   # run_experiment (crypto orchestration, no st.*)
├── attacker.py     # render_attacker: sections 1, 2 and 4
└── workbench.py    # render_workbench: section 3 of the attacker
```

```text
render_page_encrypted_channel()
   ├── css + back link + title + build_channel_intro_content()
   │   + st.page_link to the SETUP section (prerequisite)
   ├── render_component_section_tabs(TABS, state_key="ch_tab"), and after
   │   them render_component_section_sidebar (Attacker headings only once
   │   there is a run)
   ├── "The idea":    build_channel_concept_content()  sessions and ephemeral
   │                  keys, the ciphersuite (illustrative name
   │                  CIPHERSUITE_NAME, flagged as not a registered TLS suite),
   │                  Kerckhoffs table, how the SETUP breaks the channel,
   │                  session 1 stays confidential, toy-group brute force
   ├── "Participant": render_participant()
   │     number format + 1 · group (shared controls, prefix ch)
   │     Backdoor.generate(parameters) in ch_backdoor, regenerated only
   │       when the group changes (it exists whatever device Alice uses)
   │     2 · Alice's device: DeviceKind HONEST | COMPROMISED (ch_device_kind)
   │     3 · messages: 2–5 sessions (ch_session_count), one message per
   │       direction, editable (ch_message_<i>_{alice,bob}, examples in
   │       DEFAULT_MESSAGES set through session_state so "Restore the example
   │       messages" can put them back); empty = skipped, non-ASCII = error
   │     4 · run (spinner, warning from 6144 bits): run_experiment() runs
   │       run_channel with the device or an honest participant and
   │       intercept_channel ONCE → ChannelExperiment in ch_run; ch_run_count
   │       is incremented
   │     one st.tab per session: render_component_channel_session (exchange,
   │       KDF, messages); stale if group, backdoor or device kind changed
   └── "Attacker":    render_attacker() on the last run (never the device kind)
         number format (prefix ch_attacker)
         1 · what you know: group, ciphersuite, render_component_backdoor
         2 · transcript: render_component_transcript (one tab per session)
         3 · workbench, session selector ch_attacker_session:
             step 1 candidates from experiment.interception (never recomputed):
               render_component_recovery (both rejected with an honest device)
             step 2 a_i → s_i, step 3 s_i → K_i (derive_key),
             step 4 K_i (hex) + message → decrypt, or the tag failure only
               (no unauthenticated decryption is ever shown)
             each field: _render_workbench_input with "Paste <symbol>" buttons
               (a_i, or â1 and â2 with an honest device) and a "Ready to
               paste" hint; fields start empty
         4 · summary: render_component_interception_summary (table + expander
             comparing with the device's derivations), Eve callout
```

- **Workbench keys** are `<prefix>_<run count>_<session>` (`_workbench_key`):
  a widget that is not rendered loses its value, so changing the session or
  running again empties every field and its result. Do not go back to one
  key per field cleared by callbacks: that did not clear in the browser.
- **Performance.** Every widget change reruns the whole page, and with
  FFDHE8192 one `pow` takes about a second. Expensive work is done once and
  kept: `intercept_channel` runs with the channel and its result lives in
  `ChannelExperiment.interception` (step 1 and the summary read it); step 2
  reuses `InterceptedSession.shared_secret` when the pasted key is the
  recovered one and otherwise memoizes with `lru_cache` (`_shared_secret`);
  `render_component_backdoor` reads Y from the configuration instead of
  computing `g^X`; RFC groups are built once (`controls._standard_group`,
  `functools.cache`). Running the channel itself stays slow with large
  groups (about 15 s per session with FFDHE8192).
- **`content/encrypted_channel.py`**: intro, concept, participant and
  attacker builders, `DEFAULT_MESSAGES`, `session_step_definitions(i)` (3
  steps of a session) and `workbench_step_definitions(i)` (4 attacker steps),
  and the callouts (device choice, messages tip, indistinguishable, artifacts,
  first session, recovery failed, Eve).
- **`components/encrypted_channel.py`**: `DeviceKind`, `ChannelExperiment`
  (device kind, attacker, configuration, run, derivations, interception;
  `.parameters`), `render_component_step(number, definition)` (the bordered
  step container, returned for the caller to fill), and
  `render_component_{channel_session,key_derivation,encrypted_message,
  transcript,recovery,interception_summary}`. `render_component_recovery`
  takes `SetupCandidates` plus the recovered key or `None`.

#### Section navigation (`components/navigation.py`)

A section with tabs gets a sidebar and sticky tabs, so the reader moves
around without scrolling back; a section without tabs (DH) gets only the
sidebar. The sidebars list the `h2`/`h3` of the concept and formulae tabs and
the numbered `st.header`s (`dh-*`, `yy-*`, `ch-*` anchors), never the
timeline steps.

- `SectionTab(title, icon, anchors)` describes a main tab (`.label` is
  `"<icon> <title>"`, the tab label and its state value) and
  `PageAnchor(label, anchor)` one of its headings. Page headings get stable
  ids with `st.header(..., anchor="<prefix>-<name>")`; Markdown headings from
  the composer keep the ids Streamlit derives from their text, so the page
  lists those ids by hand (change both together).
- `render_component_section_tabs(tabs, *, state_key)` renders
  `st.tabs(..., key=state_key, on_change="rerun")` inside a container keyed
  `section-tabs-<state_key>`. Tabs are stateful (every switch reruns) but all
  of them still render, so widgets keep their values; never skip a tab with
  `.open`, or its widgets lose their state.
- `render_component_section_sidebar(tabs, *, state_key)` renders, in
  `st.sidebar`: "On this page" (one button per tab, whose callback sets
  `st.session_state[state_key]`; the active tab is tinted and lists its
  headings as anchor links) and "Sections" (`st.page_link` to home and every
  section; Streamlit highlights the current one). Call it after the tabs'
  content, so a run made in this rerun is already visible (the channel hides
  the Attacker headings until there is a run).
- `render_component_page_sidebar(anchors, *, key_prefix)` is the same
  sidebar for a section without tabs: "On this page" lists the anchors
  directly (container `section-anchors-page-<prefix>`, not indented), then
  "Sections". Both sidebars share `_render_sidebar_anchors` and
  `_render_sidebar_sections`.
- `css/styles/section_navigation.css` (injected by the sidebar) gives the
  sidebar the header palette in both themes, makes only the keyed tab list
  sticky (`top: 3.75rem`, under the 60 px header, translucent blurred
  background because Streamlit exposes no theme variables) and sets
  `scroll-margin-top` on headings so anchors land below the tabs. Selectors
  are those of Streamlit 1.63; recheck them after an upgrade.
- On narrow screens Streamlit collapses the sidebar. The same stylesheet
  turns its faint expand toggle (`[data-testid="stExpandSidebarButton"]`)
  into a pill labelled "On this page" (CSS `::after`), so readers notice it.

#### UX rules for interactive sections

- No page menu. Every section is reachable from a home card and has a back
  link to home; sections with tabs also have the sidebar above.
- Cryptographic values always go in wrapped code blocks via
  `render_component_value` (integers), `render_component_bytes` (byte
  strings, always hexadecimal in groups of 4 bytes via `format_bytes`) or
  `render_component_text` (messages): never horizontal scroll, and always a
  visibility badge. `highlight=True` tints the block orange (a keyed
  container `computed-value-*` styled in `protocol.css`); use it only for
  values the reader has just computed in the attacker's workbench, and
  leave the rejected candidate untinted.
- Never repeat modular exponentiations on every rerun: compute once with the
  run and keep the result in the run's value object, or memoize.
- Explain before showing: every step has plain-language text, a general
  formula, and concrete values when they are small enough.
- Toy groups are labeled insecure; RFC groups are labeled as standardized.

- **Naming**: `render_page_<name>()` in `pages/`,
  `render_component_<name>()` in `components/`, and
  `build_<name>_content() -> str` in `content/`.
- **`ContentComposer`** is a fluent Markdown builder: `h1`–`h3`,
  `paragraph(*parts)`, `bullet_list`, `ordered_list`, `quote`, `image`,
  `divider`, `formula(latex)` (a display `$$…$$` block), `block(str |
  CalloutComposer)`, and the static inline helpers `bold`, `italic`, `code`
  and `math(latex)` (`$…$`). `build()` joins the blocks with blank lines.
- **LaTeX** is rendered by Streamlit's KaTeX: `$…$` / `$$…$$` in
  `st.markdown` (via the composer), and `st.latex(...)` for standalone
  formulas. Streamlit text elements such as `st.success` and labels also
  accept `$…$`. KaTeX does **not** render inside raw HTML, so
  `CalloutComposer` content must use HTML (`<em>g<sup>a</sup></em>`) instead
  of `$…$`. Write LaTeX in raw strings (`r"…"`, `rf"…"`) to avoid invalid
  escape sequences such as `"\le"`.
- Show bounds and relations as formulas (`$1 \le a \le q - 1$`) instead of
  printing huge raw numbers in UI text.
- **`CalloutComposer(type, title, content)`** is frozen. `type` must be one
  of `note`, `tip`, `warning`, `danger`, `info` or `success`, and each has
  a classmethod constructor (`CalloutComposer.info(content, title=...)`).
  `build()` returns HTML. `css()` returns an inline `<style>` block that
  every page using callouts must emit once.
- **Two styling paths exist**. Header and footer use external CSS from
  `css/styles/*.css` with BEM classes (`site-header__*`, `site-footer__*`),
  passed through `render_html`. Callouts embed their CSS in Python.
  Page-wide rules (e.g. `protocol.css`) are injected with
  `render_html("", css=load_css(...))`.
- `render_template(name, **ctx)` builds a `jinja2.Template` from
  `html/templates/<name>`, read as UTF-8. `load_css(name)` reads
  `css/styles/<name>`. Both resolve paths relative to their own module.
- The version has a single source, `pyproject.toml` (`1.0.0`):
  `kleptography.__version__` reads it from the installed package metadata,
  and the header and footer import it. Other header and footer metadata
  (release date, author, links, and the `kleptographic_mechanisms` list) is
  **hardcoded** in `components/*.py`. The footer links point to the
  repository, to `docs/` on `main` (`.../tree/main/docs`) and to its
  `LICENSE`. Header pills stay short: `kleptographic_mechanisms`
  names the targeted cryptosystem (`"Diffie-Hellman"` covers the SETUP and
  the encrypted channel), not each section. Add an entry only for a new
  target (e.g. RSA).
- Widgets use explicit `key=`s prefixed by the section (`dh_…`), and
  section state lives in `st.session_state` under the same prefix.
- Prefer Material icons (`:material/name:`) and Markdown badges
  (`:blue-badge[…]`) over emoji in new UI.
- UI text is English. Educational content is written as Python code using
  the composer, not as `.md` files.

### 4.6 Kleptographic code (`crypto/dh/setup/`)

The package depends on the honest DH modules, and they never import it
(`tests/crypto/dh/setup/test_setup_isolation.py` checks this). Its
docstrings keep the paper's names (`c1`, `m1`, `a`, `b`, `W`, `t`, `H`).

```text
setup/
├── exceptions.py    # SetupError(DiffieHellmanError); InvalidSetupConfiguration,
│                    # SetupRecoveryError (both also ValueError)
├── hashing.py       # SetupHashFunction (Protocol), hash_to_exponent = paper's H
├── configuration.py # YoungYungConfiguration (frozen, kw_only): parameters,
│                    # attacker_public_key (Y), multiplier_a, offset_b,
│                    # correction_w (W, odd), hash_function
├── records.py       # SetupDerivation, SetupCandidates, SetupRecovery (frozen)
├── construction.py  # pure equations: compute_z, derive_setup,
│                    # derive_private_key (device); compute_r,
│                    # recover_z_candidates (attacker)
├── participant.py   # YoungYungDiffieHellmanParticipant(DiffieHellmanParticipant)
└── attacker.py      # YoungYungAttacker(parameters, private_key X)
```

Equations (group of prime order q, exponents reduced modulo q):

```text
device:   z = g^(c1 - W*t) * Y^(-a*c1 - b) mod p,   c2 = H(z)
attacker: r = m1^a * g^b,  z1 = m1 / r^X,  z2 = z1 / g^W   (mod p)
          c2 = H(z1) if g^H(z1) == m2, else H(z2) if it matches, else error
```

- **`hash_to_exponent(z, *, parameters)`**: SHAKE-256 over the domain tag
  `b"young-yung-setup-H"` followed by z encoded big-endian with the byte
  length of p (fixed width, as I2OSP). The output has 8 extra bytes over q
  and is reduced as `digest mod (q - 1) + 1`, so it lies in [1, q − 1] with a
  bias below 2^-64. Raises `ValueError` unless `1 <= z < p`.
- **`YoungYungConfiguration`** validates Y as a public value of its group
  (`InvalidPublicKey`), and raises `InvalidSetupConfiguration` if
  a ≡ 0 (mod q), W is even, or W ≡ 0 (mod q). In the prime-order subgroup,
  "W odd" has no mathematical effect; it is kept for fidelity to the paper.
- **`construction.py`**: division modulo p is done with `mod_inverse`, never
  `/`. `derive_setup` returns a `SetupDerivation(previous_private_key,
  correction_bit, z, private_key)`; `derive_private_key` returns only its
  `private_key`. `compute_r(m1, *, configuration)` returns r (note that
  r^X = Y^(a·c1 + b), the mask shared by device and attacker).
- **Device** (`YoungYungDiffieHellmanParticipant(parameters,
  configuration)`): raises `DiffieHellmanParametersMismatch` if the two groups
  differ. It overrides `_generate_private_key`: an honest c1 when no key is
  stored, and `derive_setup(c1, t)` afterwards. It is a drop-in argument to
  `perform_key_exchange` (principle 2: separate class, no flag). Each later
  `generate_keypair()` chains from the previous exponent (c3 from c2, …).
  `super()` without arguments breaks in `slots=True` dataclasses on
  Python < 3.14, so parent methods are called explicitly
  (`DiffieHellmanParticipant._generate_private_key(self)`).
- The bit t is sampled in `_sample_correction_bit()`. Tests force it by
  monkeypatching that method **on the class**, because slotted instances
  reject instance attributes.
- **Attacker** (`YoungYungAttacker(parameters, private_key)`, frozen):
  `public_key`, `generate(parameters)`, `generate_configuration(*,
  hash_function=hash_to_exponent)` (random a, b in [1, q − 1] and odd W in
  [1, q − 2]; skips the degenerate a·X ≡ 1 (mod q), where z would not depend
  on c1; raises `InvalidSetupConfiguration` if q < 3), `recover(...)`,
  `recover_private_key(...)` and `recover_shared_secret(...)`. All recovery
  methods take `first_public_key`, `second_public_key` and `configuration`
  as keywords, raise `InvalidSetupConfiguration` if the configuration is for
  another group or does not embed this attacker's Y, `InvalidPublicKey` for
  invalid public values, and `SetupRecoveryError` if neither candidate
  reproduces m2.
  - `recover` is split in two public steps, so a failed recovery still
    shows its work: `compute_candidates(*, first_public_key, configuration)
    -> SetupCandidates(first_public_key, r, z_candidates,
    private_key_candidates)` uses m1 alone (validates the configuration and
    m1), and `match_candidates(candidates, *, second_public_key) ->
    SetupRecovery` validates m2 and keeps the candidate that reproduces it,
    or raises `SetupRecoveryError`.
- **Model for the UI.** SETUP internals happen outside `perform_key_exchange`
  (the derivation runs in `generate_keypair()` before the second exchange,
  and recovery is done by an outside party), and the device does not know
  whether it plays Alice or Bob, so they are exposed as value objects
  instead of tracing events:
  - `device.derivations`: a tuple snapshot of every `SetupDerivation`
    (c_{i-1}, t, z, c_i) of the current chain, in order. An honest generation
    or `load_private_key` starts a new chain and empties it. In the channel
    (4.7), session i ≥ 2 matches `derivations[i - 2]`, so one `run_channel`
    call is enough for the UI to show every derivation. Hidden from `repr`.
  - `device.last_derivation`: `derivations[-1]`, or `None` when the chain
    has no SETUP generation yet.
  - `attacker.recover(...)`: a `SetupRecovery(first_public_key,
    second_public_key, r, z_candidates, private_key_candidates,
    correction_bit, private_key)`. `correction_bit` is the t the attacker
    infers (the first matching candidate).

  Intended flow for the section: `attacker = YoungYungAttacker.generate(p)`
  → `configuration = attacker.generate_configuration()` → `device =
  YoungYungDiffieHellmanParticipant(p, configuration)` → exchange 1 with an
  observer (c1 is traced as generated) → `device.generate_keypair()` and
  read `device.last_derivation` → exchange 2 with an observer (c2 is traced
  as provided) → `attacker.recover(...)` / `recover_shared_secret(...)` from
  the `PUBLIC_KEY_SENT` values of both timelines.
- Test vectors (toy group 23/2/11, X=3, Y=8, a=2, b=2, W=3,
  H(v)=v mod 10 + 1, c1=6, m1=18): t=0 → z=3, c2=4, m2=16; t=1 → z=9,
  c2=10, m2=12. The attacker gets r=8 and candidates (3, 9) → (4, 10). The
  honest peer b=7 (B=13) gives the secrets 18 and 16.
- The former open points (exact equations, motivation of a and b, behaviour
  from the third exchange onward, weak/regular/strong classification) are
  **closed by the maintainer's decision**: do not reopen them or list them as
  pending in the UI. The formulae tab presents the construction as a
  (1,2)-leakage scheme and lists only implementation choices.

Honest and kleptographic implementations must be directly comparable in
tests and in the UI, including the fact that their outputs are
indistinguishable.

### 4.7 Encrypted channel compromised by the SETUP

Status: **`crypto` done (AEAD, KDF, channel and attacker); UI pending.**
It extends the Young–Yung case
study from the key exchange to a complete cryptosystem, to show that a
malicious key establishment compromises the whole channel without breaking
any cipher.

**Model.** Alice (the compromised device) and Bob (honest) run N sessions in
a row (2 ≤ N ≤ 5, enforced by the UI; `crypto` accepts N ≥ 1). Each session
is one ephemeral DH exchange, a session key `K_i = KDF(s_i)`, and short
ASCII messages in both directions encrypted under `K_i`. The attacker knows the whole system (Kerckhoffs) and holds only X and
the configuration. From the public transcript, each consecutive pair
`(A_{i-1}, A_i)` gives `a_i` (the existing `recover`), so the
attacker decrypts sessions 2…N. **Session 1 stays confidential**: it is the
(1,2)-leakage made visible at the application level. Eve, with the same
transcript and no X, reads nothing.

**Primitives** (all from `cryptography`, never reimplemented):

- **KDF** (`crypto/kdf/`): NIST SP 800-56C Rev. 2 one-step KDF with SHA-256,
  via `ConcatKDFHash`: `K = SHA-256(0x00000001 ‖ Z ‖ OtherInfo)`, 32 bytes.
  `Z` is the shared secret big-endian with the byte length of p (fixed width,
  as I2OSP, like the SETUP's H). `OtherInfo` is a fixed label. No salt and
  no randomness: the key is a deterministic function of the shared secret,
  which is exactly what the attacker exploits. **Done**:
  - `records.py`: `KEY_SIZE = 32` and the frozen `KeyDerivation(shared_secret,
    encoded_secret, other_info, key)`, which exposes every intermediate value
    for the UI. It checks that `encoded_secret` encodes `shared_secret` and
    that the key is 32 `bytes` (`InvalidKeyDerivation`). The secret, `Z` and
    the key are hidden from `repr`.
  - `one_step.py`: `OTHER_INFO = b"kleptography-encrypted-channel"` and
    `derive_key(shared_secret, *, secret_length) -> KeyDerivation`. The
    caller passes the byte length of p as `secret_length`, so `kdf` never
    sees DH parameters. It raises `InvalidKdfInput` unless both arguments
    are integers (not `bool`), `secret_length >= 1` and
    `1 <= shared_secret < 256^secret_length`.
  - `exceptions.py`: `KdfError` (independent of the DH and AEAD hierarchies),
    `InvalidKdfInput` and `InvalidKeyDerivation`, both also `ValueError`.
  - Tests recompute every key with `hashlib`
    (`SHA-256(0x00000001 ‖ Z ‖ OtherInfo)`), pin one vector (toy secret 6,
    1 byte), and include an isolation test (`kdf` imports only itself).
- **AEAD** (`crypto/aead/`): AES-256-GCM, 96-bit nonce from `secrets`, 128-bit
  tag, no associated data. The nonce is random but public: it travels with
  the ciphertext, so it adds no secret. A wrong key fails the tag check,
  which is how "the attacker cannot read session 1" shows up. **Done**:
  - `records.py`: `NONCE_SIZE = 12`, `TAG_SIZE = 16` and the frozen
    `EncryptedMessage(nonce, ciphertext, tag)`, all public. It validates the
    nonce and tag sizes (`InvalidAeadNonce`, `InvalidAeadTag`; `bytes` only).
    The ciphertext is as long as the plaintext, and the tag is kept apart
    (the library returns `ciphertext ‖ tag`) so the UI can show each field.
  - `aes_gcm.py`: `KEY_SIZE = 32`, `generate_nonce()` (`secrets.token_bytes`),
    `encrypt(key, plaintext, *, nonce=None)` and `decrypt(key, message)`.
    Only 32-byte keys are accepted (`InvalidAeadKey`, even for valid AES-128
    or AES-192 sizes). The `nonce` argument exists for test vectors and
    reproducible demos; reusing it under one key is insecure. Any tag
    failure (wrong key or tampering) raises `AeadAuthenticationError`,
    chained from the library's `InvalidTag`.
  - `exceptions.py`: `AeadError` (independent of `DiffieHellmanError`) and the
    four errors above, all also `ValueError`.
  - Tests use test cases 13–15 of McGrew–Viega's GCM specification and an
    isolation test (`aead` imports only itself).
- Both packages take integers or bytes and **never import `dh`**, so they can
  be reused by future targets (RSA, ML-DSA).

**Layout** (dependency direction
`channel/setup → channel → {dh, dh/setup only in channel/setup, kdf, aead}`):

```text
crypto/kdf/        exceptions.py, one_step.py (derive_key), records.py
                   (KeyDerivation: shared_secret, encoded_secret, other_info, key)
crypto/aead/       exceptions.py, aes_gcm.py (encrypt/decrypt), records.py
                   (EncryptedMessage: nonce, ciphertext, tag)
crypto/channel/    exceptions.py, records.py (session and transcript value
                   objects), session.py (run_session), protocol.py (run_channel)
crypto/channel/setup/  exceptions.py, records.py (InterceptionOutcome,
                   InterceptedMessage, InterceptedSession, ChannelInterception),
                   attacker.py (intercept_channel)
```

- **One channel, no SETUP variant.** `crypto/channel/` is the ordinary
  protocol: its code holds no kleptographic logic and works with any
  `DiffieHellmanParticipant`. It is *not* an "honest-only" channel: the case
  study runs it with the device as Alice,
  `run_channel(device, DiffieHellmanParticipant(parameters), sessions)`. The
  device is a drop-in replacement (principle 2): before every session the
  channel calls `generate_keypair()` on both participants (ephemeral DH), and
  the device's override is what chains the exponents. Never add a SETUP
  copy of the channel or a flag; the only kleptographic code is the attacker
  in `channel/setup/`. Whether the UI also shows an honest Alice for
  comparison is a UI decision.
- **Channel (done)**:
  - `records.py` has two views of the same communication.
    - **Input**: `PlainMessage(sender, text)`, where `sender` is
      `Actor.ALICE` or `Actor.BOB` from `dh.tracing` (the recipient is the
      other one). `text` is printable ASCII (`isascii() and isprintable()`:
      no newlines or tabs) of 1 to `MAX_MESSAGE_LENGTH = 140` characters.
      Otherwise it raises `InvalidChannelMessage`, as does any sender that
      is not one of those two `Actor` members.
    - **Private view**: `ChannelMessage(sender, plaintext, encrypted,
      received_plaintext)` with `.delivered`; `ChannelSession(number,
      events, alice_public_key, bob_public_key, alice_key_derivation,
      bob_key_derivation, messages)` with `.keys_match` (`events` hidden
      from `repr`); `ChannelRun(parameters, sessions)`.
    - **Public view**, built by the `.transcript` property of each private
      record: `TranscriptMessage(sender, encrypted)`,
      `SessionTranscript(number, alice_public_key, bob_public_key,
      messages)` and `ChannelTranscript(parameters, sessions)`. This is all
      Eve and the attacker see.
    - Session numbers start at 1. Runs and transcripts need at least one
      session, numbered 1, 2, … in order (`InvalidChannelSessions`).
  - `session.py`: `run_session(alice, bob, messages, *, number)`.
    1. Checks that both groups match (`DiffieHellmanParametersMismatch`,
       before any key is generated).
    2. **Always** calls `generate_keypair()` on Alice, then Bob, replacing
       any loaded key: ephemeral DH, so chosen keys are not supported. The
       timeline therefore traces both keys as `PRIVATE_KEY_PROVIDED`.
    3. Runs `perform_key_exchange` with its own `ProtocolExecutionContext`.
    4. Each party runs `derive_key(own secret,
       secret_length=parameters.byte_length)`.
    5. Each message is encrypted with a random nonce under the sender's key
       and decrypted under the recipient's key.
  - `protocol.py`: `run_channel(alice, bob, sessions)` runs one session per
    entry (a sequence of `PlainMessage`s, possibly empty), numbered from 1.
    It raises `InvalidChannelSessions` if `sessions` is empty and checks the
    groups before running any session.
  - `exceptions.py`: `ChannelError` (independent of the DH, KDF and AEAD
    hierarchies), `InvalidChannelMessage` and `InvalidChannelSessions`, both
    also `ValueError`. DH errors propagate unwrapped.
  - Tests fix private keys by monkeypatching
    `DiffieHellmanParticipant._generate_private_key` **on the class** with an
    iterator, which also fixes the device's honest c1. The isolation test
    allows only `channel`, `dh`, `kdf` and `aead` imports, and never
    `dh.setup` or `channel.setup`. The device is used only in tests.
- **Attacker (done)**, `channel/setup/`: the only kleptographic code of the
  channel. It follows the `dh/setup/` rules (paper names, isolation test)
  and has no symmetric code of its own.
  - `attacker.py`: `intercept_channel(transcript, *, attacker,
    configuration) -> ChannelInterception`. It takes only the public
    `ChannelTranscript`. It first raises `InvalidSetupConfiguration` if the
    configuration does not embed this attacker's Y or group, and
    `DiffieHellmanParametersMismatch` if the transcript uses another group,
    whatever the number of sessions. Session 1 is `NOT_RECOVERABLE`. For
    each i ≥ 2 it validates `B_i` (`InvalidPublicKey`), runs
    `compute_candidates(A_{i-1})` then `match_candidates(…, A_i)` (not
    `recover_shared_secret`, to keep the candidates and the `SetupRecovery`
    for the UI), computes `s_i = B_i^{a_i}`,
    `derive_key(s_i, secret_length=parameters.byte_length)` and decrypts
    every message. A `SetupRecoveryError` (e.g. honest Alice) becomes
    `RECOVERY_FAILED`, never an exception, and keeps its rejected
    candidates, so the UI can apply the same attacker to an honest channel
    and follow the chain to a wrong key. A message whose GCM tag fails (only a
    tampered ciphertext: a matching candidate is `a_i` itself) gets
    `plaintext=None`.
  - `records.py`: `InterceptionOutcome` (`StrEnum`: `NOT_RECOVERABLE`,
    `RECOVERY_FAILED`, `RECOVERED`); `InterceptedMessage(transcript,
    plaintext)` with `.sender`, `.encrypted`, `.readable`;
    `InterceptedSession(transcript, outcome, candidates, recovery,
    shared_secret, key_derivation, messages)` with `.number`, `.recovered`,
    `.readable`;
    `ChannelInterception(parameters, sessions)`. Invariants
    (`InvalidChannelInterception`): only session 1, and always session 1,
    is `NOT_RECOVERABLE`; every session but the first has `candidates`;
    messages wrap exactly the transcript's; a recovered session has its
    recovery (built from its candidates and targeting `A_i`), secret and key
    (derived from that secret); any other session reveals nothing.
  - `exceptions.py`: `InvalidChannelInterception(ChannelError, ValueError)`.
  - In a toy group an honest `a_i` can equal a SETUP candidate by chance
    (about 2/q), and the attacker then really reads that session; a test
    pins this (q = 11, keys 6 → 10).
  - For comparison with the device's truth, session i ≥ 2 matches
    `device.derivations[i - 2]` (4.6).
- **Didactic model**: like 4.6, no new tracing events. Every intermediate
  value (Z bytes, key, nonce, ciphertext, tag, recovered secret) is exposed
  through frozen value objects, so the UI can show each step. Each session's
  DH exchange keeps its own `ProtocolExecutionContext` timeline.
- The transcript type holds only public data (public keys, encrypted
  messages); the attacker API takes it as its only view of the
  communication, which makes "public information only" explicit.
- Toy groups give shared secrets of a few bits, so `K_i` is brute-forceable
  by anyone; the UI must say so, as it does for DH.

**Tests** (mirroring the tree, unique basenames such as
`test_kdf_one_step.py`, `test_aead_aes_gcm.py`, `test_channel_session.py`,
`test_channel_attacker.py`): KDF vectors computed independently with
`hashlib`, GCM round trip and tamper/wrong-key failure, channel (Bob
decrypts everything, with honest and device participants), attacker
decrypts sessions 2…N and fails on session 1, device transcripts pass the
same validation as honest ones, and isolation (`kdf`/`aead` never import
`dh`; `channel` never imports `channel.setup` or `dh.setup`; `channel.setup`
imports only `channel`, `dh`, `kdf`, `aead` and `math`).

**UI**: its own page `/encrypted-channel`, not a tab of the SETUP section
(see 4.5, "Encrypted channel section").

### 4.8 Developer documentation (`docs/`)

Markdown only (no site generator), in English, linked from the README
("Documentation" section) and the footer.

```text
docs/
├── README.md        index, reading paths, how to regenerate diagrams
├── architecture.md  layers, dependency table, isolation tests, conventions
├── math.md · dh.md · setup.md · primitives.md · channel.md · app.md
└── images/
    ├── kleptofox.png                      (README logo)
    └── diagrams/<name>.svg + <name>.png   architecture, dh-exchange,
                                           setup-chain, channel-session
```

- Pages describe the `crypto` and `math` API (purpose, usage, reference,
  errors, limitations); `app.md` only explains how sections use the API,
  not the visual design. `channel.md` documents `channel/setup/` briefly
  and points to its source and tests, without a step-by-step walkthrough or
  a diagram.
- Every ```` ```python ```` block is runnable and uses the toy group
  23/2/11 (random toy groups only where noted). Ruff formats these blocks
  (`ruff format --check .` covers `docs/`). Illustrative, non-runnable
  snippets use ```` ```py ````.
- Diagrams are hand-written SVG (the source) exported to PNG at 2x with
  headless Chrome (command in `docs/README.md`; `--window-size` = SVG
  size). Code text uses `white-space: pre`, since Chrome collapses spaces in
  SVG text. Keep the shared style: honest blue, kleptographic red, public
  orange, external dashed; toy values in green.
- Every value in pages and diagrams was produced by running the code.
  **When an API, a value object or an equation changes, update the
  matching page and diagram in the same change.**

## 5. Known limitations

There are no pending cleanups. These limitations are known and accepted;
only address them when a task asks for it.

- The interactive sections have not been reviewed visually in a browser by
  an agent; they were only executed headless with `streamlit.testing`
  (AppTest), without rendering KaTeX or Markdown tables. The maintainer
  reviewed the encrypted channel section in the browser.
- Streamlit 1.63 (Starlette server, no Tornado fallback) logs a
  `RuntimeError: WebSocket is not connected` / `Cannot call "send" once a
  close message has been sent` traceback from its own websocket handler when
  it sends to a browser that already left, most likely after a reload during
  a long run. It is not raised by project code and does not affect the app;
  it could not be reproduced with a plain client disconnect.
- The SETUP section does not yet show an honest device side by side with
  the compromised one (4.6 asks for them to be directly comparable); it
  states that the transcript passes the same validation instead.

## 6. Code conventions

- **Imports are absolute from `kleptography.`**, never `src.kleptography.`.
  Importing the same file under both names creates two distinct classes and
  breaks test collection.
- Start new modules with a docstring and `from __future__ import annotations`.
- Use frozen, slotted dataclasses for value objects
  (`@dataclass(frozen=True, slots=True)`), validated in `__post_init__`.
- Make functions that take several integers (`prime`, `generator`,
  `subgroup_order`, …) keyword-only (`*,`) so `p`, `g` and `q` cannot be
  swapped by position.
- Use descriptive names (`prime`, `generator`, `subgroup_order`,
  `private_key`, `public_key`, `shared_secret`), not single letters. Keep
  the math notation (`p`, `g`, `q`, `x`) for docstrings and educational
  text.
- Put DH errors in `crypto/dh/exceptions.py`, subclassing
  `DiffieHellmanError` plus the matching builtin. New schemes get their own
  hierarchy.
- Generate secrets with `secrets`, never with `random`. Test primality
  through `sympy`.
- Docstrings follow the Google style (PEP 257): the summary on the first
  line, then `Args:` / `Returns:` / `Raises:` for public functions and
  methods, and `Attributes:` (plus `Raises:` for validation) for classes and
  dataclasses. Private helpers get a one-line summary. Every module and
  package has a docstring. Inline code uses double backticks.
- Ruff enforces formatting and linting (line length 88, rules `D`, `E`, `F`,
  `I`; `D` uses the Google convention and ignores `D105`/`D107`, magic
  methods and `__init__`) and `ty` enforces type checking. Type-annotate every function, including
  test functions and fixtures.
- Write user-facing text, docstrings and identifiers in English.

## 7. Tests

- Mirror the source tree: `src/kleptography/x/y.py` → `tests/x/test_y.py`.
  There is no `conftest.py`; fixtures are defined per module.
- Every test module starts with a docstring: `Tests for <subject>.` (or
  `Isolation tests for <package>.`), then a paragraph on what the tests
  check, then the test vectors if any. Every test, fixture and helper has a
  one-line docstring stating the behaviour checked, without repeating the
  test name.
- Keep tests deterministic. Use the toy group `p=23, g=2, q=11` as a
  fixture, and fix keys with `participant.load_private_key(x)`. Reference
  values: `x_A=6 → y_A=18`, `x_B=7 → y_B=13`, shared secret `6`. A second
  valid group for mismatch tests is `p=47, g=2, q=23`. Use `generate_toy()`
  only where randomness is the property under test, and assert invariants
  rather than values.
- Test directories have no `__init__.py`, so **test file basenames must be
  unique across the whole `tests/` tree** (e.g. `test_setup_participant.py`
  next to `test_participant.py`, or `test_html_loader.py` and
  `test_css_loader.py`, not two `test_loader.py`).
- RFC group tests check primality of `p` and `q`, `g^q ≡ 1`, bit length,
  and the exact RFC constants.
- Cover mathematical correctness, invalid inputs and boundary values,
  expected exception types, and exact emitted event sequences. A test that
  only checks that something returns a value is not enough for crypto code.
- For kleptographic code, test at least that honest parties still agree on
  the secret, that the attacker recovers the intended value, and that the
  outputs pass the same validation as honest outputs.
- Never start Streamlit in tests. Test `app` helpers as plain functions and
  patch `streamlit` calls with `unittest.mock.patch`, as in
  `tests/app/html/test_renderer.py`.

## 8. Commands

All tooling runs through `uv`. Never call `pip` or create virtualenvs
manually.

```bash
uv sync                                   # install deps (incl. dev group)
uv run pytest                             # tests (~25 s, mostly primality checks of RFC groups)
uv run coverage run -m pytest && uv run coverage report
uv run ruff check .                       # lint
uv run ruff format .                      # format
uv run ty check                           # type check
uv run streamlit run src/kleptography/app/main.py   # launch the app
```

**Definition of done:** `pytest`, `ruff check .`, `ruff format --check .`
and `ty check` all pass. CI (`.github/workflows/ci.yml`) runs them on every
push, with tests on Python 3.12, 3.13 and 3.14. Pre-commit runs Ruff and ty
locally.

Runtime dependencies: `streamlit`, `sympy`, `jinja2` and `cryptography`
(standard primitives such as SHA-2 or AES, e.g. for the SETUP's hash H;
never reimplement a primitive it provides). Dev dependencies:
`pytest`, `coverage`, `ruff`, `ty` and `pre-commit`. The build backend is
`hatchling`. Add dependencies with `uv add <pkg>` (or `uv add --dev <pkg>`)
and keep `uv.lock` committed. If code imports a package directly, declare
it directly in `pyproject.toml`. The `gh` CLI is not installed in the local
environment.

## 9. Workflow

- **Never commit, push, or create branches, tags or PRs.** Leave all changes
  uncommitted in the working tree for the maintainer to review. This applies
  even when a task seems finished.
- Work comes from GitHub issues (`danielsp13/kleptography`). Do the
  smallest change that satisfies the issue and follow existing patterns
  before introducing new abstractions.
- **Never record issue numbers in `CLAUDE.md`**, even when the maintainer
  mentions them in a task. Keep this file limited to the context needed to
  work on the code: current state, architecture, conventions and commands,
  not the history of how it got there.
- When suggesting a commit message, use the project format:
  `<area>: <lowercase summary>[, closes #N | , #N]`. Areas in use: `crypto`,
  `crypto-dh`, `ui`, `ui-content`, `test`, `infra` (short for
  infrastructure; both are accepted, `infra` is preferred), `ai`.
- Update `CLAUDE.md` in the same change whenever a change invalidates it
  (status, architecture, conventions, commands, known limitations).
- End each task with a report of what changed, the verification results
  (the definition-of-done commands and their output), and any assumptions
  or open questions.
