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
| DH parameters, validation, RFC 7919 groups | Done (issue #8). |
| Honest DH participant and protocol | Done (issue #8). Five-phase execution model; supports known (loaded) and generated keys. |
| Protocol tracing (observer + event timeline) | Done. Consumed by the Diffie-Hellman section. |
| Streamlit shell: header, footer, home page, content composer | Done (issues #9, #10). Composer supports LaTeX. |
| Hidden navigation (home ↔ sections, no sidebar) | Done. |
| Interactive honest DH section (`/diffie-hellman`) | Done. Toy or RFC 7919 group, random or chosen keys, step-by-step timeline. |
| Kleptographic DH section in the UI | Placeholder card on the home page ("In research", disabled). |
| Young–Yung DH SETUP (kleptographic DH) | **Not started.** Needs a research issue first. |
| RSA / post-quantum targets | Future. |

Roadmap, as stated on the home page (`app/content/home.py`):

1. Mathematical and implementation foundations. **(done)**
2. Reference DH construction. **(done)**, including its interactive section.
3. Study and implement the Young–Yung construction.
4. Interactive experiments around it, mirroring the honest DH section.
5. Expose intermediate values and attacker knowledge.
6. Document security assumptions and limitations.
7. Apply the same methodology to other constructions.

Every case study follows the same page progression: mathematical background
→ reference construction → kleptographic construction → experiment
(both constructions under comparable conditions) → observation (what each
participant can see) → analysis.

Test suite: 316 tests. `crypto/` and `math/` are at about 100% coverage. On
the maintainer's request, the new UI modules (`navigation.py`,
`components/navigation.py`, `components/protocol.py`,
`content/diffie_hellman.py`, `content/numbers.py`, `pages/*`) **have no tests
yet. Do not add page or component tests unless a task asks for them.**

## 4. Architecture and interrelations

```text
src/kleptography/
├── math/                    # pure number theory, no project imports
│   ├── modular.py           # mod_pow, mod_inverse, is_coprime
│   └── primes.py            # generate_safe_prime, generate_subgroup_generator (sympy)
├── crypto/                  # schemes; never imports streamlit or app
│   └── dh/                  # honest finite-field Diffie-Hellman
│       ├── exceptions.py    # DiffieHellmanError hierarchy (leaf, imports nothing)
│       ├── validation.py    # validate_parameters/_private_key/_public_key
│       ├── parameters.py    # DiffieHellmanParameters
│       ├── participant.py   # DiffieHellmanParticipant
│       ├── exchange.py      # DiffieHellmanExchangeResult
│       ├── protocol.py      # perform_key_exchange
│       ├── tracing/         # events.py, observer.py, context.py
│       └── groups/rfc7919/  # ffdhe2048() … ffdhe8192()
└── app/                     # Streamlit presentation layer
    ├── main.py              # entry point: page config + hidden st.navigation
    ├── navigation.py        # page registry: home_page(), diffie_hellman_page(), all_pages()
    ├── pages/               # home.py, diffie_hellman.py
    ├── components/          # header, footer, navigation (back link, section card), protocol
    ├── content/             # composer, callouts, home, diffie_hellman, numbers
    ├── html/                # templates/*.html, loader.py, renderer.py
    ├── css/                 # styles/{header,footer,protocol}.css, loader.py
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
  - `.bit_length` is the bit length of `p`.
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

- `Actor` (`StrEnum`): `SYSTEM`, `ALICE`, `BOB`. An attacker actor does not
  exist yet; the SETUP work will need to add one.
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
  `ProtocolExecutionContext.events`. The observer pattern is the intended
  mechanism for exposing kleptographic internals (SETUP state, attacker
  recovery) as well.

### 4.5 `app` (Streamlit)

Launch with `uv run streamlit run src/kleptography/app/main.py`. The app
imports `kleptography.*` as an installed package, which `uv sync` sets up.

#### Navigation

`main.main()` calls `st.set_page_config(...)` and then
`st.navigation(all_pages(), position="hidden").run()`. There is **no
sidebar**: pages link to each other with `st.page_link`.

- `app/navigation.py` defines one factory per page: `home_page()` (default,
  URL `/`) and `diffie_hellman_page()` (URL `/diffie-hellman`). Streamlit
  identifies a page by its `url_path`, so a factory can be called wherever a
  link is needed.
- Page modules import `navigation.py` to build links, so the factories
  import the page renderers **inside the function body**. This is the
  deliberate cycle-breaker; do not move those imports to module level.
- To add a page: write `render_page_<name>()` in `pages/`, add a factory in
  `navigation.py`, add it to `all_pages()`, and add a `SectionCard` for it
  in `pages/home.py`. Start the page with `render_component_back_home()`.
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

#### Diffie-Hellman section (`pages/diffie_hellman.py`)

The page only orchestrates the `crypto` API and delegates text to `content/`
and rendering to `components/`:

```text
render_page_diffie_hellman()
   ├── render_html("", css=load_css("protocol.css")) + CalloutComposer.css()
   ├── render_component_back_home()
   ├── title + build_dh_intro_content()
   ├── number format control (Decimal / Hexadecimal)         key dh_number_format
   ├── 1 · public parameters                                  key dh_group_kind
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
   ├── 3 · run: DiffieHellmanParticipant ×2 (+ load_private_key if chosen)
   │     → perform_key_exchange(observer=ProtocolExecutionContext())
   │     → session_state["dh_run"] = ExchangeRun(parameters, build_protocol_steps(events))
   │     → session_state["dh_revealed"] = 1; InvalidPrivateKey → st.error
   └── 4 · timeline: progress bar, steps[:revealed] via
         render_component_protocol_step, then Next step / Show all steps /
         Start over (on_click callbacks update dh_revealed). If the current
         parameters differ from ExchangeRun.parameters, the run is stale:
         an info message replaces the timeline.
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
- **`content/numbers.py`**: `NumberFormat` (DECIMAL, HEXADECIMAL);
  `parse_integer(text)`; `is_small(*values)`.
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
  (Public / Private / Shared secret), the bit size, and an
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
  display formulas scroll inside themselves.

#### UX rules for interactive sections

- No sidebar. Every section is reachable from a home card and has a back
  link to home.
- Cryptographic values always go in wrapped code blocks via
  `render_component_value`: never horizontal scroll, and always a
  visibility badge.
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
- Header and footer metadata (version `"1.0.0"`, release date, author,
  links, and the `kleptographic_mechanisms` list) is **hardcoded** in
  `components/*.py`. When a new mechanism is added, update the header's
  `kleptographic_mechanisms`.
- Widgets use explicit `key=`s prefixed by the section (`dh_…`), and
  section state lives in `st.session_state` under the same prefix.
- Prefer Material icons (`:material/name:`) and Markdown badges
  (`:blue-badge[…]`) over emoji in new UI.
- UI text is English. Educational content is written as Python code using
  the composer, not as `.md` files.

### 4.6 Kleptographic code (not yet implemented)

The SETUP counterpart of DH does not exist yet. Put it in its own module or
package, separate from the honest modules above, with names that make its
nature obvious. Its concrete location must be defined in the task's issue.
If the issue does not define it, ask instead of choosing one. Honest and
kleptographic implementations must be directly comparable in tests and in
the UI, including the fact that their outputs are indistinguishable.

## 5. Known limitations and pending cleanups

Only fix these when the task asks for it, or when you are already editing
the affected code.

- The interactive section has not been reviewed visually in a browser by
  an agent; only its rendering logic was exercised.
- The UI version `"1.0.0"` differs from `pyproject.toml` `0.1.0`, and the
  footer's documentation and license URLs point to the GitHub profile, not
  the repository.
- In `components/header.py`, `description` concatenates `"...studying and"`
  with `"demonstrating..."` without a space.
- Docstring style is mixed: Google style in `math/`, NumPy style in
  `crypto/dh/validation.py` and `participant.py`, and some modules
  (`tracing/*`, `app/*`) have no module docstring.

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
- Match the docstring style of the module being edited. For new modules,
  prefer Google style (`Args:` / `Returns:` / `Raises:`).
- Ruff enforces formatting and linting (line length 88, rules `E`, `F`, `I`)
  and `ty` enforces type checking. Type-annotate every function, including
  test functions and fixtures.
- Write user-facing text, docstrings and identifiers in English.

## 7. Tests

- Mirror the source tree: `src/kleptography/x/y.py` → `tests/x/test_y.py`.
  There is no `conftest.py`; fixtures are defined per module.
- Keep tests deterministic. Use the toy group `p=23, g=2, q=11` as a
  fixture, and fix keys with `participant.load_private_key(x)`. Reference
  values: `x_A=6 → y_A=18`, `x_B=7 → y_B=13`, shared secret `6`. A second
  valid group for mismatch tests is `p=47, g=2, q=23`. Use `generate_toy()`
  only where randomness is the property under test, and assert invariants
  rather than values.
- Test directories have no `__init__.py`, so **test file basenames must be
  unique across the whole `tests/` tree** (e.g. `test_html_loader.py` and
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

Runtime dependencies: `streamlit`, `sympy` and `jinja2`. Dev dependencies:
`pytest`, `coverage`, `ruff`, `ty` and `pre-commit`. The build backend is
`hatchling`. Add dependencies with `uv add <pkg>` (or `uv add --dev <pkg>`)
and keep `uv.lock` committed. If code imports a package directly, declare
it directly in `pyproject.toml`. The `gh` CLI is not installed in the local
environment.

## 9. Workflow

- **Never commit, push, or create branches, tags or PRs.** Leave all changes
  uncommitted in the working tree for the maintainer to review. This applies
  even when a task seems finished.
- Work comes from GitHub issues (`danielsp13/kleptography`), referenced as
  `#N`. Do the smallest change that satisfies the issue and follow existing
  patterns before introducing new abstractions.
- When suggesting a commit message, use the project format:
  `<area>: <lowercase summary>[, closes #N | , #N]`. Areas in use: `crypto`,
  `crypto-dh`, `ui`, `ui-content`, `test`, `infrastructure`, `AI`.
- Update `CLAUDE.md` in the same change whenever a change invalidates it
  (status, architecture, conventions, commands, known limitations).
- End each task with a report of what changed, the verification results
  (the definition-of-done commands and their output), and any assumptions
  or open questions.
