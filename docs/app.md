# Interface (`kleptography.app`)

This page explains how the Streamlit interface uses the library. It does
not cover the visual design. The rule behind every section: **`app` holds
no cryptographic or mathematical logic**. It builds `crypto` objects, runs
them once and renders the values they expose.

```bash
uv run streamlit run src/kleptography/app/main.py
```

## Layout

| Package | Role |
| --- | --- |
| `main.py`, `navigation.py` | Page configuration and the page registry (`home_page()`, `diffie_hellman_page()`, `young_yung_setup_page()`, `encrypted_channel_page()`). Streamlit's page menu is hidden; pages link to each other. |
| `pages/` | `home.py`, and one package per section (below). |
| `components/` | Reusable renderers: values with a visibility badge, protocol steps, shared controls (group selection, number format), the section sidebar. |
| `content/` | Educational text, built as Markdown with LaTeX by a small composer; formula helpers that substitute concrete values only when they are small. |
| `css/`, `html/`, `assets/` | Stylesheets, Jinja2 templates (header, footer, section cards) and the logo. |

### Page packages

Every section is a package with the same modules, so its structure reads
at a glance in `page.py`:

| Module | Role |
| --- | --- |
| `page.py` | `render_page_<name>()`: introduction, tabs or sections, sidebar, footer. Layout only. |
| `outline.py` | The tabs and headings listed by the tabs and the sidebar. |
| `state.py` | Session state and widget keys shared by several modules (prefixed `dh_`, `yy_`, `ch_`). |
| `experiment.py` | The run of the `crypto` API. It never calls Streamlit. |
| one module per tab or part | `sections.py` and `timeline.py` (DH, SETUP); `participant.py`, `attacker.py`, `workbench.py` (channel). |

## How each section uses the library

### Diffie-Hellman (`/diffie-hellman`)

`experiment.run_exchange(parameters, private_keys)` creates two
`DiffieHellmanParticipant`s (with `load_private_key` when the reader chooses
the keys), runs `perform_key_exchange` with a `ProtocolExecutionContext`, and
turns the 13 events into five teaching steps
(`content.diffie_hellman.build_protocol_steps`). The timeline is rendered
from those events alone. See [dh.md](dh.md).

### Young–Yung SETUP (`/young-yung-setup`)

`experiment.run_experiment` follows the intended flow of
[setup.md](setup.md#a-complete-run): `Backdoor.generate(parameters)` (an
attacker and its configuration), a `YoungYungDiffieHellmanParticipant` as
Alice, a first traced exchange, `generate_keypair()` and
`device.last_derivation`, a second traced exchange, and the attacker's
`recover` and `recover_shared_secret` from the `PUBLIC_KEY_SENT` values of
both timelines. The result is a `SetupRun` rendered in eight steps.

The interface uses DH notation (`a1`, `A1`, `α`, `β`) where the code keeps
the paper's (`c1`, `m1`, `a`, `b`); the Formulae tab shows the
correspondence.

### Encrypted channel (`/encrypted-channel`)

`experiment.run_experiment` runs `run_channel` with either the device or an
honest participant as Alice, and processes the public transcript once with
the `channel.setup` API. Both results are kept in a `ChannelExperiment`; the
Participant tab shows the private view of each session and the Attacker tab
shows only what the transcript allows. See [channel.md](channel.md).

## Rules the interface follows

- **Compute once.** Expensive work runs with the experiment and is kept in
  its value object (or memoized). With `ffdhe8192` one exponentiation takes
  about a second, and Streamlit reruns the whole page on every widget change.
- **Show, do not recompute.** Intermediate values are read from the records
  `crypto` returns (`SetupDerivation`, `SetupRecovery`, `KeyDerivation`,
  `EncryptedMessage`, …), never recalculated in the interface.
- **Explicit visibility.** Every value carries a badge: public, private,
  shared secret, hidden in the device, or attacker only.
- **Toy versus standardized.** Toy groups are labeled insecure; RFC 7919
  groups are labeled standardized.

## Tests

The interface is tested as plain functions with Streamlit calls patched
(e.g. the HTML renderer and the loaders). Pages and most components have no
tests yet; they were checked by running the app.
