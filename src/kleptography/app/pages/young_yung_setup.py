"""Interactive section: the Young–Yung SETUP on Diffie-Hellman, step by step.

The section has three tabs: the idea of a SETUP, the complete mathematical
development, and an experiment. The experiment only orchestrates the
``crypto`` API: it creates an attacker and the configuration it embeds in a
``YoungYungDiffieHellmanParticipant``, runs two traced exchanges between that
device and honest Bobs, and lets the attacker recover the second key from
the public values of both timelines.
"""

from __future__ import annotations

from dataclasses import dataclass

import streamlit as st

from kleptography.app.components.controls import (
    KeyMode,
    render_component_group_selection,
    render_component_number_format,
    render_component_step_navigation,
)
from kleptography.app.components.footer import render_component_footer
from kleptography.app.components.navigation import (
    PageAnchor,
    SectionTab,
    render_component_back_home,
    render_component_section_sidebar,
    render_component_section_tabs,
)
from kleptography.app.components.protocol import ValueDisplay
from kleptography.app.components.young_yung_setup import (
    SETUP_STEP_COUNT,
    SetupRun,
    render_component_backdoor,
    render_component_setup_step,
)
from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.numbers import NumberFormat, parse_integer
from kleptography.app.content.young_yung_setup import (
    build_setup_concept_content,
    build_setup_formulae_content,
    build_setup_intro_content,
    summarize_exchange,
)
from kleptography.app.css.loader import load_css
from kleptography.app.html.renderer import render_html
from kleptography.crypto.dh.exceptions import InvalidPrivateKey
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext

# Widget and session state prefix, and session state keys.
_PREFIX = "yy"
_TAB = "yy_tab"
_BACKDOOR = "yy_backdoor"
_RUN = "yy_run"
_REVEALED = "yy_revealed"

# The tabs of the section and their headings, for the tabs and the sidebar.
# The anchors of "The idea" and "Formulae" are the ones Streamlit derives
# from the Markdown headings of build_setup_concept_content and
# build_setup_formulae_content.
_TABS = (
    SectionTab(
        "The idea",
        ":material/lightbulb:",
        (
            PageAnchor("What is a SETUP?", "what-is-a-setup"),
            PageAnchor(
                "Why a public key makes the difference",
                "why-a-public-key-makes-the-difference",
            ),
            PageAnchor("Who is who", "who-is-who"),
            PageAnchor(
                "How much leaks: (m, n)-leakage schemes",
                "how-much-leaks-m-n-leakage-schemes",
            ),
            PageAnchor("Why is it so hard to detect?", "why-is-it-so-hard-to-detect"),
            PageAnchor("What is at stake", "what-is-at-stake"),
        ),
    ),
    SectionTab(
        "Formulae",
        ":material/function:",
        (
            PageAnchor("Notation", "notation"),
            PageAnchor(
                "Arithmetic in a subgroup of prime order",
                "arithmetic-in-a-subgroup-of-prime-order",
            ),
            PageAnchor("What the device computes", "what-the-device-computes"),
            PageAnchor("What the attacker computes", "what-the-attacker-computes"),
            PageAnchor(
                "Why the attacker recovers the key",
                "why-the-attacker-recovers-the-key",
            ),
            PageAnchor(
                "A Diffie-Hellman exchange hidden inside another",
                "a-diffie-hellman-exchange-hidden-inside-another",
            ),
            PageAnchor("Why nobody else can do it", "why-nobody-else-can-do-it"),
            PageAnchor(
                "One key out of two: a (1,2)-leakage scheme",
                "one-key-out-of-two-a-1-2-leakage-scheme",
            ),
            PageAnchor("Worked example", "worked-example"),
            PageAnchor("Implementation choices", "implementation-choices"),
        ),
    ),
    SectionTab(
        "Experiment",
        ":material/science:",
        (
            PageAnchor("1 · Choose the public parameters", "yy-parameters"),
            PageAnchor("2 · The attacker builds the backdoor", "yy-backdoor"),
            PageAnchor("3 · Choose the private keys", "yy-keys"),
            PageAnchor("4 · Run the experiment", "yy-run"),
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class Backdoor:
    """The attacker and the SETUP configuration it embedded in the device."""

    attacker: YoungYungAttacker
    configuration: YoungYungConfiguration


@dataclass(frozen=True, slots=True)
class ChosenKeys:
    """Private keys typed by the user: the device's a1 and Bob's b1, b2."""

    device_first: int
    peer_first: int
    peer_second: int


def render_page_young_yung_setup() -> None:
    """Render the Young–Yung SETUP section."""
    render_html("", css=load_css("protocol.css"))
    st.markdown(CalloutComposer.css(), unsafe_allow_html=True)

    render_component_back_home()

    st.title("Young–Yung SETUP on Diffie-Hellman")
    st.markdown(build_setup_intro_content(), unsafe_allow_html=True)

    concept_tab, formulae_tab, experiment_tab = render_component_section_tabs(
        _TABS, state_key=_TAB
    )

    with concept_tab:
        st.markdown(build_setup_concept_content(), unsafe_allow_html=True)

    with formulae_tab:
        st.markdown(build_setup_formulae_content(), unsafe_allow_html=True)

    with experiment_tab:
        _render_experiment()

    render_component_section_sidebar(_TABS, state_key=_TAB)
    render_component_footer()


def _render_experiment() -> None:
    """Render the Experiment tab."""
    st.markdown(
        "Build a backdoored device, run two exchanges between it and an honest "
        "Bob, and then take the attacker's seat: from the public messages "
        "alone, plus the trapdoor $X$, recover the second shared secret."
    )

    number_format = render_component_number_format(key_prefix=_PREFIX)

    st.header("1 · Choose the public parameters", anchor="yy-parameters")
    parameters = render_component_group_selection(
        key_prefix=_PREFIX, number_format=number_format
    )

    st.divider()
    backdoor = _render_backdoor_section(parameters, number_format)

    st.divider()
    chosen_keys = _render_private_keys_section()

    st.divider()
    _render_run_section(parameters, backdoor, chosen_keys)
    _render_timeline_section(parameters, backdoor, number_format)


def _render_backdoor_section(
    parameters: DiffieHellmanParameters,
    number_format: NumberFormat,
) -> Backdoor:
    """Render section 2 and return the current backdoor."""
    st.header("2 · The attacker builds the backdoor", anchor="yy-backdoor")
    st.markdown(
        "The attacker generates its key pair $(X, Y)$ and the constants "
        "$\\alpha$, $\\beta$ and $W$, and ships them, except $X$, inside Alice's "
        "device."
    )

    backdoor: Backdoor | None = st.session_state.get(_BACKDOOR)
    regenerate = st.button(
        "Generate a new backdoor",
        icon=":material/casino:",
        help="Pick a new attacker key pair and new SETUP constants.",
        key="yy_new_backdoor",
    )

    if regenerate or backdoor is None or backdoor.attacker.parameters != parameters:
        attacker = YoungYungAttacker.generate(parameters)
        backdoor = Backdoor(attacker, attacker.generate_configuration())
        st.session_state[_BACKDOOR] = backdoor

    render_component_backdoor(
        attacker=backdoor.attacker,
        configuration=backdoor.configuration,
        display=ValueDisplay(number_format, parameters.bit_length),
    )

    return backdoor


def _render_private_keys_section() -> ChosenKeys | None:
    """Render section 3 and return the chosen keys, if any."""
    st.header("3 · Choose the private keys", anchor="yy-keys")
    st.markdown(
        "The device picks $a_1$ for the first exchange and derives $a_2$ "
        "itself. Bob uses a fresh key in each exchange, $b_1$ and $b_2$. "
        "Normally they are random, but you can pick them to reproduce a run."
    )

    mode = KeyMode(
        st.segmented_control(
            "Private keys",
            options=list(KeyMode),
            default=KeyMode.RANDOM,
            required=True,
            key="yy_key_mode",
        )
    )

    if mode is KeyMode.RANDOM:
        return None

    st.latex(r"1 \le a_1,\ b_1,\ b_2 \le q - 1")
    help_text = "Decimal, or hexadecimal with the 0x prefix. Spaces are ignored."
    device_column, first_column, second_column = st.columns(3)
    texts = (
        device_column.text_input(
            "Device's first key $a_1$", key="yy_device_key", help=help_text
        ),
        first_column.text_input(
            "Bob's first key $b_1$", key="yy_bob_first_key", help=help_text
        ),
        second_column.text_input(
            "Bob's second key $b_2$", key="yy_bob_second_key", help=help_text
        ),
    )

    try:
        device_first, peer_first, peer_second = (parse_integer(t) for t in texts)
    except ValueError:
        st.info(
            r"Type the three private keys, in the range $[1,\ q - 1]$, to run "
            "the experiment.",
            icon=":material/edit:",
        )
        return None

    return ChosenKeys(device_first, peer_first, peer_second)


def _render_run_section(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    chosen_keys: ChosenKeys | None,
) -> None:
    """Render section 4 and run the experiment when the button is pressed."""
    st.header("4 · Run the experiment", anchor="yy-run")

    waiting_for_keys = (
        st.session_state.get("yy_key_mode") == KeyMode.CHOSEN and chosen_keys is None
    )

    if not st.button(
        "Run both exchanges",
        type="primary",
        icon=":material/play_arrow:",
        disabled=waiting_for_keys,
        key="yy_run_button",
    ):
        return

    try:
        run = _run_experiment(parameters, backdoor, chosen_keys)
    except InvalidPrivateKey:
        st.error(
            r"All private keys must satisfy $1 \le a_1, b_1, b_2 \le q - 1$.",
            icon=":material/error:",
        )
        return

    st.session_state[_RUN] = run
    st.session_state[_REVEALED] = 1


def _run_experiment(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    chosen_keys: ChosenKeys | None,
) -> SetupRun:
    """Run both exchanges with the device and the attacker's recovery."""
    device = YoungYungDiffieHellmanParticipant(parameters, backdoor.configuration)
    first_peer = DiffieHellmanParticipant(parameters)
    second_peer = DiffieHellmanParticipant(parameters)

    if chosen_keys is not None:
        device.load_private_key(chosen_keys.device_first)
        first_peer.load_private_key(chosen_keys.peer_first)
        second_peer.load_private_key(chosen_keys.peer_second)

    # Exchange 1: the device has no previous key, so a1 is honest.
    first_context = ProtocolExecutionContext()
    perform_key_exchange(device, first_peer, observer=first_context)

    # Between exchanges: the SETUP derives a2 from a1.
    device.generate_keypair()
    derivation = device.last_derivation
    if derivation is None:
        raise RuntimeError("The device did not derive its second key.")

    # Exchange 2: the device sends A2 = g^a2.
    second_context = ProtocolExecutionContext()
    perform_key_exchange(device, second_peer, observer=second_context)

    first_exchange = summarize_exchange(first_context.events)
    second_exchange = summarize_exchange(second_context.events)

    # The attacker only uses what travelled over the network.
    attacker = backdoor.attacker
    recovery = attacker.recover(
        first_public_key=first_exchange.device_public_key,
        second_public_key=second_exchange.device_public_key,
        configuration=backdoor.configuration,
    )
    recovered_shared_secret = attacker.recover_shared_secret(
        first_public_key=first_exchange.device_public_key,
        second_public_key=second_exchange.device_public_key,
        peer_public_key=second_exchange.peer_public_key,
        configuration=backdoor.configuration,
    )

    return SetupRun(
        parameters=parameters,
        attacker=attacker,
        configuration=backdoor.configuration,
        first_exchange=first_exchange,
        second_exchange=second_exchange,
        derivation=derivation,
        recovery=recovery,
        recovered_shared_secret=recovered_shared_secret,
    )


def _render_timeline_section(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    number_format: NumberFormat,
) -> None:
    """Render the step-by-step timeline of the last run."""
    run: SetupRun | None = st.session_state.get(_RUN)

    if run is None:
        st.caption("Run the experiment to follow it step by step.")
        return

    if run.parameters != parameters or run.configuration != backdoor.configuration:
        st.info(
            "The group or the backdoor changed since the last run. Run the "
            "experiment again to see it with the new values.",
            icon=":material/refresh:",
        )
        return

    revealed = min(st.session_state.get(_REVEALED, 1), SETUP_STEP_COUNT)

    st.progress(
        revealed / SETUP_STEP_COUNT,
        text=f"Step {revealed} of {SETUP_STEP_COUNT}",
    )

    display = ValueDisplay(number_format, run.parameters.bit_length)
    for number in range(1, revealed + 1):
        render_component_setup_step(number, run, display=display)

    render_component_step_navigation(
        state_key=_REVEALED, revealed=revealed, total=SETUP_STEP_COUNT
    )
