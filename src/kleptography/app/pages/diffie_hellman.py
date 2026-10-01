"""Interactive section: an honest Diffie-Hellman key exchange, step by step.

The page only orchestrates: it builds parameters and participants through
the ``crypto`` API, runs ``perform_key_exchange`` with a
``ProtocolExecutionContext`` and renders the recorded timeline.
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
    render_component_back_home,
    render_component_page_sidebar,
)
from kleptography.app.components.protocol import (
    ValueDisplay,
    render_component_protocol_step,
)
from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.diffie_hellman import (
    ProtocolStep,
    build_dh_intro_content,
    build_protocol_steps,
)
from kleptography.app.content.numbers import NumberFormat, parse_integer
from kleptography.app.css.loader import load_css
from kleptography.app.html.renderer import render_html
from kleptography.crypto.dh.exceptions import InvalidPrivateKey
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange
from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext

# Widget and session state prefix, and session state keys.
_PREFIX = "dh"
_RUN = "dh_run"
_REVEALED = "dh_revealed"

# The headings of the section, for the sidebar.
_ANCHORS = (
    PageAnchor("1 · Choose the public parameters", "dh-parameters"),
    PageAnchor("2 · Choose the private keys", "dh-keys"),
    PageAnchor("3 · Run the exchange", "dh-run"),
)


@dataclass(frozen=True, slots=True)
class ExchangeRun:
    """An executed exchange and the parameters it was run with."""

    parameters: DiffieHellmanParameters
    steps: tuple[ProtocolStep, ...]


def render_page_diffie_hellman() -> None:
    """Render the interactive honest Diffie-Hellman section."""
    render_html("", css=load_css("protocol.css"))
    st.markdown(CalloutComposer.css(), unsafe_allow_html=True)

    render_component_back_home()

    st.title("Diffie-Hellman key exchange")
    st.markdown(build_dh_intro_content(), unsafe_allow_html=True)

    st.divider()
    number_format = render_component_number_format(key_prefix=_PREFIX)
    parameters = _render_parameters_section(number_format)

    st.divider()
    private_keys = _render_private_keys_section(parameters)

    st.divider()
    _render_run_section(parameters, private_keys)
    _render_timeline_section(parameters, number_format)

    render_component_page_sidebar(_ANCHORS, key_prefix=_PREFIX)
    render_component_footer()


def _render_parameters_section(number_format: NumberFormat) -> DiffieHellmanParameters:
    """Render section 1 and return the selected group."""
    st.header("1 · Choose the public parameters", anchor="dh-parameters")
    return render_component_group_selection(
        key_prefix=_PREFIX, number_format=number_format
    )


def _render_private_keys_section(
    parameters: DiffieHellmanParameters,
) -> tuple[int, int] | None:
    """Render section 2 and return the chosen keys, if any."""
    st.header("2 · Choose the private keys", anchor="dh-keys")
    st.markdown(
        "Each participant needs a secret number between $1$ and $q - 1$. "
        "Normally it is chosen at random, but you can pick your own to "
        "reproduce an exchange."
    )

    mode = KeyMode(
        st.segmented_control(
            "Private keys",
            options=list(KeyMode),
            default=KeyMode.RANDOM,
            required=True,
            key="dh_key_mode",
        )
    )

    if mode is KeyMode.RANDOM:
        return None

    st.latex(r"1 \le a \le q - 1, \qquad 1 \le b \le q - 1")
    help_text = "Decimal, or hexadecimal with the 0x prefix. Spaces are ignored."
    alice_column, bob_column = st.columns(2)
    alice_text = alice_column.text_input(
        "Alice's private key $a$", key="dh_alice_key", help=help_text
    )
    bob_text = bob_column.text_input(
        "Bob's private key $b$", key="dh_bob_key", help=help_text
    )

    try:
        alice_key, bob_key = parse_integer(alice_text), parse_integer(bob_text)
    except ValueError:
        st.info(
            r"Type both private keys, in the range $[1,\ q - 1]$, to run the exchange.",
            icon=":material/edit:",
        )
        return None

    return alice_key, bob_key


def _render_run_section(
    parameters: DiffieHellmanParameters,
    private_keys: tuple[int, int] | None,
) -> None:
    """Render section 3 and run the exchange when the button is pressed."""
    st.header("3 · Run the exchange", anchor="dh-run")

    waiting_for_keys = (
        st.session_state.get("dh_key_mode") == KeyMode.CHOSEN and private_keys is None
    )

    if not st.button(
        "Run the key exchange",
        type="primary",
        icon=":material/play_arrow:",
        disabled=waiting_for_keys,
    ):
        return

    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    if private_keys is not None:
        try:
            alice.load_private_key(private_keys[0])
            bob.load_private_key(private_keys[1])
        except InvalidPrivateKey:
            st.error(
                r"Both private keys must satisfy $1 \le a, b \le q - 1$.",
                icon=":material/error:",
            )
            return

    context = ProtocolExecutionContext()
    perform_key_exchange(alice, bob, observer=context)

    st.session_state[_RUN] = ExchangeRun(
        parameters=parameters,
        steps=build_protocol_steps(context.events),
    )
    st.session_state[_REVEALED] = 1


def _render_timeline_section(
    parameters: DiffieHellmanParameters,
    number_format: NumberFormat,
) -> None:
    """Render the step-by-step timeline of the last run."""
    run: ExchangeRun | None = st.session_state.get(_RUN)

    if run is None:
        st.caption("Run the exchange to follow it step by step.")
        return

    if run.parameters != parameters:
        st.info(
            "The parameters changed since the last run. Run the exchange again "
            "to see it with the new group.",
            icon=":material/refresh:",
        )
        return

    total = len(run.steps)
    revealed = min(st.session_state.get(_REVEALED, 1), total)

    st.progress(revealed / total, text=f"Step {revealed} of {total}")

    display = ValueDisplay(number_format, run.parameters.bit_length)
    for step in run.steps[:revealed]:
        render_component_protocol_step(step, display=display)

    render_component_step_navigation(
        state_key=_REVEALED, revealed=revealed, total=total
    )
