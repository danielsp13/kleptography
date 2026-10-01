"""The Experiment tab of the Young–Yung SETUP section: its numbered sections.

The reader chooses the group, builds the backdoor, chooses the private keys
and runs both exchanges; the timeline of the run follows.
"""

from __future__ import annotations

import streamlit as st

from kleptography.app.components.controls import (
    KeyMode,
    render_component_group_selection,
    render_component_number_format,
)
from kleptography.app.components.protocol import ValueDisplay
from kleptography.app.components.young_yung_setup import (
    Backdoor,
    render_component_backdoor,
)
from kleptography.app.content.numbers import NumberFormat, parse_integer
from kleptography.app.pages.young_yung_setup.experiment import (
    ChosenKeys,
    run_experiment,
)
from kleptography.app.pages.young_yung_setup.state import (
    BACKDOOR,
    PREFIX,
    REVEALED,
    RUN,
)
from kleptography.app.pages.young_yung_setup.timeline import render_timeline_section
from kleptography.crypto.dh.exceptions import InvalidPrivateKey
from kleptography.crypto.dh.parameters import DiffieHellmanParameters


def render_experiment() -> None:
    """Render the Experiment tab."""
    st.markdown(
        "Build a backdoored device, run two exchanges between it and an honest "
        "Bob, and then take the attacker's seat: from the public messages "
        "alone, plus the trapdoor $X$, recover the second shared secret."
    )

    number_format = render_component_number_format(key_prefix=PREFIX)

    st.header("1 · Choose the public parameters", anchor="yy-parameters")
    parameters = render_component_group_selection(
        key_prefix=PREFIX, number_format=number_format
    )

    st.divider()
    backdoor = _render_backdoor_section(parameters, number_format)

    st.divider()
    chosen_keys = _render_private_keys_section()

    st.divider()
    _render_run_section(parameters, backdoor, chosen_keys)
    render_timeline_section(parameters, backdoor, number_format)


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

    backdoor: Backdoor | None = st.session_state.get(BACKDOOR)
    regenerate = st.button(
        "Generate a new backdoor",
        icon=":material/casino:",
        help="Pick a new attacker key pair and new SETUP constants.",
        key="yy_new_backdoor",
    )

    if regenerate or backdoor is None or backdoor.attacker.parameters != parameters:
        backdoor = Backdoor.generate(parameters)
        st.session_state[BACKDOOR] = backdoor

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
        run = run_experiment(parameters, backdoor, chosen_keys)
    except InvalidPrivateKey:
        st.error(
            r"All private keys must satisfy $1 \le a_1, b_1, b_2 \le q - 1$.",
            icon=":material/error:",
        )
        return

    st.session_state[RUN] = run
    st.session_state[REVEALED] = 1
