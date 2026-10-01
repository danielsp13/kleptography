"""The numbered sections of the Diffie-Hellman section.

The reader chooses the group and the private keys, and runs the exchange.
"""

from __future__ import annotations

import streamlit as st

from kleptography.app.components.controls import (
    KeyMode,
    render_component_group_selection,
)
from kleptography.app.content.numbers import NumberFormat, parse_integer
from kleptography.app.pages.diffie_hellman.experiment import run_exchange
from kleptography.app.pages.diffie_hellman.state import PREFIX, REVEALED, RUN
from kleptography.crypto.dh.exceptions import InvalidPrivateKey
from kleptography.crypto.dh.parameters import DiffieHellmanParameters


def render_parameters_section(number_format: NumberFormat) -> DiffieHellmanParameters:
    """Render section 1 and return the selected group."""
    st.header("1 · Choose the public parameters", anchor="dh-parameters")
    return render_component_group_selection(
        key_prefix=PREFIX, number_format=number_format
    )


def render_private_keys_section(
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


def render_run_section(
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

    try:
        run = run_exchange(parameters, private_keys)
    except InvalidPrivateKey:
        st.error(
            r"Both private keys must satisfy $1 \le a, b \le q - 1$.",
            icon=":material/error:",
        )
        return

    st.session_state[RUN] = run
    st.session_state[REVEALED] = 1
