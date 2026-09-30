"""
Controls shared by the interactive Diffie-Hellman based sections.

Each section passes its own key prefix (``dh``, ``yy``…), so widgets and
session state of different sections never collide.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

import streamlit as st

from kleptography.app.components.protocol import (
    ValueDisplay,
    render_component_parameters,
)
from kleptography.app.content.diffie_hellman import (
    build_standard_group_content,
    build_toy_group_content,
)
from kleptography.app.content.numbers import NumberFormat
from kleptography.crypto.dh.groups.rfc7919 import (
    ffdhe2048,
    ffdhe3072,
    ffdhe4096,
    ffdhe6144,
    ffdhe8192,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters

TOY_BITS_MIN = 8
TOY_BITS_MAX = 64
TOY_BITS_DEFAULT = 16

STANDARD_GROUPS: dict[str, Callable[[], DiffieHellmanParameters]] = {
    "FFDHE2048": ffdhe2048,
    "FFDHE3072": ffdhe3072,
    "FFDHE4096": ffdhe4096,
    "FFDHE6144": ffdhe6144,
    "FFDHE8192": ffdhe8192,
}


class GroupKind(StrEnum):
    """Origin of the domain parameters."""

    TOY = "Toy group"
    STANDARD = "Standardized group (RFC 7919)"


class KeyMode(StrEnum):
    """How private keys are chosen."""

    RANDOM = "Random"
    CHOSEN = "Chosen by me"


def render_component_number_format(*, key_prefix: str) -> NumberFormat:
    """
    Render the decimal / hexadecimal selector.

    Args:
        key_prefix: Section prefix for the widget key.

    Returns:
        The selected number format.
    """
    selected = st.segmented_control(
        "Show numbers in",
        options=list(NumberFormat),
        format_func=lambda option: option.value.capitalize(),
        default=NumberFormat.DECIMAL,
        required=True,
        key=f"{key_prefix}_number_format",
        help="Hexadecimal is the notation used by standards such as RFC 7919.",
    )
    return NumberFormat(selected)


def render_component_group_selection(
    *,
    key_prefix: str,
    number_format: NumberFormat,
) -> DiffieHellmanParameters:
    """
    Render the choice of a toy or RFC 7919 group and show its parameters.

    A generated toy group is kept in ``st.session_state`` under
    ``<key_prefix>_toy_parameters`` until its size changes or the user asks
    for a new one.

    Args:
        key_prefix: Section prefix for widget keys and session state.
        number_format: How the parameters are displayed.

    Returns:
        The selected parameters.
    """
    kind = GroupKind(
        st.segmented_control(
            "Group",
            options=list(GroupKind),
            default=GroupKind.TOY,
            required=True,
            key=f"{key_prefix}_group_kind",
        )
    )

    if kind is GroupKind.TOY:
        st.markdown(build_toy_group_content(), unsafe_allow_html=True)
        parameters = _render_toy_group_controls(key_prefix)
    else:
        st.markdown(build_standard_group_content(), unsafe_allow_html=True)
        name = st.selectbox(
            "Group", options=list(STANDARD_GROUPS), key=f"{key_prefix}_group"
        )
        parameters = STANDARD_GROUPS[name]()

    st.markdown(
        f"The selected group has a **{parameters.bit_length}-bit** prime. "
        "Anyone may know these values:"
    )
    render_component_parameters(
        prime=parameters.prime,
        generator=parameters.generator,
        subgroup_order=parameters.subgroup_order,
        display=ValueDisplay(number_format, parameters.bit_length),
    )

    return parameters


def _render_toy_group_controls(key_prefix: str) -> DiffieHellmanParameters:
    bits = int(
        st.number_input(
            "Size of the prime $p$ (bits)",
            min_value=TOY_BITS_MIN,
            max_value=TOY_BITS_MAX,
            value=TOY_BITS_DEFAULT,
            step=1,
            key=f"{key_prefix}_toy_bits",
            help=(
                f"Between {TOY_BITS_MIN} and {TOY_BITS_MAX} bits. Larger primes "
                "are more realistic but harder to follow."
            ),
        )
    )

    state_key = f"{key_prefix}_toy_parameters"
    parameters: DiffieHellmanParameters | None = st.session_state.get(state_key)
    regenerate = st.button(
        "Generate a new group",
        icon=":material/casino:",
        help="Pick a new random safe prime of the selected size.",
        key=f"{key_prefix}_new_group",
    )

    if regenerate or parameters is None or parameters.bit_length != bits:
        parameters = DiffieHellmanParameters.generate_toy(bits=bits)
        st.session_state[state_key] = parameters

    return parameters


def render_component_step_navigation(
    *,
    state_key: str,
    revealed: int,
    total: int,
) -> None:
    """
    Render the Next step / Show all steps / Start over buttons of a timeline.

    Args:
        state_key: Session state key holding the number of revealed steps.
        revealed: Steps currently revealed.
        total: Steps in the timeline.
    """
    next_column, all_column, restart_column = st.columns(3)
    next_column.button(
        "Next step",
        icon=":material/arrow_downward:",
        type="primary",
        disabled=revealed >= total,
        on_click=_reveal,
        args=(state_key, revealed + 1),
        width="stretch",
        key=f"{state_key}_next",
    )
    all_column.button(
        "Show all steps",
        icon=":material/unfold_more:",
        disabled=revealed >= total,
        on_click=_reveal,
        args=(state_key, total),
        width="stretch",
        key=f"{state_key}_all",
    )
    restart_column.button(
        "Start over",
        icon=":material/restart_alt:",
        on_click=_reveal,
        args=(state_key, 1),
        width="stretch",
        key=f"{state_key}_restart",
    )


def _reveal(state_key: str, count: int) -> None:
    st.session_state[state_key] = count
