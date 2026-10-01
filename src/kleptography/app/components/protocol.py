"""
Components that render an executed Diffie-Hellman exchange step by step.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

import streamlit as st

from kleptography.app.content.diffie_hellman import (
    PRIVATE_SYMBOL,
    PUBLIC_SYMBOL,
    SECRET_SYMBOL,
    ProtocolStep,
    build_eavesdropper_content,
    public_key_formula,
    shared_secret_formula,
)
from kleptography.app.content.numbers import (
    NumberFormat,
    format_bytes,
    format_integer,
    is_small,
)
from kleptography.crypto.dh.tracing.events import Actor, ProtocolEventType

# Code blocks taller than this scroll vertically (never horizontally).
_MAX_VALUE_HEIGHT = 220
_LONG_VALUE_CHARACTERS = 400

_ACTOR_NAME = {Actor.ALICE: "Alice", Actor.BOB: "Bob"}


class Visibility(StrEnum):
    """Who can see a value, shown as a colored badge."""

    PUBLIC = "public"
    PRIVATE = "private"
    SHARED_SECRET = "shared secret"
    DEVICE = "hidden in the device"
    ATTACKER = "attacker only"


_BADGE = {
    Visibility.PUBLIC: ":blue-badge[:material/visibility: Public]",
    Visibility.PRIVATE: ":red-badge[:material/lock: Private]",
    Visibility.SHARED_SECRET: ":green-badge[:material/key: Shared secret]",
    Visibility.DEVICE: ":orange-badge[:material/memory: Hidden in the device]",
    Visibility.ATTACKER: ":violet-badge[:material/vpn_key: Attacker only]",
}


@dataclass(frozen=True, slots=True)
class ValueDisplay:
    """
    How cryptographic values are displayed.

    Attributes:
        number_format: The base used to display values.
        width_bits: Bit length of the modulus ``p``. Values reduced modulo
            ``p`` are padded to this width in hexadecimal so they line up.
    """

    number_format: NumberFormat
    width_bits: int


def render_component_value(
    label: str,
    value: int,
    *,
    visibility: Visibility,
    number_format: NumberFormat,
    width_bits: int | None = None,
    highlight: bool = False,
) -> None:
    """
    Render a labeled cryptographic value in a wrapping code block.

    Args:
        label: Markdown label, typically including a LaTeX symbol.
        value: The integer to display.
        visibility: Who can see the value.
        number_format: The base used to display it.
        width_bits: Optional fixed width for hexadecimal padding, usually
            the bit length of ``p``. Leave it unset for small constants such
            as the generator.
        highlight: Whether to tint the block, to mark a value that the
            reader just computed.
    """
    text = format_integer(value, number_format, width_bits=width_bits)

    st.markdown(
        f"{label} &nbsp; {_BADGE[visibility]} &nbsp; :gray[{value.bit_length()} bits]"
    )
    _render_code(label, text, highlight=highlight)


def render_component_bytes(
    label: str,
    data: bytes,
    *,
    visibility: Visibility,
    highlight: bool = False,
) -> None:
    """
    Render a labeled byte string in hexadecimal, in a wrapping code block.

    Args:
        label: Markdown label, typically including a LaTeX symbol.
        data: The bytes to display.
        visibility: Who can see the value.
        highlight: Whether to tint the block, to mark a computed value.
    """
    text = format_bytes(data)

    st.markdown(f"{label} &nbsp; {_BADGE[visibility]} &nbsp; :gray[{len(data)} bytes]")
    _render_code(label, text, highlight=highlight)


def render_component_text(
    label: str,
    text: str,
    *,
    visibility: Visibility,
    highlight: bool = False,
) -> None:
    """
    Render a labeled human-readable text, such as a message, in a code block.

    Args:
        label: Markdown label.
        text: The text to display, shown verbatim.
        visibility: Who can see the text.
        highlight: Whether to tint the block, to mark a computed value.
    """
    st.markdown(
        f"{label} &nbsp; {_BADGE[visibility]} &nbsp; :gray[{len(text)} characters]"
    )
    _render_code(label, text, highlight=highlight)


def _render_code(label: str, text: str, *, highlight: bool) -> None:
    height = _MAX_VALUE_HEIGHT if len(text) > _LONG_VALUE_CHARACTERS else "content"

    if not highlight:
        st.code(text, language="text", wrap_lines=True, height=height)
        return

    # Streamlit adds the class "st-key-<key>" to a keyed container, which
    # protocol.css uses to tint the block. The key only has to be unique.
    key = f"computed-value-{hash((label, text)) & 0xFFFFFFFF:08x}"
    with st.container(key=key):
        st.code(text, language="text", wrap_lines=True, height=height)


def render_component_protocol_step(
    step: ProtocolStep,
    *,
    display: ValueDisplay,
) -> None:
    """
    Render one explanatory step of an executed exchange.

    Args:
        step: The step, with its explanation and recorded events.
        display: How values are displayed.
    """
    renderers = {
        1: _render_parameters,
        2: _render_keypairs,
        3: _render_public_key_exchange,
        4: _render_shared_secrets,
        5: _render_verification,
    }

    with st.container(border=True):
        st.markdown(f"### Step {step.number} · {step.definition.title}")
        st.markdown(step.definition.explanation)
        st.latex(step.definition.formula)
        renderers[step.number](step, display)


def render_component_parameters(
    *,
    prime: int,
    generator: int,
    subgroup_order: int,
    display: ValueDisplay,
) -> None:
    """
    Render the public group parameters p, g and q.

    Small groups are shown side by side; large ones are stacked. The
    generator is not padded, since it is a small constant such as 2.
    """
    values = (
        ("Prime modulus $p$", prime, display.width_bits),
        ("Generator $g$", generator, None),
        ("Subgroup order $q$", subgroup_order, display.width_bits),
    )

    columns = st.columns(3) if is_small(prime) else [st.container()] * 3
    for column, (label, value, width_bits) in zip(columns, values, strict=True):
        with column:
            render_component_value(
                label,
                value,
                visibility=Visibility.PUBLIC,
                number_format=display.number_format,
                width_bits=width_bits,
            )


def _integer(data: Mapping[str, object], key: str) -> int:
    """Read an integer field from event data."""
    value = data[key]
    if not isinstance(value, int):
        raise TypeError(f"Event field {key!r} is not an integer.")
    return value


def _render_parameters(step: ProtocolStep, display: ValueDisplay) -> None:
    data = step.event(ProtocolEventType.PARAMETERS_SELECTED, Actor.SYSTEM).data
    prime = _integer(data, "prime")
    generator = _integer(data, "generator")
    subgroup_order = _integer(data, "subgroup_order")

    render_component_parameters(
        prime=prime,
        generator=generator,
        subgroup_order=subgroup_order,
        display=display,
    )

    if step.events_of(ProtocolEventType.PARAMETERS_VALIDATED):
        st.success(
            "Alice and Bob use the same group, and it satisfies "
            "$p = 2q + 1$ and $g^{q} \\equiv 1 \\pmod{p}$.",
            icon=":material/check_circle:",
        )


def _render_keypairs(step: ProtocolStep, display: ValueDisplay) -> None:
    for column, actor in zip(st.columns(2), (Actor.ALICE, Actor.BOB), strict=True):
        with column, st.container(border=True):
            _render_keypair(step, actor, display)


def _render_keypair(
    step: ProtocolStep,
    actor: Actor,
    display: ValueDisplay,
) -> None:
    name = _ACTOR_NAME[actor]
    private = PRIVATE_SYMBOL[actor]
    public = PUBLIC_SYMBOL[actor]

    key_event = next(
        event
        for event in step.events_of(
            ProtocolEventType.PRIVATE_KEY_GENERATED,
            ProtocolEventType.PRIVATE_KEY_PROVIDED,
        )
        if event.actor is actor
    )
    origin = (
        "chosen at random"
        if key_event.event_type is ProtocolEventType.PRIVATE_KEY_GENERATED
        else "chosen by you"
    )

    public_data = step.event(ProtocolEventType.PUBLIC_KEY_COMPUTED, actor).data
    private_key = _integer(public_data, "exponent")
    public_key = _integer(public_data, "public_key")

    st.markdown(f"#### {name}")
    render_component_value(
        f"Private key ${private}$ ({origin})",
        private_key,
        visibility=Visibility.PRIVATE,
        number_format=display.number_format,
        width_bits=display.width_bits,
    )
    st.latex(
        public_key_formula(
            actor,
            generator=_integer(public_data, "base"),
            private_key=private_key,
            prime=_integer(public_data, "modulus"),
            public_key=public_key,
        )
    )
    render_component_value(
        f"Public key ${public}$",
        public_key,
        visibility=Visibility.PUBLIC,
        number_format=display.number_format,
        width_bits=display.width_bits,
    )


def _render_public_key_exchange(
    step: ProtocolStep,
    display: ValueDisplay,
) -> None:
    columns = st.columns(2)

    for column, sent in zip(
        columns, step.events_of(ProtocolEventType.PUBLIC_KEY_SENT), strict=True
    ):
        sender = sent.actor
        recipient = _ACTOR_NAME[Actor(str(sent.data["recipient"]))]

        with column, st.container(border=True):
            st.markdown(
                f"#### {_ACTOR_NAME[sender]} :material/arrow_forward: {recipient}"
            )
            render_component_value(
                f"Message: public key ${PUBLIC_SYMBOL[sender]}$",
                _integer(sent.data, "public_key"),
                visibility=Visibility.PUBLIC,
                number_format=display.number_format,
                width_bits=display.width_bits,
            )

    st.markdown(build_eavesdropper_content(), unsafe_allow_html=True)


def _render_shared_secrets(step: ProtocolStep, display: ValueDisplay) -> None:
    for column, actor in zip(st.columns(2), (Actor.ALICE, Actor.BOB), strict=True):
        data = step.event(ProtocolEventType.SHARED_SECRET_COMPUTED, actor).data
        shared_secret = _integer(data, "shared_secret")

        with column, st.container(border=True):
            st.markdown(f"#### {_ACTOR_NAME[actor]}")
            st.latex(
                shared_secret_formula(
                    actor,
                    peer_public_key=_integer(data, "peer_public_key"),
                    private_key=_integer(data, "private_key"),
                    prime=_integer(data, "modulus"),
                    shared_secret=shared_secret,
                )
            )
            render_component_value(
                f"Shared secret ${SECRET_SYMBOL[actor]}$",
                shared_secret,
                visibility=Visibility.SHARED_SECRET,
                number_format=display.number_format,
                width_bits=display.width_bits,
            )


def _render_verification(step: ProtocolStep, _: ValueDisplay) -> None:
    data = step.event(ProtocolEventType.SHARED_SECRET_VERIFIED, Actor.SYSTEM).data

    if data["successful"]:
        st.success(
            "Both participants computed the same secret "
            "$s_A = s_B = g^{ab} \\bmod p$. Eve saw every message, yet she "
            "does not know it.",
            icon=":material/verified:",
        )
    else:
        st.error(
            "The participants computed different secrets. The exchange failed.",
            icon=":material/error:",
        )
