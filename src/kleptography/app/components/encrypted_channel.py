"""
Components that render the encrypted channel compromised by the SETUP.

A run is several sessions of the channel between Alice's device (honest or
compromised) and an honest Bob. Every value is read from the ``crypto``
records of the run (``ChannelRun``, ``ChannelSession``, ``KeyDerivation``,
``EncryptedMessage``); nothing is computed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

import streamlit as st
from streamlit.delta_generator import DeltaGenerator

from kleptography.app.components.protocol import (
    ValueDisplay,
    Visibility,
    render_component_bytes,
    render_component_text,
    render_component_value,
)
from kleptography.app.content.diffie_hellman import StepDefinition
from kleptography.app.content.encrypted_channel import session_step_definitions
from kleptography.app.content.young_yung_setup import (
    ExchangeSummary,
    power_formula,
    summarize_exchange,
)
from kleptography.crypto.channel.records import (
    ChannelMessage,
    ChannelRun,
    ChannelSession,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.records import SetupDerivation
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.kdf.records import KeyDerivation

_ACTOR_NAME = {Actor.ALICE: "Alice", Actor.BOB: "Bob"}


class DeviceKind(StrEnum):
    """Which device generates Alice's ephemeral keys."""

    HONEST = "Honest device"
    COMPROMISED = "Compromised device (SETUP)"


@dataclass(frozen=True, slots=True)
class ChannelExperiment:
    """
    An executed run of the encrypted channel.

    Attributes:
        device_kind: Whether Alice's device was honest or compromised.
        attacker: The attacker, holding the private key ``X``. It exists
            even with an honest device, which simply does not embed it.
        configuration: The SETUP configuration of the attacker.
        run: The private view of the channel (keys, secrets, plaintexts).
        derivations: The SETUP derivations of the compromised device, one
            per session from session 2 on; empty with an honest device.
    """

    device_kind: DeviceKind
    attacker: YoungYungAttacker
    configuration: YoungYungConfiguration
    run: ChannelRun
    derivations: tuple[SetupDerivation, ...]

    @property
    def parameters(self) -> DiffieHellmanParameters:
        """Return the group of every session."""
        return self.run.parameters


def render_component_channel_session(
    session: ChannelSession,
    *,
    parameters: DiffieHellmanParameters,
    display: ValueDisplay,
) -> None:
    """
    Render one session as the participants see it, in three steps.

    Args:
        session: The executed session.
        parameters: The group of the session.
        display: How values are displayed.
    """
    exchange_step, derivation_step, messages_step = session_step_definitions(
        session.number
    )

    with _step(1, exchange_step):
        _render_exchange(
            session.number,
            summarize_exchange(session.events),
            parameters=parameters,
            display=display,
        )

    with _step(2, derivation_step):
        _render_key_derivations(session)

    with _step(3, messages_step):
        _render_messages(session)


def _step(number: int, definition: StepDefinition) -> DeltaGenerator:
    container = st.container(border=True)
    container.markdown(f"### Step {number} · {definition.title}")
    container.markdown(definition.explanation)
    container.latex(definition.formula)
    return container


def _value(
    label: str,
    value: int,
    visibility: Visibility,
    display: ValueDisplay,
) -> None:
    render_component_value(
        label,
        value,
        visibility=visibility,
        number_format=display.number_format,
        width_bits=display.width_bits,
    )


def _render_exchange(
    number: int,
    exchange: ExchangeSummary,
    *,
    parameters: DiffieHellmanParameters,
    display: ValueDisplay,
) -> None:
    i = number
    sides = (
        (
            ":material/memory: Alice's device",
            ("a", "A", "B"),
            exchange.device_private_key,
            exchange.device_public_key,
            exchange.peer_public_key,
            exchange.device_shared_secret,
        ),
        (
            ":material/person: Bob",
            ("b", "B", "A"),
            exchange.peer_private_key,
            exchange.peer_public_key,
            exchange.device_public_key,
            exchange.peer_shared_secret,
        ),
    )

    for column, side in zip(st.columns(2), sides, strict=True):
        title, symbols, private_key, public_key, peer_public_key, secret = side
        private, public, peer = symbols
        with column, st.container(border=True):
            st.markdown(f"#### {title}")
            _value(
                f"Ephemeral private key ${private}_{i}$",
                private_key,
                Visibility.PRIVATE,
                display,
            )
            st.latex(
                power_formula(
                    f"{public}_{i}",
                    "g",
                    f"{private}_{i}",
                    base=parameters.generator,
                    exponent=private_key,
                    prime=parameters.prime,
                    result=public_key,
                )
            )
            _value(f"Public key ${public}_{i}$", public_key, Visibility.PUBLIC, display)
            st.latex(
                power_formula(
                    f"s_{i}",
                    f"{peer}_{i}",
                    f"{private}_{i}",
                    base=peer_public_key,
                    exponent=private_key,
                    prime=parameters.prime,
                    result=secret,
                )
            )
            _value(f"Shared secret $s_{i}$", secret, Visibility.SHARED_SECRET, display)

    if exchange.device_shared_secret == exchange.peer_shared_secret:
        st.success(
            f"Alice and Bob share the same secret $s_{i}$.",
            icon=":material/check_circle:",
        )
    else:
        st.error(
            "The participants computed different secrets. The exchange failed.",
            icon=":material/error:",
        )


def _render_key_derivations(session: ChannelSession) -> None:
    i = session.number
    derivations = (
        (Actor.ALICE, session.alice_key_derivation),
        (Actor.BOB, session.bob_key_derivation),
    )

    for column, (actor, derivation) in zip(st.columns(2), derivations, strict=True):
        with column, st.container(border=True):
            st.markdown(f"#### {_ACTOR_NAME[actor]}")
            _render_key_derivation(i, derivation)

    if session.keys_match:
        st.success(
            f"Both parties derived the same 256-bit session key $K_{i}$.",
            icon=":material/check_circle:",
        )
    else:
        st.error(
            "The session keys differ: no message can be decrypted.",
            icon=":material/error:",
        )


def _render_key_derivation(number: int, derivation: KeyDerivation) -> None:
    render_component_bytes(
        f"Encoded secret $Z_{number}$",
        derivation.encoded_secret,
        visibility=Visibility.SHARED_SECRET,
    )
    render_component_text(
        "Label $\\mathit{OtherInfo}$ (ASCII)",
        derivation.other_info.decode("ascii"),
        visibility=Visibility.PUBLIC,
    )
    render_component_bytes(
        f"Session key $K_{number}$",
        derivation.key,
        visibility=Visibility.SHARED_SECRET,
    )


def _render_messages(session: ChannelSession) -> None:
    if not session.messages:
        st.caption("No messages were sent in this session.")
        return

    for message in session.messages:
        _render_message(message)


def _render_message(message: ChannelMessage) -> None:
    sender = _ACTOR_NAME[message.sender]
    recipient = _ACTOR_NAME[message.recipient]

    with st.container(border=True):
        st.markdown(f"#### {sender} :material/arrow_forward: {recipient}")
        render_component_text(
            f"Message $m$ written by {sender}",
            message.plaintext,
            visibility=Visibility.SHARED_SECRET,
        )

        nonce_column, tag_column = st.columns(2)
        with nonce_column:
            render_component_bytes(
                "Nonce $n$", message.encrypted.nonce, visibility=Visibility.PUBLIC
            )
        with tag_column:
            render_component_bytes(
                "Tag $\\tau$", message.encrypted.tag, visibility=Visibility.PUBLIC
            )
        render_component_bytes(
            "Ciphertext $c$",
            message.encrypted.ciphertext,
            visibility=Visibility.PUBLIC,
        )

        render_component_text(
            f"Message decrypted by {recipient}",
            message.received_plaintext,
            visibility=Visibility.SHARED_SECRET,
        )

        if message.delivered:
            st.success(
                f"The tag is valid: {recipient} reads exactly what {sender} wrote.",
                icon=":material/mark_email_read:",
            )
        else:
            st.error(
                f"{recipient} did not read what {sender} wrote.",
                icon=":material/error:",
            )
