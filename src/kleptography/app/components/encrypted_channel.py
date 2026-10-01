"""Components that render the encrypted channel compromised by the SETUP.

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
from kleptography.app.content.numbers import is_small
from kleptography.app.content.young_yung_setup import (
    ExchangeSummary,
    hash_formula,
    power_formula,
    r_formula,
    summarize_exchange,
    z1_formula,
    z2_formula,
)
from kleptography.crypto.channel.records import (
    ChannelMessage,
    ChannelRun,
    ChannelSession,
    ChannelTranscript,
    SessionTranscript,
    TranscriptMessage,
)
from kleptography.crypto.channel.setup.records import (
    ChannelInterception,
    InterceptedSession,
    InterceptionOutcome,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.records import SetupCandidates, SetupDerivation
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.kdf.records import KeyDerivation

_ACTOR_NAME = {Actor.ALICE: "Alice", Actor.BOB: "Bob"}


class DeviceKind(StrEnum):
    """Which device generates Alice's ephemeral keys."""

    HONEST = "Honest device"
    COMPROMISED = "Compromised device (SETUP)"


@dataclass(frozen=True, slots=True)
class ChannelExperiment:
    """An executed run of the encrypted channel.

    Attributes:
        device_kind: Whether Alice's device was honest or compromised.
        attacker: The attacker, holding the private key ``X``. It exists
            even with an honest device, which simply does not embed it.
        configuration: The SETUP configuration of the attacker.
        run: The private view of the channel (keys, secrets, plaintexts).
        derivations: The SETUP derivations of the compromised device, one
            per session from session 2 on; empty with an honest device.
        interception: The attacker's reading of the public transcript,
            computed once with the run: the recoveries exponentiate modulo
            ``p``, which is too slow to repeat on every rerun of the page.
    """

    device_kind: DeviceKind
    attacker: YoungYungAttacker
    configuration: YoungYungConfiguration
    run: ChannelRun
    derivations: tuple[SetupDerivation, ...]
    interception: ChannelInterception

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
    """Render one session as the participants see it, in three steps.

    Args:
        session: The executed session.
        parameters: The group of the session.
        display: How values are displayed.
    """
    exchange_step, derivation_step, messages_step = session_step_definitions(
        session.number
    )

    with render_component_step(1, exchange_step):
        _render_exchange(
            session.number,
            summarize_exchange(session.events),
            parameters=parameters,
            display=display,
        )

    with render_component_step(2, derivation_step):
        _render_key_derivations(session)

    with render_component_step(3, messages_step):
        _render_messages(session)


def render_component_step(number: int, definition: StepDefinition) -> DeltaGenerator:
    """Render the bordered container of an explanatory step and return it.

    Args:
        number: The step number shown in the title.
        definition: The title, explanation and formula of the step.

    Returns:
        The container, so the caller can render the step's body inside it.
    """
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
    *,
    highlight: bool = False,
) -> None:
    """Render an integer with the run's display settings."""
    render_component_value(
        label,
        value,
        visibility=visibility,
        number_format=display.number_format,
        width_bits=display.width_bits,
        highlight=highlight,
    )


def _render_exchange(
    number: int,
    exchange: ExchangeSummary,
    *,
    parameters: DiffieHellmanParameters,
    display: ValueDisplay,
) -> None:
    """Render the ephemeral DH exchange of a session, Alice and Bob side by side."""
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
    """Render each party's session key derivation and whether they match."""
    i = session.number
    derivations = (
        (Actor.ALICE, session.alice_key_derivation),
        (Actor.BOB, session.bob_key_derivation),
    )

    for column, (actor, derivation) in zip(st.columns(2), derivations, strict=True):
        with column, st.container(border=True):
            st.markdown(f"#### {_ACTOR_NAME[actor]}")
            render_component_key_derivation(
                i, derivation, visibility=Visibility.SHARED_SECRET
            )

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


def _render_messages(session: ChannelSession) -> None:
    """Render every message of a session, or a note if there are none."""
    if not session.messages:
        st.caption("No messages were sent in this session.")
        return

    for message in session.messages:
        _render_message(message)


def _render_message(message: ChannelMessage) -> None:
    """Render one message: plaintext, encrypted form and decryption."""
    sender = _ACTOR_NAME[message.sender]
    recipient = _ACTOR_NAME[message.recipient]

    with st.container(border=True):
        st.markdown(f"#### {sender} :material/arrow_forward: {recipient}")
        render_component_text(
            f"Message $m$ written by {sender}",
            message.plaintext,
            visibility=Visibility.SHARED_SECRET,
        )

        render_component_encrypted_message(message.transcript)

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


def render_component_key_derivation(
    number: int,
    derivation: KeyDerivation,
    *,
    visibility: Visibility,
    highlight: bool = False,
) -> None:
    """Render the encoded secret, the label and the key of a key derivation.

    Args:
        number: The session index used in the labels.
        derivation: The derivation to show.
        visibility: Who knows the encoded secret and the key.
        highlight: Whether to tint the computed values (Z and K).
    """
    render_component_bytes(
        f"Encoded secret $Z_{{{number}}}$",
        derivation.encoded_secret,
        visibility=visibility,
        highlight=highlight,
    )
    render_component_text(
        "Label $\\mathit{OtherInfo}$ (ASCII)",
        derivation.other_info.decode("ascii"),
        visibility=Visibility.PUBLIC,
    )
    render_component_bytes(
        f"Session key $K_{{{number}}}$",
        derivation.key,
        visibility=visibility,
        highlight=highlight,
    )


def render_component_encrypted_message(message: TranscriptMessage) -> None:
    """Render the public fields of an encrypted message: nonce, tag, ciphertext.

    Args:
        message: The message as it travelled over the network.
    """
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


def render_component_transcript(
    transcript: ChannelTranscript,
    *,
    display: ValueDisplay,
) -> None:
    """Render what crossed the network, one tab per session.

    Args:
        transcript: The public view of the channel.
        display: How values are displayed.
    """
    tabs = st.tabs([f"Session {session.number}" for session in transcript.sessions])
    for tab, session in zip(tabs, transcript.sessions, strict=True):
        with tab:
            _render_session_transcript(session, display=display)


def _render_session_transcript(
    session: SessionTranscript,
    *,
    display: ValueDisplay,
) -> None:
    """Render the public transcript of one session."""
    i = session.number
    alice_column, bob_column = st.columns(2)
    with alice_column, st.container(border=True):
        st.markdown("#### Alice :material/arrow_forward: Bob")
        _value(
            f"Public key $A_{i}$", session.alice_public_key, Visibility.PUBLIC, display
        )
    with bob_column, st.container(border=True):
        st.markdown("#### Bob :material/arrow_forward: Alice")
        _value(
            f"Public key $B_{i}$", session.bob_public_key, Visibility.PUBLIC, display
        )

    if not session.messages:
        st.caption("No messages were sent in this session.")
    for message in session.messages:
        with st.container(border=True):
            sender = _ACTOR_NAME[message.sender]
            recipient = _ACTOR_NAME[message.recipient]
            st.markdown(f"#### {sender} :material/arrow_forward: {recipient}")
            render_component_encrypted_message(message)


def render_component_recovery(
    candidates: SetupCandidates,
    *,
    second_public_key: int,
    recovered_key: int | None,
    number: int,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    display: ValueDisplay,
) -> None:
    """Render the attacker's candidates for ``a_i`` and their check against ``A_i``.

    Args:
        candidates: What the attacker computed from ``A_{i-1}`` alone.
        second_public_key: ``A_i``, the public key the candidates must match.
        recovered_key: The candidate that reproduces ``A_i``, or ``None`` if
            neither does (for example, with an honest device).
        number: The session the attacker works on (at least 2).
        attacker: The attacker, holding ``X``.
        configuration: The SETUP configuration.
        display: How values are displayed.
    """
    parameters = configuration.parameters
    previous = f"A_{{{number - 1}}}"
    z1, z2 = candidates.z_candidates

    previous_column, current_column = st.columns(2)
    with previous_column:
        _value(
            f"Previous public key ${previous}$",
            candidates.first_public_key,
            Visibility.PUBLIC,
            display,
        )
    with current_column:
        _value(
            f"Public key $A_{{{number}}}$",
            second_public_key,
            Visibility.PUBLIC,
            display,
        )

    with st.container(border=True):
        st.markdown("#### :material/vpn_key: Unmasking $z$")
        st.latex(
            r_formula(
                first_public_key=candidates.first_public_key,
                multiplier_a=configuration.multiplier_a,
                generator=parameters.generator,
                offset_b=configuration.offset_b,
                prime=parameters.prime,
                r=candidates.r,
                first_symbol=previous,
            )
        )
        _value("$r$", candidates.r, Visibility.ATTACKER, display, highlight=True)
        st.latex(
            z1_formula(
                first_public_key=candidates.first_public_key,
                r=candidates.r,
                attacker_private_key=attacker.private_key,
                prime=parameters.prime,
                z1=z1,
                first_symbol=previous,
            )
        )
        _value(
            "Candidate $z_1$ (if $t = 0$)",
            z1,
            Visibility.ATTACKER,
            display,
            highlight=True,
        )
        st.latex(
            z2_formula(
                z1=z1,
                generator=parameters.generator,
                correction_w=configuration.correction_w,
                prime=parameters.prime,
                z2=z2,
            )
        )
        _value(
            "Candidate $z_2$ (if $t = 1$)",
            z2,
            Visibility.ATTACKER,
            display,
            highlight=True,
        )

    for index, (column, z, candidate) in enumerate(
        zip(
            st.columns(2),
            candidates.z_candidates,
            candidates.private_key_candidates,
            strict=True,
        ),
        start=1,
    ):
        with column, st.container(border=True):
            st.markdown(f"#### Candidate $t = {index - 1}$")
            st.latex(
                hash_formula(rf"\hat{{a}}_{index}", f"z_{index}", z=z, result=candidate)
            )
            _value(
                rf"Candidate key $\hat{{a}}_{index}$",
                candidate,
                Visibility.ATTACKER,
                display,
                # Only the candidate that reproduces A_i is the right key.
                highlight=candidate == recovered_key,
            )
            _render_candidate_check(
                candidate,
                recovered_key=recovered_key,
                second_public_key=second_public_key,
                index=index,
                number=number,
                parameters=parameters,
            )

    if recovered_key is not None:
        st.success(
            f"The attacker has Alice's private key $a_{{{number}}}$.",
            icon=":material/lock_open:",
        )


def _render_candidate_check(
    candidate: int,
    *,
    recovered_key: int | None,
    second_public_key: int,
    index: int,
    number: int,
    parameters: DiffieHellmanParameters,
) -> None:
    """Render whether a candidate exponent reproduces Alice's public key."""
    # Only the matching candidate's power is known (it is A_i), so the
    # rejected one is shown symbolically.
    target = f"A_{{{number}}}"
    if candidate != recovered_key:
        st.markdown(
            rf"$g^{{\hat{{a}}_{index}}} \not\equiv {target}$ &nbsp; "
            f":red-badge[:material/close: Does not match ${target}$]"
        )
        return

    check = (
        rf"{parameters.generator}^{{{candidate}}} \bmod {parameters.prime} = "
        rf"{second_public_key} = {target}"
        if is_small(candidate, parameters.prime, second_public_key)
        else rf"g^{{\hat{{a}}_{index}}} \equiv {target}"
    )
    st.markdown(f"${check}$ &nbsp; :green-badge[:material/check: Matches ${target}$]")


_OUTCOME_TEXT = {
    InterceptionOutcome.NOT_RECOVERABLE: "Not possible (first session)",
    InterceptionOutcome.RECOVERY_FAILED: "Failed: no SETUP link",
    InterceptionOutcome.RECOVERED: "Recovered",
}


def render_component_interception_summary(
    interception: ChannelInterception,
    experiment: ChannelExperiment,
) -> None:
    """Render who reads what in each session, and compare it with the device.

    Args:
        interception: The attacker's reading of the whole transcript.
        experiment: The executed run, used only for the comparison with
            what really happened.
    """
    rows = [
        "| Session | Attacker's recovery | Attacker reads | Bob reads | Eve reads |",
        "| --- | --- | --- | --- | --- |",
    ]
    for intercepted, session in zip(
        interception.sessions, experiment.run.sessions, strict=True
    ):
        total = len(session.messages)
        read = sum(message.readable for message in intercepted.messages)
        delivered = sum(message.delivered for message in session.messages)
        rows.append(
            f"| {intercepted.number} | {_OUTCOME_TEXT[intercepted.outcome]} | "
            f"{_reading(intercepted, read, total)} | {delivered} of {total} | "
            f"0 of {total} |"
        )
    st.markdown("\n".join(rows))

    with st.expander(
        "Compare with what really happened inside the device",
        icon=":material/memory:",
    ):
        _render_ground_truth(interception, experiment)


def _reading(intercepted: InterceptedSession, read: int, total: int) -> str:
    """Return the summary cell of how many messages the attacker read."""
    if not intercepted.recovered:
        return f"0 of {total}"
    if total == 0:
        return "Key known, no messages"
    return f"**{read} of {total}**"


def _render_ground_truth(
    interception: ChannelInterception,
    experiment: ChannelExperiment,
) -> None:
    """Render the comparison between the attacker's results and the device."""
    st.markdown(f"Alice's device in this run: **{experiment.device_kind.value}**.")

    if experiment.device_kind is DeviceKind.HONEST:
        st.markdown(
            "Every key was drawn at random, so no key is linked to the "
            "previous one and the recovery has nothing to find. In a toy "
            "group, a random key can still equal a candidate by pure "
            "chance: then the attacker really reads that session."
        )
        return

    rows = [
        "| Session | Device's hidden bit $t$ | Device's key equals the recovered one |",
        "| --- | --- | --- |",
        "| 1 | — (drawn at random) | — |",
    ]
    for derivation, intercepted in zip(
        experiment.derivations, interception.sessions[1:], strict=True
    ):
        recovery = intercepted.recovery
        matches = (
            recovery is not None and recovery.private_key == derivation.private_key
        )
        rows.append(
            f"| {intercepted.number} | {derivation.correction_bit} | "
            f"{'Yes' if matches else 'No'} |"
        )
    st.markdown("\n".join(rows))
