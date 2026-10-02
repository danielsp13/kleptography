"""The attacker's workbench, section 3 of the Attacker tab.

The reader reads one session in four steps (recovery of Alice's key, shared
secret, session key, decryption), typing each value or pasting the result
of the previous step. Expensive results come from the run or are memoized.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache

import streamlit as st

from kleptography.app.components.encrypted_channel import (
    ChannelExperiment,
    render_component_encrypted_message,
    render_component_key_derivation,
    render_component_recovery,
    render_component_step,
)
from kleptography.app.components.protocol import (
    ValueDisplay,
    Visibility,
    render_component_text,
    render_component_value,
)
from kleptography.app.content.encrypted_channel import (
    build_first_session_content,
    build_recovery_failed_content,
    workbench_step_definitions,
)
from kleptography.app.content.numbers import (
    NumberFormat,
    format_bytes,
    parse_bytes,
    parse_integer,
)
from kleptography.app.content.young_yung_setup import power_formula
from kleptography.app.pages.encrypted_channel.state import (
    MESSAGE,
    PRIVATE_KEY,
    RUN_COUNT,
    SESSION,
    SESSION_KEY,
    SHARED_SECRET,
)
from kleptography.crypto.aead.aes_gcm import decrypt
from kleptography.crypto.aead.exceptions import (
    AeadAuthenticationError,
    InvalidAeadKey,
)
from kleptography.crypto.channel.records import ChannelTranscript, SessionTranscript
from kleptography.crypto.dh.exceptions import InvalidPrivateKey
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.kdf.exceptions import InvalidKdfInput
from kleptography.crypto.kdf.one_step import derive_key
from kleptography.crypto.kdf.records import KeyDerivation


def render_workbench(
    experiment: ChannelExperiment,
    transcript: ChannelTranscript,
    display: ValueDisplay,
) -> None:
    """Render the attacker's workbench for the selected session."""
    st.header("3 · Your workbench", anchor="ch-attacker-workbench")
    st.markdown(
        "Pick a session and read it step by step. Each field starts empty: "
        "type a value, or press the button next to it to paste the result of "
        "the previous step. Changing the session starts over. Values you "
        "compute are highlighted in :orange[**orange**]."
    )

    sessions = transcript.sessions
    numbers = [session.number for session in sessions]
    if st.session_state.get(SESSION) not in numbers:
        st.session_state[SESSION] = 2
    selected = st.segmented_control(
        "Session",
        options=numbers,
        format_func=lambda option: f"Session {option}",
        required=True,
        key=SESSION,
    )
    number = 2 if selected is None else selected
    session = sessions[number - 1]
    intercepted = experiment.interception.sessions[number - 1]
    scope = f"{st.session_state.get(RUN_COUNT, 0)}_{number}"
    recover_step, secret_step, key_step, decrypt_step = workbench_step_definitions(
        number
    )

    with render_component_step(1, recover_step):
        recovered, candidate_keys = _render_recovery_step(experiment, number, display)
    if intercepted.candidates is None:
        # Session 1: the SETUP leaks nothing about a_1, so the steps that
        # would start from it are not offered at all.
        return

    with render_component_step(2, secret_step):
        shared_secret = _render_shared_secret_step(
            experiment.parameters,
            session,
            recovered,
            candidate_keys,
            buffered_secret=intercepted.shared_secret,
            scope=scope,
            display=display,
        )

    with render_component_step(3, key_step):
        derivation = _render_key_step(
            experiment.parameters, number, shared_secret, scope=scope, display=display
        )

    with render_component_step(4, decrypt_step):
        _render_decrypt_step(session, derivation, scope=scope)


def _render_recovery_step(
    experiment: ChannelExperiment,
    number: int,
    display: ValueDisplay,
) -> tuple[int | None, tuple[int, ...]]:
    """Render workbench step 1: the recovery of Alice's private key."""
    # The candidates of every session were computed once, with the run.
    # Returns the recovered key (if a candidate matched) and the candidates.
    intercepted = experiment.interception.sessions[number - 1]
    candidates = intercepted.candidates
    if candidates is None:
        st.markdown(build_first_session_content(), unsafe_allow_html=True)
        return None, ()

    recovered = (
        None if intercepted.recovery is None else intercepted.recovery.private_key
    )
    render_component_recovery(
        candidates,
        second_public_key=intercepted.transcript.alice_public_key,
        recovered_key=recovered,
        number=number,
        attacker=experiment.attacker,
        configuration=experiment.configuration,
        display=display,
    )
    if recovered is None:
        st.markdown(build_recovery_failed_content(), unsafe_allow_html=True)
    return recovered, candidates.private_key_candidates


def _render_shared_secret_step(
    parameters: DiffieHellmanParameters,
    session: SessionTranscript,
    recovered: int | None,
    candidate_keys: tuple[int, ...],
    *,
    buffered_secret: int | None,
    scope: str,
    display: ValueDisplay,
) -> int | None:
    """Render workbench step 2 and return the shared secret, if computed."""
    i = session.number
    render_component_value(
        f"Bob's public key $B_{{{i}}}$",
        session.bob_public_key,
        visibility=Visibility.PUBLIC,
        number_format=display.number_format,
        width_bits=display.width_bits,
    )
    text = _render_workbench_input(
        f"Alice's private key $a_{{{i}}}$",
        field=_workbench_key(PRIVATE_KEY, scope),
        input_help="Decimal, or hexadecimal with the 0x prefix. Spaces are ignored.",
        pastes=_private_key_pastes(i, recovered, candidate_keys, display),
        pending="a key from step 1",
    )
    if not text.strip():
        return None

    try:
        private_key = parse_integer(text)
        if private_key == recovered and buffered_secret is not None:
            # Already computed with the run: pasting the recovered key is
            # instant even with the largest groups.
            shared_secret = buffered_secret
        else:
            shared_secret = _shared_secret(
                parameters, private_key, session.bob_public_key
            )
    except InvalidPrivateKey:
        st.error(
            f"A private key must satisfy $1 \\le a_{{{i}}} \\le q - 1$.",
            icon=":material/error:",
        )
        return None
    except ValueError:
        st.error("That is not a valid integer.", icon=":material/error:")
        return None

    st.latex(
        power_formula(
            f"s_{{{i}}}",
            f"B_{{{i}}}",
            f"a_{{{i}}}",
            base=session.bob_public_key,
            exponent=private_key,
            prime=parameters.prime,
            result=shared_secret,
        )
    )
    render_component_value(
        f"Shared secret $s_{{{i}}}$ (computed by you)",
        shared_secret,
        visibility=Visibility.ATTACKER,
        number_format=display.number_format,
        width_bits=display.width_bits,
        highlight=True,
    )
    return shared_secret


@lru_cache(maxsize=64)
def _shared_secret(
    parameters: DiffieHellmanParameters,
    private_key: int,
    peer_public_key: int,
) -> int:
    """Return the shared secret B_i^a_i mod p, memoized across reruns."""
    # The attacker computes the secret exactly as Alice's device does. With
    # a large group this takes a noticeable time, and the page reruns on
    # every widget change, so the result of each input is kept.
    participant = DiffieHellmanParticipant(parameters)
    participant.load_private_key(private_key)
    return participant.compute_shared_secret(peer_public_key)


def _render_key_step(
    parameters: DiffieHellmanParameters,
    number: int,
    shared_secret: int | None,
    *,
    scope: str,
    display: ValueDisplay,
) -> KeyDerivation | None:
    """Render workbench step 3 and return the key derivation, if computed."""
    text = _render_workbench_input(
        f"Shared secret $s_{{{number}}}$",
        field=_workbench_key(SHARED_SECRET, scope),
        input_help="Decimal, or hexadecimal with the 0x prefix. Spaces are ignored.",
        pastes=(
            ()
            if shared_secret is None
            else (
                _Paste(
                    symbol=f"s_{{{number}}}",
                    source_step=2,
                    source="the shared secret computed in step 2",
                    value=_integer_input(shared_secret, display),
                ),
            )
        ),
        pending="the shared secret computed in step 2",
    )
    if not text.strip():
        return None

    try:
        derivation = derive_key(
            parse_integer(text), secret_length=parameters.byte_length
        )
    except InvalidKdfInput:
        st.error(
            "The shared secret must be a positive integer smaller than $p$ "
            "once encoded in as many bytes as $p$.",
            icon=":material/error:",
        )
        return None
    except ValueError:
        st.error("That is not a valid integer.", icon=":material/error:")
        return None

    render_component_key_derivation(
        number, derivation, visibility=Visibility.ATTACKER, highlight=True
    )
    return derivation


def _render_decrypt_step(
    session: SessionTranscript,
    derivation: KeyDerivation | None,
    *,
    scope: str,
) -> None:
    """Render workbench step 4: the decryption of a message."""
    if not session.messages:
        st.caption("No messages were sent in this session: there is nothing to read.")
        return

    index = st.selectbox(
        "Message",
        options=range(len(session.messages)),
        format_func=lambda option: _message_label(session, option),
        key=_workbench_key(MESSAGE, scope),
    )
    message = session.messages[index]
    render_component_encrypted_message(message)

    text = _render_workbench_input(
        f"Session key $K_{{{session.number}}}$ (64 hexadecimal digits)",
        field=_workbench_key(SESSION_KEY, scope),
        input_help="Hexadecimal, with or without the 0x prefix. Spaces are ignored.",
        pastes=(
            ()
            if derivation is None
            else (
                _Paste(
                    symbol=f"K_{{{session.number}}}",
                    source_step=3,
                    source="the session key derived in step 3",
                    value=format_bytes(derivation.key),
                ),
            )
        ),
        pending="the session key derived in step 3",
    )
    if not text.strip():
        return

    try:
        plaintext = decrypt(parse_bytes(text), message.encrypted)
    except InvalidAeadKey:
        st.error(
            "AES-256 needs a key of exactly 32 bytes (64 hexadecimal digits).",
            icon=":material/error:",
        )
        return
    except AeadAuthenticationError:
        st.error(
            "The tag does not verify: this is not the key of the session, or "
            "the message was modified. AES-GCM returns nothing at all, so all "
            "you keep is the ciphertext above: unintelligible bytes.",
            icon=":material/gpp_bad:",
        )
        return
    except ValueError:
        st.error(
            "That is not valid hexadecimal: use an even number of digits.",
            icon=":material/error:",
        )
        return

    render_component_text(
        "Plaintext $m$ (read by you)",
        plaintext.decode("ascii"),
        visibility=Visibility.ATTACKER,
        highlight=True,
    )
    st.success(
        "The tag verifies: you read the message without breaking AES-GCM.",
        icon=":material/lock_open:",
    )


def _message_label(session: SessionTranscript, index: int) -> str:
    """Return the label of a message in the message selector."""
    message = session.messages[index]
    sender = "Alice" if message.sender is Actor.ALICE else "Bob"
    recipient = "Bob" if message.sender is Actor.ALICE else "Alice"
    return f"{index + 1} · {sender} → {recipient}"


@dataclass(frozen=True, slots=True)
class _Paste:
    """A value of a previous step that a workbench field can paste."""

    symbol: str
    source_step: int
    source: str
    value: str


def _private_key_pastes(
    number: int,
    recovered: int | None,
    candidate_keys: tuple[int, ...],
    display: ValueDisplay,
) -> tuple[_Paste, ...]:
    """Return the paste buttons for the private key field."""
    if recovered is not None:
        return (
            _Paste(
                symbol=f"a_{{{number}}}",
                source_step=1,
                source="the private key recovered in step 1",
                value=_integer_input(recovered, display),
            ),
        )
    # No candidate matched: the attacker can still try them, and the chain
    # will end in a key that AES-GCM rejects.
    return tuple(
        _Paste(
            symbol=rf"\hat{{a}}_{index}",
            source_step=1,
            source=f"the rejected candidate of step 1 (t = {index - 1})",
            value=_integer_input(candidate, display),
        )
        for index, candidate in enumerate(candidate_keys, start=1)
    )


def _render_workbench_input(
    label: str,
    *,
    field: str,
    input_help: str,
    pastes: Sequence[_Paste],
    pending: str,
) -> str:
    """Render a workbench field with its paste buttons and return its text."""
    # A text field with one button per value it can paste from a previous
    # step, and a hint below saying what each button reuses.
    columns = st.columns([3] + [1] * max(len(pastes), 1), vertical_alignment="bottom")
    for index, (column, paste) in enumerate(zip(columns[1:], pastes)):
        with column:
            st.button(
                f"Paste ${paste.symbol}$",
                icon=":material/content_paste:",
                on_click=_fill,
                args=(field, paste.value),
                help=f"Copies {paste.source} into the field.",
                width="stretch",
                key=f"{field}_fill_{index}",
            )
    if not pastes:
        with columns[1]:
            st.button(
                "Paste",
                icon=":material/content_paste:",
                disabled=True,
                help=f"Nothing to paste yet: {pending} is not ready.",
                width="stretch",
                key=f"{field}_fill_0",
            )
    with columns[0]:
        text = st.text_input(
            label,
            key=field,
            help=input_help,
            placeholder="Type a value, or paste one from the previous step",
        )

    if not pastes:
        st.caption(
            f":material/hourglass_empty: Nothing to paste yet: {pending} will "
            "be ready once that step has a result. You can still type any "
            "value."
        )
    for paste in pastes:
        st.caption(
            f":material/content_paste: Ready to paste ${paste.symbol}$: "
            f"{paste.source} (`{_preview(paste.value)}`)."
        )
    return text


def _preview(value: str) -> str:
    """Return a value shortened to 32 characters for a hint."""
    return value if len(value) <= 32 else f"{value[:32]}…"


def _fill(field: str, value: str) -> None:
    """Write a value into a workbench field (a button callback)."""
    st.session_state[field] = value


def _workbench_key(prefix: str, scope: str) -> str:
    """Return the widget key of a field for one run and session."""
    # A widget that is not rendered loses its value, so a new key per run and
    # session gives empty fields (and no stale result) whenever either one
    # changes, without relying on callbacks to clear them.
    return f"{prefix}_{scope}"


def _integer_input(value: int, display: ValueDisplay) -> str:
    """Return an integer formatted as the user would type it."""
    # Typed values follow the selected format, as parse_integer reads them.
    if display.number_format is NumberFormat.HEXADECIMAL:
        return f"0x{value:X}"
    return str(value)
