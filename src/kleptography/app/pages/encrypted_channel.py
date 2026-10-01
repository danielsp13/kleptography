"""Interactive section: an encrypted channel compromised by the Young–Yung SETUP.

The section has three tabs: the idea (the channel, its ciphersuite and how
the SETUP breaks it), the participant's point of view (running the channel
with an honest or a compromised Alice) and the attacker's point of view
(reading the channel from its public transcript and the trapdoor). It only
orchestrates the ``crypto`` API.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache

import streamlit as st
from streamlit.delta_generator import DeltaGenerator

from kleptography.app.components.controls import (
    render_component_group_selection,
    render_component_number_format,
)
from kleptography.app.components.encrypted_channel import (
    ChannelExperiment,
    DeviceKind,
    render_component_channel_session,
    render_component_encrypted_message,
    render_component_interception_summary,
    render_component_key_derivation,
    render_component_recovery,
    render_component_step,
    render_component_transcript,
)
from kleptography.app.components.footer import render_component_footer
from kleptography.app.components.navigation import render_component_back_home
from kleptography.app.components.protocol import (
    ValueDisplay,
    Visibility,
    render_component_text,
    render_component_value,
)
from kleptography.app.components.young_yung_setup import render_component_backdoor
from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.encrypted_channel import (
    CIPHERSUITE_NAME,
    DEFAULT_MESSAGES,
    build_artifacts_content,
    build_attacker_intro_content,
    build_channel_concept_content,
    build_channel_intro_content,
    build_device_choice_content,
    build_eve_content,
    build_first_session_content,
    build_indistinguishable_content,
    build_messages_tip_content,
    build_participant_intro_content,
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
from kleptography.app.css.loader import load_css
from kleptography.app.html.renderer import render_html
from kleptography.app.navigation import young_yung_setup_page
from kleptography.crypto.aead.aes_gcm import decrypt
from kleptography.crypto.aead.exceptions import (
    AeadAuthenticationError,
    InvalidAeadKey,
)
from kleptography.crypto.channel.exceptions import InvalidChannelMessage
from kleptography.crypto.channel.protocol import run_channel
from kleptography.crypto.channel.records import (
    MAX_MESSAGE_LENGTH,
    ChannelTranscript,
    PlainMessage,
    SessionTranscript,
)
from kleptography.crypto.channel.setup.attacker import intercept_channel
from kleptography.crypto.dh.exceptions import InvalidPrivateKey
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.kdf.exceptions import InvalidKdfInput
from kleptography.crypto.kdf.one_step import derive_key
from kleptography.crypto.kdf.records import KeyDerivation

# Widget and session state prefix, and session state keys.
_PREFIX = "ch"
_BACKDOOR = "ch_backdoor"
_RUN = "ch_run"
_ATTACKER_PREFIX = "ch_attacker"
_RUN_COUNT = "ch_run_count"
_SESSION = "ch_attacker_session"
# Workbench widgets get these prefixes plus the run and the session (see
# _workbench_key), so every session of every run starts with empty fields.
_PRIVATE_KEY = "ch_attacker_private_key"
_SHARED_SECRET = "ch_attacker_shared_secret"
_SESSION_KEY = "ch_attacker_key"
_MESSAGE = "ch_attacker_message"

# The channel accepts any number of sessions; the UI keeps it readable.
_SESSIONS_MIN = 2
_SESSIONS_MAX = len(DEFAULT_MESSAGES)
_SESSIONS_DEFAULT = 3

# From this size on (FFDHE6144, FFDHE8192), running the channel takes long.
_SLOW_GROUP_BITS = 6144


@dataclass(frozen=True, slots=True)
class Backdoor:
    """The attacker and the SETUP configuration it can embed in a device."""

    attacker: YoungYungAttacker
    configuration: YoungYungConfiguration


def render_page_encrypted_channel() -> None:
    """Render the encrypted channel section."""
    render_html("", css=load_css("protocol.css"))
    st.markdown(CalloutComposer.css(), unsafe_allow_html=True)

    render_component_back_home()

    st.title("Encrypted channel compromised by the SETUP")
    st.markdown(build_channel_intro_content(), unsafe_allow_html=True)
    st.page_link(
        young_yung_setup_page(),
        label="Young–Yung SETUP on Diffie-Hellman",
        icon=":material/school:",
    )

    concept_tab, participant_tab, attacker_tab = st.tabs(
        [
            ":material/lightbulb: The idea",
            ":material/forum: Participant",
            ":material/visibility: Attacker",
        ]
    )

    with concept_tab:
        st.markdown(build_channel_concept_content(), unsafe_allow_html=True)

    with participant_tab:
        _render_participant()

    with attacker_tab:
        _render_attacker()

    render_component_footer()


def _render_participant() -> None:
    """Render the Participant tab."""
    st.markdown(build_participant_intro_content(), unsafe_allow_html=True)

    number_format = render_component_number_format(key_prefix=_PREFIX)

    st.header("1 · Choose the public parameters")
    parameters = render_component_group_selection(
        key_prefix=_PREFIX, number_format=number_format
    )
    backdoor = _backdoor_for(parameters)

    st.divider()
    device_kind = _render_device_section()

    st.divider()
    sessions = _render_messages_section()

    st.divider()
    _render_run_section(parameters, backdoor, device_kind, sessions)
    _render_sessions_section(parameters, backdoor, device_kind, number_format)


def _backdoor_for(parameters: DiffieHellmanParameters) -> Backdoor:
    """Return the backdoor for the group, regenerated only when it changes."""
    # The backdoor exists before any session, whatever device Alice uses. It
    # is regenerated only when the group changes.
    backdoor: Backdoor | None = st.session_state.get(_BACKDOOR)
    if backdoor is None or backdoor.attacker.parameters != parameters:
        attacker = YoungYungAttacker.generate(parameters)
        backdoor = Backdoor(attacker, attacker.generate_configuration())
        st.session_state[_BACKDOOR] = backdoor
    return backdoor


def _render_device_section() -> DeviceKind:
    """Render section 2 and return the device chosen for Alice."""
    st.header("2 · Choose Alice's device")
    st.markdown(
        "Alice's ephemeral keys come from a device she cannot inspect. Pick "
        "the one she uses."
    )

    device_kind = DeviceKind(
        st.segmented_control(
            "Alice's device",
            options=list(DeviceKind),
            default=DeviceKind.COMPROMISED,
            required=True,
            key="ch_device_kind",
        )
    )
    st.markdown(build_device_choice_content(), unsafe_allow_html=True)

    return device_kind


def _render_messages_section() -> list[list[PlainMessage]] | None:
    """Render section 3 and return the messages, or ``None`` if one is invalid."""
    st.header("3 · Write the messages")
    st.markdown(
        "Every session starts with a new key exchange. In each one, Alice "
        "and Bob send each other one message. Messages are printable ASCII "
        f"of up to {MAX_MESSAGE_LENGTH} characters; leave a field empty to "
        "skip that message."
    )
    st.markdown(build_messages_tip_content(), unsafe_allow_html=True)

    count = int(
        st.number_input(
            "Number of sessions",
            min_value=_SESSIONS_MIN,
            max_value=_SESSIONS_MAX,
            value=_SESSIONS_DEFAULT,
            step=1,
            key="ch_session_count",
        )
    )

    st.button(
        "Restore the example messages",
        icon=":material/restart_alt:",
        on_click=_restore_messages,
        key="ch_restore_messages",
    )

    sessions: list[list[PlainMessage]] = []
    invalid = False
    for number in range(1, count + 1):
        with st.container(border=True):
            st.markdown(f"**:material/edit_note: Session {number}**")
            alice_column, bob_column = st.columns(2)
            texts = (
                (
                    Actor.ALICE,
                    _render_message_input(alice_column, "Alice → Bob", number, 0),
                ),
                (
                    Actor.BOB,
                    _render_message_input(bob_column, "Bob → Alice", number, 1),
                ),
            )

        messages: list[PlainMessage] = []
        for sender, text in texts:
            if not text:
                continue
            try:
                messages.append(PlainMessage(sender=sender, text=text))
            except InvalidChannelMessage:
                invalid = True
        sessions.append(messages)

    if invalid:
        st.error(
            "Messages must be printable ASCII text: letters, digits, spaces "
            "and punctuation, without accents or emoji.",
            icon=":material/error:",
        )
        return None

    return sessions


def _message_key(number: int, direction: int) -> str:
    """Return the widget key of one message."""
    return f"ch_message_{number}_{'alice' if direction == 0 else 'bob'}"


def _render_message_input(
    column: DeltaGenerator, label: str, number: int, direction: int
) -> str:
    """Render the text field of one message and return its text."""
    # The example texts are set through Session State (not ``value=``), so
    # the restore button can put them back.
    key = _message_key(number, direction)
    if key not in st.session_state:
        st.session_state[key] = DEFAULT_MESSAGES[number - 1][direction]
    return column.text_input(
        label,
        max_chars=MAX_MESSAGE_LENGTH,
        key=key,
        icon=":material/edit:",
        placeholder="Write a message, or leave empty to skip it",
    )


def _restore_messages() -> None:
    """Put the example messages back in every field."""
    for number, texts in enumerate(DEFAULT_MESSAGES, start=1):
        for direction, text in enumerate(texts):
            st.session_state[_message_key(number, direction)] = text


def _render_run_section(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    device_kind: DeviceKind,
    sessions: Sequence[Sequence[PlainMessage]] | None,
) -> None:
    """Render section 4 and run the channel when the button is pressed."""
    st.header("4 · Run the channel")

    if parameters.bit_length >= _SLOW_GROUP_BITS:
        st.warning(
            f"With a {parameters.bit_length}-bit prime, every modular "
            "exponentiation takes about a second in pure Python, and each "
            "session needs over a dozen of them. Expect a long wait, and keep "
            "the page open until it finishes.",
            icon=":material/hourglass_top:",
        )

    if not st.button(
        "Run every session",
        type="primary",
        icon=":material/play_arrow:",
        disabled=sessions is None,
        key="ch_run_button",
    ):
        return

    assert sessions is not None
    with st.spinner(
        f"Running {len(sessions)} sessions and the attacker's recovery…",
        show_time=True,
    ):
        st.session_state[_RUN] = _run_experiment(
            parameters, backdoor, device_kind, sessions
        )
    st.session_state[_RUN_COUNT] = st.session_state.get(_RUN_COUNT, 0) + 1


def _run_experiment(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    device_kind: DeviceKind,
    sessions: Sequence[Sequence[PlainMessage]],
) -> ChannelExperiment:
    """Run the channel with the chosen device and intercept it once."""
    configuration = backdoor.configuration
    bob = DiffieHellmanParticipant(parameters)

    if device_kind is DeviceKind.COMPROMISED:
        device = YoungYungDiffieHellmanParticipant(parameters, configuration)
        run = run_channel(device, bob, sessions)
        derivations = device.derivations
    else:
        run = run_channel(DiffieHellmanParticipant(parameters), bob, sessions)
        derivations = ()

    return ChannelExperiment(
        device_kind=device_kind,
        attacker=backdoor.attacker,
        configuration=configuration,
        run=run,
        derivations=derivations,
        interception=intercept_channel(
            run.transcript,
            attacker=backdoor.attacker,
            configuration=configuration,
        ),
    )


def _render_sessions_section(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    device_kind: DeviceKind,
    number_format: NumberFormat,
) -> None:
    """Render one tab per session of the last run."""
    experiment: ChannelExperiment | None = st.session_state.get(_RUN)

    if experiment is None:
        st.caption("Run the channel to follow each session.")
        return

    if (
        experiment.parameters != parameters
        or experiment.configuration != backdoor.configuration
        or experiment.device_kind is not device_kind
    ):
        st.info(
            "The group or Alice's device changed since the last run. Run the "
            "channel again to see it with the new settings.",
            icon=":material/refresh:",
        )
        return

    st.markdown(
        f"Alice's device in this run: **{experiment.device_kind.value}**. Open "
        "each session to see what the participants computed and sent."
    )

    display = ValueDisplay(number_format, parameters.bit_length)
    sessions = experiment.run.sessions
    tabs = st.tabs([f"Session {session.number}" for session in sessions])
    for tab, session in zip(tabs, sessions, strict=True):
        with tab:
            render_component_channel_session(
                session, parameters=parameters, display=display
            )

    st.markdown(build_indistinguishable_content(), unsafe_allow_html=True)


def _render_attacker() -> None:
    """Render the Attacker tab."""
    st.markdown(build_attacker_intro_content(), unsafe_allow_html=True)

    experiment: ChannelExperiment | None = st.session_state.get(_RUN)
    if experiment is None:
        st.info(
            "Nothing has crossed the network yet. Run the channel in the "
            "Participant tab first.",
            icon=":material/forum:",
        )
        return

    number_format = render_component_number_format(key_prefix=_ATTACKER_PREFIX)
    display = ValueDisplay(number_format, experiment.parameters.bit_length)
    transcript = experiment.run.transcript

    st.header("1 · What you know")
    st.markdown(
        "The system is public (Kerckhoffs): the group of the last run, with "
        f"a **{experiment.parameters.bit_length}-bit** prime, and the "
        f"ciphersuite `{CIPHERSUITE_NAME}`. You also keep the artifacts of "
        "your backdoor:"
    )
    render_component_backdoor(
        attacker=experiment.attacker,
        configuration=experiment.configuration,
        display=display,
    )
    st.markdown(build_artifacts_content(), unsafe_allow_html=True)

    st.divider()
    st.header("2 · What crossed the network")
    st.markdown(
        "This is the whole transcript of the last run: every public key and "
        "every encrypted message. Eve recorded exactly the same."
    )
    render_component_transcript(transcript, display=display)

    st.divider()
    _render_workbench(experiment, transcript, display)

    st.divider()
    st.header("4 · Summary")
    st.markdown(
        "The same recovery, applied to every session at once. Bob reads "
        "everything because he holds the keys; Eve reads nothing."
    )
    render_component_interception_summary(experiment.interception, experiment)
    st.markdown(build_eve_content(), unsafe_allow_html=True)


def _render_workbench(
    experiment: ChannelExperiment,
    transcript: ChannelTranscript,
    display: ValueDisplay,
) -> None:
    """Render the attacker's workbench for the selected session."""
    st.header("3 · Your workbench")
    st.markdown(
        "Pick a session and read it step by step. Each field starts empty: "
        "type a value, or press the button next to it to paste the result of "
        "the previous step. Changing the session starts over. Values you "
        "compute are highlighted in :orange[**orange**]."
    )

    sessions = transcript.sessions
    numbers = [session.number for session in sessions]
    if st.session_state.get(_SESSION) not in numbers:
        st.session_state[_SESSION] = 2
    selected = st.segmented_control(
        "Session",
        options=numbers,
        format_func=lambda option: f"Session {option}",
        required=True,
        key=_SESSION,
    )
    number = 2 if selected is None else selected
    session = sessions[number - 1]
    intercepted = experiment.interception.sessions[number - 1]
    scope = f"{st.session_state.get(_RUN_COUNT, 0)}_{number}"
    recover_step, secret_step, key_step, decrypt_step = workbench_step_definitions(
        number
    )

    with render_component_step(1, recover_step):
        recovered, candidate_keys = _render_recovery_step(experiment, number, display)

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
        field=_workbench_key(_PRIVATE_KEY, scope),
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
        field=_workbench_key(_SHARED_SECRET, scope),
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
        key=_workbench_key(_MESSAGE, scope),
    )
    message = session.messages[index]
    render_component_encrypted_message(message)

    text = _render_workbench_input(
        f"Session key $K_{{{session.number}}}$ (64 hexadecimal digits)",
        field=_workbench_key(_SESSION_KEY, scope),
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
