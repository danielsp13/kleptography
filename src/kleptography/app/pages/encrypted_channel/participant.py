"""The Participant tab of the encrypted channel section.

The reader chooses the group, Alice's device and the messages, runs the
channel and follows each session from the participants' point of view.
"""

from __future__ import annotations

from collections.abc import Sequence

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
)
from kleptography.app.components.protocol import ValueDisplay
from kleptography.app.components.young_yung_setup import Backdoor
from kleptography.app.content.encrypted_channel import (
    DEFAULT_MESSAGES,
    build_device_choice_content,
    build_indistinguishable_content,
    build_messages_tip_content,
    build_participant_intro_content,
)
from kleptography.app.content.numbers import NumberFormat
from kleptography.app.pages.encrypted_channel.experiment import (
    run_experiment,
)
from kleptography.app.pages.encrypted_channel.state import (
    BACKDOOR,
    PREFIX,
    RUN,
    RUN_COUNT,
)
from kleptography.crypto.channel.exceptions import InvalidChannelMessage
from kleptography.crypto.channel.records import MAX_MESSAGE_LENGTH, PlainMessage
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.tracing.events import Actor

# The channel accepts any number of sessions; the UI keeps it readable.
_SESSIONS_MIN = 2
_SESSIONS_MAX = len(DEFAULT_MESSAGES)
_SESSIONS_DEFAULT = 3

# From this size on (FFDHE6144, FFDHE8192), running the channel takes long.
_SLOW_GROUP_BITS = 6144


def render_participant() -> None:
    """Render the Participant tab."""
    st.markdown(build_participant_intro_content(), unsafe_allow_html=True)

    number_format = render_component_number_format(key_prefix=PREFIX)

    st.header("1 · Choose the public parameters", anchor="ch-parameters")
    parameters = render_component_group_selection(
        key_prefix=PREFIX, number_format=number_format
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
    backdoor: Backdoor | None = st.session_state.get(BACKDOOR)
    if backdoor is None or backdoor.attacker.parameters != parameters:
        backdoor = Backdoor.generate(parameters)
        st.session_state[BACKDOOR] = backdoor
    return backdoor


def _render_device_section() -> DeviceKind:
    """Render section 2 and return the device chosen for Alice."""
    st.header("2 · Choose Alice's device", anchor="ch-device")
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
    st.header("3 · Write the messages", anchor="ch-messages")
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
    st.header("4 · Run the channel", anchor="ch-run")

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
        st.session_state[RUN] = run_experiment(
            parameters, backdoor, device_kind, sessions
        )
    st.session_state[RUN_COUNT] = st.session_state.get(RUN_COUNT, 0) + 1


def _render_sessions_section(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    device_kind: DeviceKind,
    number_format: NumberFormat,
) -> None:
    """Render one tab per session of the last run."""
    experiment: ChannelExperiment | None = st.session_state.get(RUN)

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
