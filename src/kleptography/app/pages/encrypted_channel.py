"""
Interactive section: an encrypted channel compromised by the Young–Yung SETUP.

The section has three tabs: the idea (the channel, its ciphersuite and how
the SETUP breaks it), the participant's point of view (running the channel
with an honest or a compromised Alice) and the attacker's point of view
(reading the channel from its public transcript and the trapdoor). It only
orchestrates the ``crypto`` API.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import streamlit as st

from kleptography.app.components.controls import (
    render_component_group_selection,
    render_component_number_format,
)
from kleptography.app.components.encrypted_channel import (
    ChannelExperiment,
    DeviceKind,
    render_component_channel_session,
)
from kleptography.app.components.footer import render_component_footer
from kleptography.app.components.navigation import render_component_back_home
from kleptography.app.components.protocol import ValueDisplay
from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.encrypted_channel import (
    DEFAULT_MESSAGES,
    build_channel_concept_content,
    build_channel_intro_content,
    build_device_choice_content,
    build_indistinguishable_content,
    build_participant_intro_content,
)
from kleptography.app.content.numbers import NumberFormat
from kleptography.app.css.loader import load_css
from kleptography.app.html.renderer import render_html
from kleptography.app.navigation import young_yung_setup_page
from kleptography.crypto.channel.exceptions import InvalidChannelMessage
from kleptography.crypto.channel.protocol import run_channel
from kleptography.crypto.channel.records import MAX_MESSAGE_LENGTH, PlainMessage
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.tracing.events import Actor

# Widget and session state prefix, and session state keys.
_PREFIX = "ch"
_BACKDOOR = "ch_backdoor"
_RUN = "ch_run"

# The channel accepts any number of sessions; the UI keeps it readable.
_SESSIONS_MIN = 2
_SESSIONS_MAX = len(DEFAULT_MESSAGES)
_SESSIONS_DEFAULT = 3


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
        st.info("The attacker's point of view is under construction.")

    render_component_footer()


def _render_participant() -> None:
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
    # The backdoor exists before any session, whatever device Alice uses. It
    # is regenerated only when the group changes.
    backdoor: Backdoor | None = st.session_state.get(_BACKDOOR)
    if backdoor is None or backdoor.attacker.parameters != parameters:
        attacker = YoungYungAttacker.generate(parameters)
        backdoor = Backdoor(attacker, attacker.generate_configuration())
        st.session_state[_BACKDOOR] = backdoor
    return backdoor


def _render_device_section() -> DeviceKind:
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
    st.header("3 · Write the messages")
    st.markdown(
        "Every session starts with a new key exchange. In each one, Alice "
        "and Bob send each other one message. Messages are printable ASCII "
        f"of up to {MAX_MESSAGE_LENGTH} characters; leave a field empty to "
        "skip that message."
    )

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

    sessions: list[list[PlainMessage]] = []
    invalid = False
    for number, (alice_default, bob_default) in enumerate(
        DEFAULT_MESSAGES[:count], start=1
    ):
        st.markdown(f"**Session {number}**")
        alice_column, bob_column = st.columns(2)
        texts = (
            (
                Actor.ALICE,
                alice_column.text_input(
                    "Alice → Bob",
                    value=alice_default,
                    max_chars=MAX_MESSAGE_LENGTH,
                    key=f"ch_message_{number}_alice",
                ),
            ),
            (
                Actor.BOB,
                bob_column.text_input(
                    "Bob → Alice",
                    value=bob_default,
                    max_chars=MAX_MESSAGE_LENGTH,
                    key=f"ch_message_{number}_bob",
                ),
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


def _render_run_section(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    device_kind: DeviceKind,
    sessions: Sequence[Sequence[PlainMessage]] | None,
) -> None:
    st.header("4 · Run the channel")

    if not st.button(
        "Run every session",
        type="primary",
        icon=":material/play_arrow:",
        disabled=sessions is None,
        key="ch_run_button",
    ):
        return

    assert sessions is not None
    configuration = backdoor.configuration
    bob = DiffieHellmanParticipant(parameters)

    if device_kind is DeviceKind.COMPROMISED:
        device = YoungYungDiffieHellmanParticipant(parameters, configuration)
        run = run_channel(device, bob, sessions)
        derivations = device.derivations
    else:
        run = run_channel(DiffieHellmanParticipant(parameters), bob, sessions)
        derivations = ()

    st.session_state[_RUN] = ChannelExperiment(
        device_kind=device_kind,
        attacker=backdoor.attacker,
        configuration=configuration,
        run=run,
        derivations=derivations,
    )


def _render_sessions_section(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    device_kind: DeviceKind,
    number_format: NumberFormat,
) -> None:
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
