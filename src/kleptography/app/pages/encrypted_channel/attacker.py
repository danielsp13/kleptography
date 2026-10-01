"""The Attacker tab of the encrypted channel section.

The reader takes the attacker's seat on the last run: what it knows, the
public transcript, the workbench and a summary of every session.
"""

from __future__ import annotations

import streamlit as st

from kleptography.app.components.controls import render_component_number_format
from kleptography.app.components.encrypted_channel import (
    ChannelExperiment,
    render_component_interception_summary,
    render_component_transcript,
)
from kleptography.app.components.protocol import ValueDisplay
from kleptography.app.components.young_yung_setup import render_component_backdoor
from kleptography.app.content.encrypted_channel import (
    CIPHERSUITE_NAME,
    build_artifacts_content,
    build_attacker_intro_content,
    build_eve_content,
)
from kleptography.app.pages.encrypted_channel.state import ATTACKER_PREFIX, RUN
from kleptography.app.pages.encrypted_channel.workbench import render_workbench


def render_attacker() -> None:
    """Render the Attacker tab."""
    st.markdown(build_attacker_intro_content(), unsafe_allow_html=True)

    experiment: ChannelExperiment | None = st.session_state.get(RUN)
    if experiment is None:
        st.info(
            "Nothing has crossed the network yet. Run the channel in the "
            "Participant tab first.",
            icon=":material/forum:",
        )
        return

    number_format = render_component_number_format(key_prefix=ATTACKER_PREFIX)
    display = ValueDisplay(number_format, experiment.parameters.bit_length)
    transcript = experiment.run.transcript

    st.header("1 · What you know", anchor="ch-attacker-known")
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
    st.header("2 · What crossed the network", anchor="ch-attacker-transcript")
    st.markdown(
        "This is the whole transcript of the last run: every public key and "
        "every encrypted message. Eve recorded exactly the same."
    )
    render_component_transcript(transcript, display=display)

    st.divider()
    render_workbench(experiment, transcript, display)

    st.divider()
    st.header("4 · Summary", anchor="ch-attacker-summary")
    st.markdown(
        "The same recovery, applied to every session at once. Bob reads "
        "everything because he holds the keys; Eve reads nothing."
    )
    render_component_interception_summary(experiment.interception, experiment)
    st.markdown(build_eve_content(), unsafe_allow_html=True)
