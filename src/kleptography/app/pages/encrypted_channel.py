"""
Interactive section: an encrypted channel compromised by the Young–Yung SETUP.

The section has three tabs: the idea (the channel, its ciphersuite and how
the SETUP breaks it), the participant's point of view (running the channel
with an honest or a compromised Alice) and the attacker's point of view
(reading the channel from its public transcript and the trapdoor). It only
orchestrates the ``crypto`` API.
"""

from __future__ import annotations

import streamlit as st

from kleptography.app.components.footer import render_component_footer
from kleptography.app.components.navigation import render_component_back_home
from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.encrypted_channel import (
    build_channel_concept_content,
    build_channel_intro_content,
)
from kleptography.app.css.loader import load_css
from kleptography.app.html.renderer import render_html
from kleptography.app.navigation import young_yung_setup_page


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
        st.info("The participant's point of view is under construction.")

    with attacker_tab:
        st.info("The attacker's point of view is under construction.")

    render_component_footer()
