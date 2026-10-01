"""Entry point of the encrypted channel section: its layout.

The page shows the introduction, the three tabs and the sidebar; each tab
is rendered by its own module.
"""

from __future__ import annotations

import streamlit as st

from kleptography.app.components.footer import render_component_footer
from kleptography.app.components.navigation import (
    render_component_back_home,
    render_component_section_sidebar,
    render_component_section_tabs,
)
from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.encrypted_channel import (
    build_channel_concept_content,
    build_channel_intro_content,
)
from kleptography.app.css.loader import load_css
from kleptography.app.html.renderer import render_html
from kleptography.app.navigation import young_yung_setup_page
from kleptography.app.pages.encrypted_channel.attacker import render_attacker
from kleptography.app.pages.encrypted_channel.outline import TABS, sidebar_tabs
from kleptography.app.pages.encrypted_channel.participant import (
    render_participant,
)
from kleptography.app.pages.encrypted_channel.state import TAB


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

    concept_tab, participant_tab, attacker_tab = render_component_section_tabs(
        TABS, state_key=TAB
    )

    with concept_tab:
        st.markdown(build_channel_concept_content(), unsafe_allow_html=True)

    with participant_tab:
        render_participant()

    with attacker_tab:
        render_attacker()

    # After the tabs, so the sidebar already sees a run made in this one.
    render_component_section_sidebar(sidebar_tabs(), state_key=TAB)
    render_component_footer()
