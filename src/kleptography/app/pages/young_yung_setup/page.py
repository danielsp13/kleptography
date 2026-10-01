"""Entry point of the Young–Yung SETUP section: its layout.

The page shows the introduction, the three tabs and the sidebar; the
Experiment tab is rendered by its own module.
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
from kleptography.app.content.young_yung_setup import (
    build_setup_concept_content,
    build_setup_formulae_content,
    build_setup_intro_content,
)
from kleptography.app.css.loader import load_css
from kleptography.app.html.renderer import render_html
from kleptography.app.pages.young_yung_setup.outline import TABS
from kleptography.app.pages.young_yung_setup.sections import render_experiment
from kleptography.app.pages.young_yung_setup.state import TAB


def render_page_young_yung_setup() -> None:
    """Render the Young–Yung SETUP section."""
    render_html("", css=load_css("protocol.css"))
    st.markdown(CalloutComposer.css(), unsafe_allow_html=True)

    render_component_back_home()

    st.title("Young–Yung SETUP on Diffie-Hellman")
    st.markdown(build_setup_intro_content(), unsafe_allow_html=True)

    concept_tab, formulae_tab, experiment_tab = render_component_section_tabs(
        TABS, state_key=TAB
    )

    with concept_tab:
        st.markdown(build_setup_concept_content(), unsafe_allow_html=True)

    with formulae_tab:
        st.markdown(build_setup_formulae_content(), unsafe_allow_html=True)

    with experiment_tab:
        render_experiment()

    render_component_section_sidebar(TABS, state_key=TAB)
    render_component_footer()
