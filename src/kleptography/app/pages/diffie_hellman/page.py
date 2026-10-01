"""Entry point of the Diffie-Hellman section: its layout.

The page shows the introduction, the numbered sections, the timeline of the
last run and the sidebar; each part is rendered by its own module.
"""

from __future__ import annotations

import streamlit as st

from kleptography.app.components.controls import render_component_number_format
from kleptography.app.components.footer import render_component_footer
from kleptography.app.components.navigation import (
    render_component_back_home,
    render_component_page_sidebar,
)
from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.diffie_hellman import build_dh_intro_content
from kleptography.app.css.loader import load_css
from kleptography.app.html.renderer import render_html
from kleptography.app.pages.diffie_hellman.outline import ANCHORS
from kleptography.app.pages.diffie_hellman.sections import (
    render_parameters_section,
    render_private_keys_section,
    render_run_section,
)
from kleptography.app.pages.diffie_hellman.state import PREFIX
from kleptography.app.pages.diffie_hellman.timeline import render_timeline_section


def render_page_diffie_hellman() -> None:
    """Render the interactive honest Diffie-Hellman section."""
    render_html("", css=load_css("protocol.css"))
    st.markdown(CalloutComposer.css(), unsafe_allow_html=True)

    render_component_back_home()

    st.title("Diffie-Hellman key exchange")
    st.markdown(build_dh_intro_content(), unsafe_allow_html=True)

    st.divider()
    number_format = render_component_number_format(key_prefix=PREFIX)
    parameters = render_parameters_section(number_format)

    st.divider()
    private_keys = render_private_keys_section(parameters)

    st.divider()
    render_run_section(parameters, private_keys)
    render_timeline_section(parameters, number_format)

    render_component_page_sidebar(ANCHORS, key_prefix=PREFIX)
    render_component_footer()
