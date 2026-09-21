import streamlit as st

from kleptography.app.components.footer import render_component_footer
from kleptography.app.components.header import render_component_header
from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.home import build_home_content


def render_page_home() -> None:
    render_component_header()

    st.markdown(
        CalloutComposer.css(),
        unsafe_allow_html=True,
    )

    st.markdown(
        build_home_content(),
        unsafe_allow_html=True,
    )

    render_component_footer()
