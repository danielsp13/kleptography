"""
Page registry for the Streamlit application.

Navigation is hidden (no sidebar): pages link to each other explicitly
through ``st.page_link``. Streamlit identifies a page by its ``url_path``,
so each factory can be called wherever a link is needed.

Page modules import this module to build links, so the page renderers are
imported inside the factories to avoid a circular import.
"""

from __future__ import annotations

import streamlit as st
from streamlit.navigation.page import StreamlitPage


def home_page() -> StreamlitPage:
    """Return the landing page."""
    from kleptography.app.pages.home import render_page_home

    return st.Page(
        render_page_home,
        title="Kleptography",
        icon="🦊",
        url_path="home",
        default=True,
    )


def diffie_hellman_page() -> StreamlitPage:
    """Return the interactive honest Diffie-Hellman section."""
    from kleptography.app.pages.diffie_hellman import render_page_diffie_hellman

    return st.Page(
        render_page_diffie_hellman,
        title="Diffie-Hellman · Kleptography",
        icon="🔑",
        url_path="diffie-hellman",
    )


def all_pages() -> list[StreamlitPage]:
    """Return every page of the application, the default page first."""
    return [home_page(), diffie_hellman_page()]
