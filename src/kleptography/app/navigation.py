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


def young_yung_setup_page() -> StreamlitPage:
    """Return the Young–Yung SETUP section on Diffie-Hellman."""
    from kleptography.app.pages.young_yung_setup import (
        render_page_young_yung_setup,
    )

    return st.Page(
        render_page_young_yung_setup,
        title="Young–Yung SETUP · Kleptography",
        icon="🕵️",
        url_path="young-yung-setup",
    )


def encrypted_channel_page() -> StreamlitPage:
    """Return the encrypted channel compromised by the SETUP."""
    from kleptography.app.pages.encrypted_channel import (
        render_page_encrypted_channel,
    )

    return st.Page(
        render_page_encrypted_channel,
        title="Encrypted channel · Kleptography",
        icon="🔐",
        url_path="encrypted-channel",
    )


def all_pages() -> list[StreamlitPage]:
    """Return every page of the application, the default page first."""
    return [
        home_page(),
        diffie_hellman_page(),
        young_yung_setup_page(),
        encrypted_channel_page(),
    ]
