"""Navigation components: links between pages and inside a section."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import streamlit as st
from streamlit.delta_generator import DeltaGenerator

from kleptography.app.css.loader import load_css
from kleptography.app.html.loader import render_template
from kleptography.app.html.renderer import render_html
from kleptography.app.navigation import (
    diffie_hellman_page,
    encrypted_channel_page,
    home_page,
    young_yung_setup_page,
)


@dataclass(frozen=True, slots=True)
class SectionCard:
    """A section of the application, as presented on the home page.

    Attributes:
        title: The section name.
        description: A one or two sentence summary (plain text).
        status: A short status label shown as a badge.
        url_path: The page ``url_path`` to open, or ``None`` if the section
            is not available yet.
    """

    title: str
    description: str
    status: str
    url_path: str | None


def render_component_back_home() -> None:
    """Render a link back to the home page."""
    st.page_link(home_page(), label="Back to home", icon=":material/arrow_back:")


def render_component_section_cards(cards: Sequence[SectionCard]) -> None:
    """Render the section cards as a grid of equally sized, fully clickable cards.

    Each available card is a plain link to its page's URL (relative, so it
    also works under a base URL path). Unavailable cards are rendered
    disabled.

    Args:
        cards: The sections to present, in display order.
    """
    html = render_template(
        "section_cards.html",
        cards=[
            {
                "title": card.title,
                "description": card.description,
                "status": card.status,
                "href": card.url_path,
            }
            for card in cards
        ],
    )

    render_html(html, css=load_css("section_cards.css"))


@dataclass(frozen=True, slots=True)
class PageAnchor:
    """A heading of a section that the sidebar links to.

    Attributes:
        label: The text of the link (Markdown, may contain inline LaTeX).
        anchor: The ``id`` of the heading, without ``#``.
    """

    label: str
    anchor: str


@dataclass(frozen=True, slots=True)
class SectionTab:
    """A tab of a section, with the headings it contains.

    Attributes:
        title: The tab name, without icon.
        icon: A Material icon (``:material/name:``).
        anchors: The headings of the tab, in display order.
    """

    title: str
    icon: str
    anchors: tuple[PageAnchor, ...] = ()

    @property
    def label(self) -> str:
        """The label shown on the tab, which also identifies it."""
        return f"{self.icon} {self.title}"


def render_component_section_tabs(
    tabs: Sequence[SectionTab], *, state_key: str
) -> Sequence[DeltaGenerator]:
    """Render the main tabs of a section, which stick under the page header.

    The tabs keep their state in ``st.session_state[state_key]`` (the label
    of the active tab), so the sidebar can switch them. Every tab still
    renders on each run, so the widgets inside keep their values.

    Args:
        tabs: The tabs of the section, in display order.
        state_key: The session state key of the active tab.

    Returns:
        One container per tab, in the same order.
    """
    # The keyed container lets section_navigation.css make only these tabs
    # sticky, not the nested ones (e.g. one tab per session).
    container = st.container(key=f"section-tabs-{state_key}")
    return container.tabs([tab.label for tab in tabs], key=state_key, on_change="rerun")


def render_component_section_sidebar(
    tabs: Sequence[SectionTab], *, state_key: str
) -> None:
    """Render the sidebar of a section: its tabs, their headings and the sections.

    Each tab is a button that opens it; the headings of the active tab are
    anchor links. Below, links to home and to every interactive section.
    Call it after ``render_component_section_tabs``, with the same tabs.

    Args:
        tabs: The tabs of the section, as passed to the tabs.
        state_key: The session state key of the active tab.
    """
    render_html("", css=load_css("section_navigation.css"))
    active = st.session_state.get(state_key, tabs[0].label)

    with st.sidebar:
        _render_sidebar_heading("On this page")
        for index, tab in enumerate(tabs):
            is_active = tab.label == active
            st.button(
                tab.title,
                icon=tab.icon,
                type="primary" if is_active else "tertiary",
                on_click=_select_tab,
                args=(state_key, tab.label),
                width="stretch",
                key=f"section-sidebar-tab-{state_key}-{index}",
            )
            if is_active and tab.anchors:
                with st.container(key=f"section-anchors-{state_key}"):
                    st.markdown(
                        "\n".join(
                            f"- [{anchor.label}](#{anchor.anchor})"
                            for anchor in tab.anchors
                        )
                    )

        st.divider()
        _render_sidebar_heading("Sections")
        st.page_link(home_page(), label="Home", icon=":material/home:")
        st.page_link(
            diffie_hellman_page(), label="Diffie-Hellman", icon=":material/key:"
        )
        st.page_link(
            young_yung_setup_page(),
            label="Young–Yung SETUP",
            icon=":material/policy:",
        )
        st.page_link(
            encrypted_channel_page(),
            label="Encrypted channel",
            icon=":material/lock:",
        )


def _render_sidebar_heading(text: str) -> None:
    """Render a small heading of the sidebar."""
    st.html(f'<p class="section-sidebar__heading">{text}</p>')


def _select_tab(state_key: str, label: str) -> None:
    """Open a tab of the section (a button callback)."""
    st.session_state[state_key] = label
