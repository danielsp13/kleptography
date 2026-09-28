"""
Navigation components: links between the home page and the sections.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import streamlit as st

from kleptography.app.css.loader import load_css
from kleptography.app.html.loader import render_template
from kleptography.app.html.renderer import render_html
from kleptography.app.navigation import home_page


@dataclass(frozen=True, slots=True)
class SectionCard:
    """
    A section of the application, as presented on the home page.

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
    """
    Render the section cards as a grid of equally sized, fully clickable cards.

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
