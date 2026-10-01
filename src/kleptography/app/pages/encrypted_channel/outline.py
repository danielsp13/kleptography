"""Outline of the encrypted channel section: its tabs and their headings."""

from __future__ import annotations

from dataclasses import replace

import streamlit as st

from kleptography.app.components.navigation import PageAnchor, SectionTab
from kleptography.app.pages.encrypted_channel.state import RUN

# The tabs of the section and their headings, for the tabs and the sidebar.
# The anchors of "The idea" are the ones Streamlit derives from the Markdown
# headings of build_channel_concept_content.
TABS = (
    SectionTab(
        "The idea",
        ":material/lightbulb:",
        (
            PageAnchor(
                "From a key exchange to a secure channel",
                "from-a-key-exchange-to-a-secure-channel",
            ),
            PageAnchor("The ciphersuite", "the-ciphersuite"),
            PageAnchor("What everyone knows", "what-everyone-knows"),
            PageAnchor(
                "How the SETUP breaks the channel", "how-the-setup-breaks-the-channel"
            ),
            PageAnchor("Session 1 stays confidential", "session-1-stays-confidential"),
            PageAnchor("Why nothing looks wrong", "why-nothing-looks-wrong"),
        ),
    ),
    SectionTab(
        "Participant",
        ":material/forum:",
        (
            PageAnchor("1 · Choose the public parameters", "ch-parameters"),
            PageAnchor("2 · Choose Alice's device", "ch-device"),
            PageAnchor("3 · Write the messages", "ch-messages"),
            PageAnchor("4 · Run the channel", "ch-run"),
        ),
    ),
    SectionTab(
        "Attacker",
        ":material/visibility:",
        (
            PageAnchor("1 · What you know", "ch-attacker-known"),
            PageAnchor("2 · What crossed the network", "ch-attacker-transcript"),
            PageAnchor("3 · Your workbench", "ch-attacker-workbench"),
            PageAnchor("4 · Summary", "ch-attacker-summary"),
        ),
    ),
)


def sidebar_tabs() -> tuple[SectionTab, ...]:
    """Return the tabs for the sidebar, without headings that are not shown."""
    # Until the channel runs, the Attacker tab has none of its headings.
    if st.session_state.get(RUN) is not None:
        return TABS
    concept, participant, attacker = TABS
    return concept, participant, replace(attacker, anchors=())
