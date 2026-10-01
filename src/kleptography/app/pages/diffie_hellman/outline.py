"""Outline of the Diffie-Hellman section: its headings, for the sidebar."""

from __future__ import annotations

from kleptography.app.components.navigation import PageAnchor

# The headings of the section, for the sidebar.
ANCHORS = (
    PageAnchor("1 · Choose the public parameters", "dh-parameters"),
    PageAnchor("2 · Choose the private keys", "dh-keys"),
    PageAnchor("3 · Run the exchange", "dh-run"),
)
