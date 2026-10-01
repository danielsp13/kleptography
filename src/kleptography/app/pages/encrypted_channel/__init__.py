"""Interactive section: an encrypted channel compromised by the Young–Yung SETUP.

The section has three tabs: the idea (the channel, its ciphersuite and how
the SETUP breaks it), the participant's point of view (running the channel
with an honest or a compromised Alice) and the attacker's point of view
(reading the channel from its public transcript and the trapdoor). It only
orchestrates the ``crypto`` API.

Modules:
    page: the entry point, which lays out the tabs and the sidebar.
    outline: the tabs and their headings, for the tabs and the sidebar.
    state: the session state and widget keys.
    participant: the Participant tab.
    experiment: the backdoor and the run of the channel, without Streamlit.
    attacker: the Attacker tab.
    workbench: the attacker's workbench, section 3 of the Attacker tab.
"""

from __future__ import annotations

from kleptography.app.pages.encrypted_channel.page import (
    render_page_encrypted_channel,
)

__all__ = ["render_page_encrypted_channel"]
