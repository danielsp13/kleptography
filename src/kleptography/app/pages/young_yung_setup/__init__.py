"""Interactive section: the Young–Yung SETUP on Diffie-Hellman, step by step.

The section has three tabs: the idea of a SETUP, the complete mathematical
development, and an experiment. The experiment only orchestrates the
``crypto`` API: it creates an attacker and the configuration it embeds in a
``YoungYungDiffieHellmanParticipant``, runs two traced exchanges between that
device and honest Bobs, and lets the attacker recover the second key from
the public values of both timelines.

Modules:
    page: the entry point, which lays out the tabs and the sidebar.
    outline: the tabs and their headings, for the tabs and the sidebar.
    state: the session state and widget keys.
    sections: the Experiment tab and its numbered sections.
    experiment: the backdoor and the run of both exchanges, without Streamlit.
    timeline: the step-by-step timeline of the last run.
"""

from __future__ import annotations

from kleptography.app.pages.young_yung_setup.page import render_page_young_yung_setup

__all__ = ["render_page_young_yung_setup"]
