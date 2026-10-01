"""Interactive section: an honest Diffie-Hellman key exchange, step by step.

The page only orchestrates: it builds parameters and participants through
the ``crypto`` API, runs ``perform_key_exchange`` with a
``ProtocolExecutionContext`` and renders the recorded timeline.

Modules:
    page: the entry point, which lays out the sections and the sidebar.
    outline: the headings of the section, for the sidebar.
    state: the session state and widget keys.
    sections: the numbered sections.
    experiment: the run of the exchange, without Streamlit.
    timeline: the step-by-step timeline of the last run.
"""

from __future__ import annotations

from kleptography.app.pages.diffie_hellman.page import render_page_diffie_hellman

__all__ = ["render_page_diffie_hellman"]
