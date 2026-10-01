"""Session state and widget keys of the Young–Yung SETUP section.

Every key of the section starts with ``yy``. Changing one loses the state
stored under it, so the keys shared by several modules are defined here.
"""

from __future__ import annotations

# Widget and session state prefix, and session state keys.
PREFIX = "yy"
TAB = "yy_tab"
BACKDOOR = "yy_backdoor"
RUN = "yy_run"
REVEALED = "yy_revealed"
