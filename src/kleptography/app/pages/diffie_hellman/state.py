"""Session state and widget keys of the Diffie-Hellman section.

Every key of the section starts with ``dh``. Changing one loses the state
stored under it, so the keys shared by several modules are defined here.
"""

from __future__ import annotations

# Widget and session state prefix, and session state keys.
PREFIX = "dh"
RUN = "dh_run"
REVEALED = "dh_revealed"
