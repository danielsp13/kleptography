"""Session state and widget keys of the encrypted channel section.

Every key of the section starts with ``ch``. Changing one loses the state
stored under it, so the keys shared by several modules are defined here.
"""

from __future__ import annotations

# Widget and session state prefix, and session state keys.
PREFIX = "ch"
TAB = "ch_tab"
BACKDOOR = "ch_backdoor"
RUN = "ch_run"
ATTACKER_PREFIX = "ch_attacker"
RUN_COUNT = "ch_run_count"
SESSION = "ch_attacker_session"
# Workbench widgets get these prefixes plus the run and the session (see
# workbench._workbench_key), so every session of every run starts with
# empty fields.
PRIVATE_KEY = "ch_attacker_private_key"
SHARED_SECRET = "ch_attacker_shared_secret"
SESSION_KEY = "ch_attacker_key"
MESSAGE = "ch_attacker_message"
