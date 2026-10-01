"""Isolation tests for the honest DH code.

The honest DH code never depends on the kleptographic SETUP (principle 2).
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path

import pytest

import kleptography.crypto.dh as honest_package
from kleptography.crypto.dh.participant import DiffieHellmanParticipant

HONEST_ROOT = Path(honest_package.__file__).parent
HONEST_MODULES = sorted(
    path
    for path in HONEST_ROOT.rglob("*.py")
    if "setup" not in path.relative_to(HONEST_ROOT).parts
)


def test_honest_modules_are_found() -> None:
    """The scan covers the honest participant, protocol and validation."""
    names = {path.name for path in HONEST_MODULES}

    assert {"participant.py", "protocol.py", "validation.py"} <= names


@pytest.mark.parametrize(
    "path",
    HONEST_MODULES,
    ids=[str(path.relative_to(HONEST_ROOT)) for path in HONEST_MODULES],
)
def test_honest_module_does_not_import_setup(path: Path) -> None:
    """No honest DH module imports the SETUP."""
    source = path.read_text(encoding="utf-8")

    assert "kleptography.crypto.dh.setup" not in source
    assert "from .setup" not in source


def test_honest_participant_has_no_setup_fields() -> None:
    """The honest participant has no SETUP field."""
    names = {field.name for field in fields(DiffieHellmanParticipant)}

    assert names == {"parameters", "_private_key", "_public_key"}
