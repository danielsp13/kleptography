"""Isolation tests for the channel attacker.

The channel attacker reuses the DH SETUP, the KDF and the AEAD: it has no
cryptography of its own and never depends on the presentation layer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import kleptography.crypto.channel.setup as attacker_package

ATTACKER_ROOT = Path(attacker_package.__file__).parent
ATTACKER_MODULES = sorted(ATTACKER_ROOT.rglob("*.py"))
ALLOWED_PREFIXES = (
    "kleptography.crypto.channel.",
    "kleptography.crypto.dh.",
    "kleptography.crypto.kdf.",
    "kleptography.crypto.aead.",
    "kleptography.math.",
)


def _project_imports(path: Path) -> list[str]:
    """Return the lines of a module that import project code."""
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if "kleptography." in line and ("import" in line or "from" in line)
    ]


def test_attacker_modules_are_found() -> None:
    """The scan covers every attacker module."""
    names = {path.name for path in ATTACKER_MODULES}

    assert {"exceptions.py", "records.py", "attacker.py"} <= names


@pytest.mark.parametrize(
    "path",
    ATTACKER_MODULES,
    ids=[str(path.relative_to(ATTACKER_ROOT)) for path in ATTACKER_MODULES],
)
def test_attacker_module_imports_only_allowed_packages(path: Path) -> None:
    """Attacker modules import only channel, DH, KDF, AEAD and math."""
    imports = _project_imports(path)

    assert all(line.split()[1].startswith(ALLOWED_PREFIXES) for line in imports)


@pytest.mark.parametrize(
    "path",
    ATTACKER_MODULES,
    ids=[str(path.relative_to(ATTACKER_ROOT)) for path in ATTACKER_MODULES],
)
def test_attacker_module_has_no_symmetric_primitives(path: Path) -> None:
    """Attacker modules use no UI and no primitive of their own."""
    source = path.read_text(encoding="utf-8")

    assert "import streamlit" not in source
    assert "cryptography.hazmat" not in source
    assert "hashlib" not in source
