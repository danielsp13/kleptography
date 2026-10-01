"""
The AEAD package is generic: it never depends on DH or other schemes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import kleptography.crypto.aead as aead_package

AEAD_ROOT = Path(aead_package.__file__).parent
AEAD_MODULES = sorted(AEAD_ROOT.rglob("*.py"))


def test_aead_modules_are_found() -> None:
    names = {path.name for path in AEAD_MODULES}

    assert {"aes_gcm.py", "exceptions.py", "records.py"} <= names


@pytest.mark.parametrize(
    "path",
    AEAD_MODULES,
    ids=[str(path.relative_to(AEAD_ROOT)) for path in AEAD_MODULES],
)
def test_aead_module_imports_only_itself(path: Path) -> None:
    project_imports = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if "kleptography." in line and ("import" in line or "from" in line)
    ]

    assert all("kleptography.crypto.aead." in line for line in project_imports)
