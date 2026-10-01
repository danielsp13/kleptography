"""Isolation tests for the KDF package.

The KDF package is generic: it never depends on DH or other schemes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import kleptography.crypto.kdf as kdf_package

KDF_ROOT = Path(kdf_package.__file__).parent
KDF_MODULES = sorted(KDF_ROOT.rglob("*.py"))


def test_kdf_modules_are_found() -> None:
    """The scan covers every KDF module."""
    names = {path.name for path in KDF_MODULES}

    assert {"exceptions.py", "one_step.py", "records.py"} <= names


@pytest.mark.parametrize(
    "path",
    KDF_MODULES,
    ids=[str(path.relative_to(KDF_ROOT)) for path in KDF_MODULES],
)
def test_kdf_module_imports_only_itself(path: Path) -> None:
    """KDF modules import only the KDF package."""
    project_imports = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if "kleptography." in line and ("import" in line or "from" in line)
    ]

    assert all("kleptography.crypto.kdf." in line for line in project_imports)
