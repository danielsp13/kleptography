"""
The channel is unaware of the SETUP: it never imports kleptographic code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import kleptography.crypto.channel as channel_package

CHANNEL_ROOT = Path(channel_package.__file__).parent
CHANNEL_MODULES = sorted(
    path
    for path in CHANNEL_ROOT.rglob("*.py")
    if "setup" not in path.relative_to(CHANNEL_ROOT).parts
)
ALLOWED_PREFIXES = (
    "kleptography.crypto.channel.",
    "kleptography.crypto.dh.",
    "kleptography.crypto.kdf.",
    "kleptography.crypto.aead.",
)


def _project_imports(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if "kleptography." in line and ("import" in line or "from" in line)
    ]


def test_channel_modules_are_found() -> None:
    names = {path.name for path in CHANNEL_MODULES}

    assert {"exceptions.py", "records.py", "session.py", "protocol.py"} <= names


@pytest.mark.parametrize(
    "path",
    CHANNEL_MODULES,
    ids=[str(path.relative_to(CHANNEL_ROOT)) for path in CHANNEL_MODULES],
)
def test_channel_module_imports_only_allowed_packages(path: Path) -> None:
    imports = _project_imports(path)

    assert all(line.split()[1].startswith(ALLOWED_PREFIXES) for line in imports)


@pytest.mark.parametrize(
    "path",
    CHANNEL_MODULES,
    ids=[str(path.relative_to(CHANNEL_ROOT)) for path in CHANNEL_MODULES],
)
def test_channel_module_never_imports_setup(path: Path) -> None:
    imports = _project_imports(path)

    assert not any("kleptography.crypto.dh.setup" in line for line in imports)
    assert not any("kleptography.crypto.channel.setup" in line for line in imports)
