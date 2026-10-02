"""Kleptography: an educational study of SETUP backdoors in cryptography."""

from __future__ import annotations

from importlib.metadata import version

# Single source of truth: the version declared in pyproject.toml.
__version__ = version("kleptography")

# Release date of ``__version__`` (ISO 8601), shown in the header and footer.
# Update it together with the version and CHANGELOG.md.
__release_date__ = "2026-10-02"
