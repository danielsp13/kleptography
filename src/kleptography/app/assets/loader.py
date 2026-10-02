"""Access to the static assets bundled with the application."""

from __future__ import annotations

import base64
from pathlib import Path

_ASSETS_DIR = Path(__file__).resolve().parent


def asset_path(*parts: str) -> Path:
    """Return the path of an asset.

    Args:
        *parts: The path components relative to the assets directory.
    """
    return _ASSETS_DIR.joinpath(*parts)


def asset_base64(*parts: str) -> str:
    """Return the content of an asset encoded in base64.

    Args:
        *parts: The path components relative to the assets directory.
    """
    path = asset_path(*parts)
    return base64.b64encode(path.read_bytes()).decode("utf-8")


def asset_data_uri(*parts: str, mime_type: str) -> str:
    """Return an asset as a base64 ``data:`` URI, ready to embed in HTML.

    Args:
        *parts: The path components relative to the assets directory.
        mime_type: The media type of the asset, such as ``image/png``.
    """
    encoded = asset_base64(*parts)
    return f"data:{mime_type};base64,{encoded}"
