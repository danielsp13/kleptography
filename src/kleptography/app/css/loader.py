"""Loading of the stylesheets bundled with the application."""

from pathlib import Path

_CSS_DIR = Path(__file__).resolve().parent / "styles"


def load_css(name: str) -> str:
    """Return the content of a stylesheet.

    Args:
        name: The file name inside ``css/styles``.
    """
    path = _CSS_DIR / name
    return path.read_text(encoding="utf-8")
