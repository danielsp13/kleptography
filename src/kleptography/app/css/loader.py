from pathlib import Path

_CSS_DIR = Path(__file__).resolve().parent / "styles"


def load_css(name: str) -> str:
    path = _CSS_DIR / name
    return path.read_text(encoding="utf-8")
