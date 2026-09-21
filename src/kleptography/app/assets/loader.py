import base64
from pathlib import Path

_ASSETS_DIR = Path(__file__).resolve().parent


def asset_path(*parts: str) -> Path:
    return _ASSETS_DIR.joinpath(*parts)


def asset_base64(*parts: str) -> str:
    path = asset_path(*parts)
    return base64.b64encode(path.read_bytes()).decode("utf-8")


def asset_data_uri(*parts: str, mime_type: str) -> str:
    encoded = asset_base64(*parts)
    return f"data:{mime_type};base64,{encoded}"
