from pathlib import Path

from jinja2 import Template

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def render_template(
    template_name: str,
    **context: object,
) -> str:
    template_path = _TEMPLATES_DIR / template_name

    template = Template(template_path.read_text(encoding="utf-8"))

    return template.render(**context)
