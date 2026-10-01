"""Rendering of the Jinja2 HTML templates bundled with the application."""

from pathlib import Path

from jinja2 import Template

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def render_template(
    template_name: str,
    **context: object,
) -> str:
    """Render a Jinja2 template.

    Args:
        template_name: The file name inside ``html/templates``.
        **context: The variables available to the template.

    Returns:
        The rendered HTML.
    """
    template_path = _TEMPLATES_DIR / template_name

    template = Template(template_path.read_text(encoding="utf-8"))

    return template.render(**context)
