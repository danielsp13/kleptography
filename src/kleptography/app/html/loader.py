"""Rendering of the Jinja2 HTML templates bundled with the application."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def render_template(
    template_name: str,
    **context: object,
) -> str:
    """Render a Jinja2 template.

    Context values are HTML-escaped (autoescape is on), so they must be plain
    text, never markup.

    Args:
        template_name: The file name inside ``html/templates``.
        **context: The variables available to the template.

    Returns:
        The rendered HTML.
    """
    template_path = _TEMPLATES_DIR / template_name

    # Context values are plain text: escaping keeps any markup in them inert.
    template = Template(template_path.read_text(encoding="utf-8"), autoescape=True)

    return template.render(**context)
