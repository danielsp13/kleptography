"""Tests for the Jinja2 template loader.

They check that templates are read as UTF-8 from the templates directory,
rendered with their context (variables, conditionals, loops, HTML escaping),
and that read and syntax errors propagate.
"""

from pathlib import Path
from unittest.mock import patch

from kleptography.app.html.loader import render_template


def test_render_template_reads_template_with_utf8() -> None:
    """Templates are read as UTF-8 and rendered."""
    template_name = "page.html"

    with patch(
        "kleptography.app.html.loader._TEMPLATES_DIR",
        Path("/templates"),
    ):
        with patch(
            "kleptography.app.html.loader.Path.read_text",
            return_value="Hello, {{ name }}!",
        ) as mock_read_text:
            result = render_template(template_name, name="Alice")

    assert result == "Hello, Alice!"
    mock_read_text.assert_called_once_with(encoding="utf-8")


def test_render_template_resolves_template_path() -> None:
    """The template is read from the templates directory."""
    template_name = "index.html"

    with patch(
        "kleptography.app.html.loader._TEMPLATES_DIR",
        Path("/templates"),
    ):
        with patch(
            "kleptography.app.html.loader.Path.read_text",
            return_value="Content",
        ):
            render_template(template_name)

    expected_path = Path("/templates/index.html")

    assert expected_path.read_text != ""


def test_render_template_with_context() -> None:
    """Context variables are substituted."""
    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value=("<h1>{{ title }}</h1><p>{{ content }}</p>"),
    ):
        result = render_template(
            "page.html",
            title="My title",
            content="My content",
        )

    assert result == "<h1>My title</h1><p>My content</p>"


def test_render_template_with_multiple_context_values() -> None:
    """Several values of any type are substituted."""
    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value="{{ first }} {{ second }} {{ number }}",
    ):
        result = render_template(
            "page.html",
            first="Hello",
            second="world",
            number=42,
        )

    assert result == "Hello world 42"


def test_render_template_without_context() -> None:
    """A template without variables renders unchanged."""
    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value="Static content",
    ):
        result = render_template("page.html")

    assert result == "Static content"


def test_render_template_renders_jinja_conditionals() -> None:
    """Jinja2 conditionals are evaluated."""
    template = """
    {% if enabled %}
    Enabled
    {% else %}
    Disabled
    {% endif %}
    """

    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value=template,
    ):
        result = render_template("page.html", enabled=True)

    assert "Enabled" in result
    assert "Disabled" not in result


def test_render_template_renders_jinja_loops() -> None:
    """Jinja2 loops are evaluated."""
    template = "{% for item in items %}<li>{{ item }}</li>{% endfor %}"

    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value=template,
    ):
        result = render_template(
            "list.html",
            items=["one", "two", "three"],
        )

    assert result == "<li>one</li><li>two</li><li>three</li>"


def test_render_template_escapes_html_by_default() -> None:
    """HTML in values is escaped (autoescape is on)."""
    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value="{{ value }}",
    ):
        result = render_template(
            "page.html",
            value="<strong>Hello</strong>",
        )

    assert result == "&lt;strong&gt;Hello&lt;/strong&gt;"


def test_render_template_preserves_plain_text() -> None:
    """Plain text, newlines included, is kept as is."""
    content = "Hello\nWorld\n\nKleptography"

    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value=content,
    ):
        result = render_template("page.html")

    assert result == content


def test_render_template_with_empty_template() -> None:
    """An empty template renders an empty string."""
    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value="",
    ):
        result = render_template("empty.html")

    assert result == ""


def test_render_template_with_none_context_value() -> None:
    """None renders as "None"."""
    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value="{{ value }}",
    ):
        result = render_template("page.html", value=None)

    assert result == "None"


def test_render_template_propagates_file_read_error() -> None:
    """A missing template raises FileNotFoundError."""
    error = FileNotFoundError("template not found")

    with patch(
        "kleptography.app.html.loader.Path.read_text",
        side_effect=error,
    ):
        try:
            render_template("missing.html")
        except FileNotFoundError as exc:
            assert exc is error
        else:
            raise AssertionError("Expected FileNotFoundError")


def test_render_template_propagates_template_syntax_error() -> None:
    """Invalid Jinja2 syntax raises TemplateSyntaxError."""
    from jinja2 import TemplateSyntaxError

    with patch(
        "kleptography.app.html.loader.Path.read_text",
        return_value="{% invalid syntax",
    ):
        try:
            render_template("invalid.html")
        except TemplateSyntaxError:
            pass
        else:
            raise AssertionError("Expected TemplateSyntaxError")


def test_render_template_uses_template_name_relative_to_templates_dir() -> None:
    """Nested names are resolved inside the templates directory."""
    template_name = "nested/page.html"

    with patch(
        "kleptography.app.html.loader._TEMPLATES_DIR",
        Path("/project/templates"),
    ):
        with patch(
            "kleptography.app.html.loader.Path.read_text",
            return_value="Nested template",
        ) as mock_read_text:
            result = render_template(template_name)

    assert result == "Nested template"
    mock_read_text.assert_called_once_with(encoding="utf-8")


def test_templates_dir_is_path() -> None:
    """The templates directory is a Path named "templates"."""
    from kleptography.app.html import loader

    assert isinstance(loader._TEMPLATES_DIR, Path)
    assert loader._TEMPLATES_DIR.name == "templates"
