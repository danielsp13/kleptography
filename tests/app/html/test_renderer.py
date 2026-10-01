"""Tests for ``render_html``, the injection of raw HTML into a page.

They check that the HTML reaches ``st.html`` unchanged, that a non-empty
stylesheet is prepended in a style element, and that Streamlit errors
propagate. ``st.html`` is patched, so Streamlit never runs.
"""

from unittest.mock import patch

from kleptography.app.html.renderer import render_html


def test_render_html_without_css() -> None:
    """Without CSS the HTML is passed unchanged."""
    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        result = render_html("<p>Hello</p>")

    assert result is None
    mock_html.assert_called_once_with("<p>Hello</p>")


def test_render_html_with_css() -> None:
    """With CSS the HTML is preceded by a style element."""
    html = "<p>Hello</p>"
    css = ".example { color: red; }"

    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        result = render_html(html, css=css)

    assert result is None
    mock_html.assert_called_once_with(
        """
        <style>
        .example { color: red; }
        </style>

        <p>Hello</p>
        """
    )


def test_render_html_with_empty_css_does_not_wrap_html() -> None:
    """An empty stylesheet adds no style element."""
    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html("<p>Hello</p>", css="")

    mock_html.assert_called_once_with("<p>Hello</p>")


def test_render_html_with_none_css_does_not_wrap_html() -> None:
    """No stylesheet adds no style element."""
    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html("<p>Hello</p>", css=None)

    mock_html.assert_called_once_with("<p>Hello</p>")


def test_render_html_preserves_html_exactly_without_css() -> None:
    """The HTML is passed byte for byte."""
    html = "\n<div>\n  <strong>Content</strong>\n</div>\n"

    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html(html)

    mock_html.assert_called_once_with(html)


def test_render_html_wraps_css_and_preserves_html_exactly() -> None:
    """The stylesheet and the HTML are both kept unchanged."""
    html = "\n<div>\n  <strong>Content</strong>\n</div>\n"
    css = "\n.example {\n    color: red;\n}\n"

    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html(html, css=css)

    expected = f"""
        <style>
        {css}
        </style>

        {html}
        """

    mock_html.assert_called_once_with(expected)


def test_render_html_with_truthy_non_empty_css() -> None:
    """Any non-empty stylesheet, even blank, is wrapped."""
    html = "content"
    css = " "

    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html(html, css=css)

    mock_html.assert_called_once_with(
        """
        <style>
         
        </style>

        content
        """
    )


def test_render_html_calls_streamlit_html_exactly_once() -> None:
    """Streamlit is called once per render."""
    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html("content", css=".foo {}")

    assert mock_html.call_count == 1


def test_render_html_does_not_mutate_original_arguments() -> None:
    """The arguments are not modified."""
    html = "<p>Original</p>"
    css = ".foo { color: red; }"

    with patch("kleptography.app.html.renderer.st.html"):
        render_html(html, css=css)

    assert html == "<p>Original</p>"
    assert css == ".foo { color: red; }"


def test_render_html_propagates_streamlit_exception() -> None:
    """A Streamlit error propagates unchanged."""
    error = RuntimeError("Streamlit rendering failed")

    with patch(
        "kleptography.app.html.renderer.st.html",
        side_effect=error,
    ):
        try:
            render_html("<p>Hello</p>")
        except RuntimeError as exc:
            assert exc is error
        else:
            raise AssertionError("Expected RuntimeError to be propagated")


def test_render_html_with_css_propagates_streamlit_exception() -> None:
    """A Streamlit error propagates when CSS is given."""
    error = RuntimeError("Streamlit rendering failed")

    with patch(
        "kleptography.app.html.renderer.st.html",
        side_effect=error,
    ):
        try:
            render_html("<p>Hello</p>", css=".foo {}")
        except RuntimeError as exc:
            assert exc is error
        else:
            raise AssertionError("Expected RuntimeError to be propagated")
