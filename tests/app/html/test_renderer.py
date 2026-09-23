from unittest.mock import patch

from kleptography.app.html.renderer import render_html


def test_render_html_without_css() -> None:
    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        result = render_html("<p>Hello</p>")

    assert result is None
    mock_html.assert_called_once_with("<p>Hello</p>")


def test_render_html_with_css() -> None:
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
    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html("<p>Hello</p>", css="")

    mock_html.assert_called_once_with("<p>Hello</p>")


def test_render_html_with_none_css_does_not_wrap_html() -> None:
    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html("<p>Hello</p>", css=None)

    mock_html.assert_called_once_with("<p>Hello</p>")


def test_render_html_preserves_html_exactly_without_css() -> None:
    html = "\n<div>\n  <strong>Content</strong>\n</div>\n"

    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html(html)

    mock_html.assert_called_once_with(html)


def test_render_html_wraps_css_and_preserves_html_exactly() -> None:
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
    with patch("kleptography.app.html.renderer.st.html") as mock_html:
        render_html("content", css=".foo {}")

    assert mock_html.call_count == 1


def test_render_html_does_not_mutate_original_arguments() -> None:
    html = "<p>Original</p>"
    css = ".foo { color: red; }"

    with patch("kleptography.app.html.renderer.st.html"):
        render_html(html, css=css)

    assert html == "<p>Original</p>"
    assert css == ".foo { color: red; }"


def test_render_html_propagates_streamlit_exception() -> None:
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
