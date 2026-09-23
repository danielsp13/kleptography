from pathlib import Path
from unittest.mock import patch

from kleptography.app.css.loader import load_css


def test_load_css_reads_file_with_utf8() -> None:
    with patch(
        "kleptography.app.css.loader.Path.read_text",
        return_value=".example { color: red; }",
    ) as mock_read_text:
        result = load_css("main.css")

    assert result == ".example { color: red; }"
    mock_read_text.assert_called_once_with(encoding="utf-8")


def test_load_css_uses_css_directory() -> None:
    with patch(
        "kleptography.app.css.loader._CSS_DIR",
        Path("/project/styles"),
    ):
        with patch(
            "kleptography.app.css.loader.Path.read_text",
            return_value="body {}",
        ) as mock_read_text:
            result = load_css("main.css")

    assert result == "body {}"
    mock_read_text.assert_called_once_with(encoding="utf-8")


def test_load_css_with_nested_filename() -> None:
    with patch(
        "kleptography.app.css.loader._CSS_DIR",
        Path("/project/styles"),
    ):
        with patch(
            "kleptography.app.css.loader.Path.read_text",
            return_value=".nested {}",
        ) as mock_read_text:
            result = load_css("components/buttons.css")

    assert result == ".nested {}"
    mock_read_text.assert_called_once_with(encoding="utf-8")


def test_load_css_with_empty_file() -> None:
    with patch(
        "kleptography.app.css.loader.Path.read_text",
        return_value="",
    ):
        result = load_css("empty.css")

    assert result == ""


def test_load_css_preserves_file_contents_exactly() -> None:
    css = """
body {
    margin: 0;
    padding: 0;
}

.example {
    color: red;
}
"""

    with patch(
        "kleptography.app.css.loader.Path.read_text",
        return_value=css,
    ):
        result = load_css("main.css")

    assert result == css


def test_load_css_returns_unicode_contents() -> None:
    css = "/* Café — documentación */\nbody { font-family: 'Ñ'; }"

    with patch(
        "kleptography.app.css.loader.Path.read_text",
        return_value=css,
    ):
        result = load_css("unicode.css")

    assert result == css


def test_load_css_propagates_file_not_found_error() -> None:
    error = FileNotFoundError("CSS file not found")

    with patch(
        "kleptography.app.css.loader.Path.read_text",
        side_effect=error,
    ):
        try:
            load_css("missing.css")
        except FileNotFoundError as exc:
            assert exc is error
        else:
            raise AssertionError("Expected FileNotFoundError")


def test_load_css_propagates_permission_error() -> None:
    error = PermissionError("Permission denied")

    with patch(
        "kleptography.app.css.loader.Path.read_text",
        side_effect=error,
    ):
        try:
            load_css("protected.css")
        except PermissionError as exc:
            assert exc is error
        else:
            raise AssertionError("Expected PermissionError")


def test_load_css_with_empty_name() -> None:
    with patch(
        "kleptography.app.css.loader._CSS_DIR",
        Path("/project/styles"),
    ):
        with patch(
            "kleptography.app.css.loader.Path.read_text",
            return_value="default css",
        ) as mock_read_text:
            result = load_css("")

    assert result == "default css"
    mock_read_text.assert_called_once_with(encoding="utf-8")


def test_load_css_with_name_containing_spaces() -> None:
    with patch(
        "kleptography.app.css.loader._CSS_DIR",
        Path("/project/styles"),
    ):
        with patch(
            "kleptography.app.css.loader.Path.read_text",
            return_value="body {}",
        ) as mock_read_text:
            result = load_css("my styles.css")

    assert result == "body {}"
    mock_read_text.assert_called_once_with(encoding="utf-8")


def test_css_dir_is_path() -> None:
    from kleptography.app.css import loader

    assert isinstance(loader._CSS_DIR, Path)
    assert loader._CSS_DIR.name == "styles"


def test_load_css_calls_read_text_exactly_once() -> None:
    with patch(
        "kleptography.app.css.loader.Path.read_text",
        return_value="body {}",
    ) as mock_read_text:
        load_css("main.css")

    assert mock_read_text.call_count == 1
