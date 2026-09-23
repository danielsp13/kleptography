import base64
from pathlib import Path
from unittest.mock import patch

from kleptography.app.assets.loader import asset_base64, asset_data_uri, asset_path


def test_asset_path_returns_path_relative_to_loader_module() -> None:
    with patch(
        "kleptography.app.assets.loader._ASSETS_DIR",
        Path("/assets"),
    ):
        result = asset_path("images", "logo.png")

    assert result == Path("/assets/images/logo.png")


def test_asset_path_with_single_part() -> None:
    with patch(
        "kleptography.app.assets.loader._ASSETS_DIR",
        Path("/assets"),
    ):
        result = asset_path("logo.png")

    assert result == Path("/assets/logo.png")


def test_asset_path_with_multiple_parts() -> None:
    with patch(
        "kleptography.app.assets.loader._ASSETS_DIR",
        Path("/assets"),
    ):
        result = asset_path("images", "icons", "logo.svg")

    assert result == Path("/assets/images/icons/logo.svg")


def test_asset_path_with_no_parts() -> None:
    with patch(
        "kleptography.app.assets.loader._ASSETS_DIR",
        Path("/assets"),
    ):
        result = asset_path()

    assert result == Path("/assets")


def test_asset_base64_encodes_file_contents() -> None:
    file_content = b"hello world"

    with patch(
        "kleptography.app.assets.loader.asset_path",
        return_value=Path("/assets/file.txt"),
    ) as mock_asset_path:
        with patch(
            "kleptography.app.assets.loader.Path.read_bytes",
            return_value=file_content,
        ) as mock_read_bytes:
            result = asset_base64("file.txt")

    assert result == base64.b64encode(file_content).decode("utf-8")
    mock_asset_path.assert_called_once_with("file.txt")
    mock_read_bytes.assert_called_once_with()


def test_asset_base64_encodes_binary_contents() -> None:
    file_content = bytes(range(256))

    with patch(
        "kleptography.app.assets.loader.asset_path",
        return_value=Path("/assets/image.png"),
    ):
        with patch(
            "kleptography.app.assets.loader.Path.read_bytes",
            return_value=file_content,
        ):
            result = asset_base64("image.png")

    assert result == base64.b64encode(file_content).decode("utf-8")


def test_asset_base64_with_multiple_path_parts() -> None:
    file_content = b"asset content"

    with patch(
        "kleptography.app.assets.loader.asset_path",
        return_value=Path("/assets/images/logo.svg"),
    ) as mock_asset_path:
        with patch(
            "kleptography.app.assets.loader.Path.read_bytes",
            return_value=file_content,
        ):
            result = asset_base64("images", "logo.svg")

    assert result == base64.b64encode(file_content).decode("utf-8")
    mock_asset_path.assert_called_once_with("images", "logo.svg")


def test_asset_base64_reads_bytes_from_resolved_path() -> None:
    path = Path("/assets/test.bin")

    with patch(
        "kleptography.app.assets.loader.asset_path",
        return_value=path,
    ):
        with patch.object(
            Path,
            "read_bytes",
            return_value=b"test",
        ) as mock_read_bytes:
            asset_base64("test.bin")

    mock_read_bytes.assert_called_once_with()


def test_asset_base64_propagates_file_read_error() -> None:
    error = FileNotFoundError("asset not found")

    with patch(
        "kleptography.app.assets.loader.asset_path",
        return_value=Path("/assets/missing.png"),
    ):
        with patch(
            "kleptography.app.assets.loader.Path.read_bytes",
            side_effect=error,
        ):
            try:
                asset_base64("missing.png")
            except FileNotFoundError as exc:
                assert exc is error
            else:
                raise AssertionError("Expected FileNotFoundError")


def test_asset_data_uri_builds_expected_uri() -> None:
    encoded = "aGVsbG8="

    with patch(
        "kleptography.app.assets.loader.asset_base64",
        return_value=encoded,
    ) as mock_asset_base64:
        result = asset_data_uri("hello.txt", mime_type="text/plain")

    assert result == "data:text/plain;base64,aGVsbG8="
    mock_asset_base64.assert_called_once_with("hello.txt")


def test_asset_data_uri_with_multiple_path_parts() -> None:
    encoded = "iVBORw0KGgo="

    with patch(
        "kleptography.app.assets.loader.asset_base64",
        return_value=encoded,
    ) as mock_asset_base64:
        result = asset_data_uri(
            "images",
            "logo.png",
            mime_type="image/png",
        )

    assert result == "data:image/png;base64,iVBORw0KGgo="
    mock_asset_base64.assert_called_once_with("images", "logo.png")


def test_asset_data_uri_supports_different_mime_types() -> None:
    with patch(
        "kleptography.app.assets.loader.asset_base64",
        return_value="YWJj",
    ):
        assert (
            asset_data_uri("file", mime_type="application/octet-stream")
            == "data:application/octet-stream;base64,YWJj"
        )


def test_asset_data_uri_with_empty_encoded_content() -> None:
    with patch(
        "kleptography.app.assets.loader.asset_base64",
        return_value="",
    ):
        result = asset_data_uri("empty.txt", mime_type="text/plain")

    assert result == "data:text/plain;base64,"


def test_asset_data_uri_propagates_asset_base64_error() -> None:
    error = RuntimeError("encoding failed")

    with patch(
        "kleptography.app.assets.loader.asset_base64",
        side_effect=error,
    ) as mock_asset_base64:
        try:
            asset_data_uri("file.txt", mime_type="text/plain")
        except RuntimeError as exc:
            assert exc is error
        else:
            raise AssertionError("Expected RuntimeError")

    mock_asset_base64.assert_called_once_with("file.txt")


def test_asset_base64_matches_real_base64_encoding() -> None:
    content = "Kleptography 🦊".encode("utf-8")

    with patch(
        "kleptography.app.assets.loader.asset_path",
        return_value=Path("/assets/fox.txt"),
    ):
        with patch(
            "kleptography.app.assets.loader.Path.read_bytes",
            return_value=content,
        ):
            result = asset_base64("fox.txt")

    assert result == base64.b64encode(content).decode("utf-8")


def test_asset_data_uri_uses_base64_result_without_modification() -> None:
    encoded = "ABC+/=123"

    with patch(
        "kleptography.app.assets.loader.asset_base64",
        return_value=encoded,
    ):
        result = asset_data_uri(
            "asset.bin",
            mime_type="application/custom",
        )

    assert result == "data:application/custom;base64,ABC+/=123"
