"""Tests for ``CalloutComposer``, the HTML callout boxes.

They check the supported types and their validation, the exact HTML of
every callout, the factory constructors with their default titles, the
immutability of the dataclass and the shared stylesheet.
"""

import pytest

from kleptography.app.content.callouts import CalloutComposer


def test_types_contains_all_supported_callout_types():
    """The six callout types are supported."""
    assert CalloutComposer.TYPES == {
        "note",
        "tip",
        "warning",
        "danger",
        "info",
        "success",
    }


@pytest.mark.parametrize(
    "callout_type",
    sorted(CalloutComposer.TYPES),
)
def test_valid_callout_types_are_accepted(callout_type):
    """Every supported type builds a callout with its fields."""
    callout = CalloutComposer(callout_type, "Title", "Content")

    assert callout.type == callout_type
    assert callout.title == "Title"
    assert callout.content == "Content"


def test_invalid_callout_type_raises_value_error():
    """An unknown type raises ValueError listing the valid ones."""
    with pytest.raises(
        ValueError,
        match=(
            r"Unknown callout type: 'invalid'\. Expected one of: "
            r"danger, info, note, success, tip, warning"
        ),
    ):
        CalloutComposer("invalid", "Title", "Content")


def test_invalid_callout_type_error_message_uses_repr():
    """The error message shows the repr of the invalid type."""
    with pytest.raises(
        ValueError,
        match=(
            r"Unknown callout type: None\. Expected one of: "
            r"danger, info, note, success, tip, warning"
        ),
    ):
        CalloutComposer(None, "Title", "Content")  # ty: ignore[invalid-argument-type]


def test_build_returns_expected_html():
    """A callout builds the expected HTML."""
    callout = CalloutComposer("note", "My title", "My content")

    assert callout.build() == (
        '<div class="callout callout-note">'
        '<div class="callout-title">My title</div>'
        '<div class="callout-content">My content</div>'
        "</div>"
    )


@pytest.mark.parametrize(
    "callout_type",
    sorted(CalloutComposer.TYPES),
)
def test_build_uses_callout_type_in_css_class(callout_type):
    """The type selects the CSS class of the callout."""
    callout = CalloutComposer(callout_type, "Title", "Content")

    assert callout.build() == (
        f'<div class="callout callout-{callout_type}">'
        '<div class="callout-title">Title</div>'
        '<div class="callout-content">Content</div>'
        "</div>"
    )


def test_build_preserves_title_and_content_verbatim():
    """Title and content are inserted as raw HTML."""
    callout = CalloutComposer(
        "info",
        "<strong>Custom title</strong>",
        "<p>Custom content</p>",
    )

    assert callout.build() == (
        '<div class="callout callout-info">'
        '<div class="callout-title"><strong>Custom title</strong></div>'
        '<div class="callout-content"><p>Custom content</p></div>'
        "</div>"
    )


@pytest.mark.parametrize(
    ("factory", "expected_type", "default_title"),
    [
        (CalloutComposer.note, "note", "Note"),
        (CalloutComposer.tip, "tip", "Tip"),
        (CalloutComposer.warning, "warning", "Warning"),
        (CalloutComposer.danger, "danger", "Danger"),
        (CalloutComposer.info, "info", "Info"),
        (CalloutComposer.success, "success", "Success"),
    ],
)
def test_factory_methods_use_default_titles(
    factory,
    expected_type,
    default_title,
):
    """Each factory uses its type and default title."""
    callout = factory("Content")

    assert callout == CalloutComposer(
        expected_type,
        default_title,
        "Content",
    )


@pytest.mark.parametrize(
    ("factory", "expected_type"),
    [
        (CalloutComposer.note, "note"),
        (CalloutComposer.tip, "tip"),
        (CalloutComposer.warning, "warning"),
        (CalloutComposer.danger, "danger"),
        (CalloutComposer.info, "info"),
        (CalloutComposer.success, "success"),
    ],
)
def test_factory_methods_accept_custom_titles(factory, expected_type):
    """Each factory accepts a custom title."""
    callout = factory("Content", title="Custom title")

    assert callout.type == expected_type
    assert callout.title == "Custom title"
    assert callout.content == "Content"


def test_note_factory_builds_expected_html():
    """A note callout builds the expected HTML."""
    assert CalloutComposer.note("Body").build() == (
        '<div class="callout callout-note">'
        '<div class="callout-title">Note</div>'
        '<div class="callout-content">Body</div>'
        "</div>"
    )


def test_tip_factory_builds_expected_html():
    """A tip callout builds the expected HTML."""
    assert CalloutComposer.tip("Body").build() == (
        '<div class="callout callout-tip">'
        '<div class="callout-title">Tip</div>'
        '<div class="callout-content">Body</div>'
        "</div>"
    )


def test_warning_factory_builds_expected_html():
    """A warning callout builds the expected HTML."""
    assert CalloutComposer.warning("Body").build() == (
        '<div class="callout callout-warning">'
        '<div class="callout-title">Warning</div>'
        '<div class="callout-content">Body</div>'
        "</div>"
    )


def test_danger_factory_builds_expected_html():
    """A danger callout builds the expected HTML."""
    assert CalloutComposer.danger("Body").build() == (
        '<div class="callout callout-danger">'
        '<div class="callout-title">Danger</div>'
        '<div class="callout-content">Body</div>'
        "</div>"
    )


def test_info_factory_builds_expected_html():
    """An info callout builds the expected HTML."""
    assert CalloutComposer.info("Body").build() == (
        '<div class="callout callout-info">'
        '<div class="callout-title">Info</div>'
        '<div class="callout-content">Body</div>'
        "</div>"
    )


def test_success_factory_builds_expected_html():
    """A success callout builds the expected HTML."""
    assert CalloutComposer.success("Body").build() == (
        '<div class="callout callout-success">'
        '<div class="callout-title">Success</div>'
        '<div class="callout-content">Body</div>'
        "</div>"
    )


def test_dataclass_is_frozen():
    """A callout cannot be modified."""
    callout = CalloutComposer("note", "Title", "Content")

    with pytest.raises(AttributeError):
        callout.title = "Changed"  # ty: ignore[invalid-assignment]


def test_dataclass_equality():
    """Callouts with the same fields are equal."""
    first = CalloutComposer("info", "Title", "Content")
    second = CalloutComposer("info", "Title", "Content")

    assert first == second


def test_dataclass_inequality_when_fields_differ():
    """Callouts with different fields are not equal."""
    first = CalloutComposer("info", "Title", "Content")
    second = CalloutComposer("info", "Other title", "Content")

    assert first != second


def test_css_returns_expected_stylesheet():
    """The stylesheet is a style element with the base rules."""
    css = CalloutComposer.css()

    assert css.startswith("\n        <style>")
    assert css.endswith("        </style>\n        ")

    assert ".callout {" in css
    assert "padding: 1rem 1.1rem;" in css
    assert "margin: 1rem 0;" in css
    assert "border-left: 5px solid;" in css
    assert "border-radius: 0.5rem;" in css
    assert "background: rgba(127, 127, 127, 0.08);" in css

    assert ".callout-title {" in css
    assert "font-weight: 700;" in css
    assert "margin-bottom: 0.5rem;" in css

    assert ".callout-content {" in css
    assert "line-height: 1.5;" in css

    assert ".callout-content p:last-child {" in css
    assert "margin-bottom: 0;" in css


@pytest.mark.parametrize(
    "callout_type",
    sorted(CalloutComposer.TYPES),
)
def test_css_contains_styles_for_every_callout_type(callout_type):
    """The stylesheet styles every callout type and its title."""
    css = CalloutComposer.css()

    assert f".callout-{callout_type}" in css
    assert f".callout-{callout_type} .callout-title" in css


def test_css_contains_note_styles():
    """The stylesheet has the note colors."""
    css = CalloutComposer.css()

    assert "border-color: #6b7280;" in css
    assert "background: rgba(107, 114, 128, 0.10);" in css
    assert "color: #4b5563;" in css


def test_css_contains_tip_styles():
    """The stylesheet has the tip colors."""
    css = CalloutComposer.css()

    assert "border-color: #10b981;" in css
    assert "background: rgba(16, 185, 129, 0.10);" in css
    assert "color: #059669;" in css


def test_css_contains_warning_styles():
    """The stylesheet has the warning colors."""
    css = CalloutComposer.css()

    assert "border-color: #f59e0b;" in css
    assert "background: rgba(245, 158, 11, 0.10);" in css
    assert "color: #d97706;" in css


def test_css_contains_danger_styles():
    """The stylesheet has the danger colors."""
    css = CalloutComposer.css()

    assert "border-color: #ef4444;" in css
    assert "background: rgba(239, 68, 68, 0.10);" in css
    assert "color: #dc2626;" in css


def test_css_contains_info_styles():
    """The stylesheet has the info colors."""
    css = CalloutComposer.css()

    assert "border-color: #3b82f6;" in css
    assert "background: rgba(59, 130, 246, 0.10);" in css
    assert "color: #2563eb;" in css


def test_css_contains_success_styles():
    """The stylesheet has the success colors."""
    css = CalloutComposer.css()

    assert "border-color: #22c55e;" in css
    assert "background: rgba(34, 197, 94, 0.10);" in css
    assert "color: #16a34a;" in css


def test_css_is_staticmethod_and_can_be_called_on_class():
    """The stylesheet is available without an instance."""
    assert isinstance(
        CalloutComposer.__dict__["css"],
        staticmethod,
    )
    assert CalloutComposer.css() == CalloutComposer("note", "", "").css()


def test_empty_title_and_content_are_supported():
    """A callout can have an empty title and content."""
    callout = CalloutComposer("note", "", "")

    assert callout.build() == (
        '<div class="callout callout-note">'
        '<div class="callout-title"></div>'
        '<div class="callout-content"></div>'
        "</div>"
    )
