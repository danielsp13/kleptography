"""Tests for ``ContentComposer``, the fluent Markdown builder.

They check the exact Markdown of every block and inline helper, that block
methods return the composer for chaining, and that blocks are joined with
blank lines in insertion order.
"""

import pytest

from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.composer import ContentComposer


def test_empty_composer() -> None:
    """A new composer builds an empty string."""
    composer = ContentComposer()

    assert composer.build() == ""


@pytest.mark.parametrize(
    ("method", "text", "expected"),
    [
        ("h1", "Title", "# Title"),
        ("h2", "Section", "## Section"),
        ("h3", "Subsection", "### Subsection"),
    ],
)
def test_headings(method: str, text: str, expected: str) -> None:
    """Each heading method appends a heading of its level."""
    composer = ContentComposer()

    result = getattr(composer, method)(text)

    assert result is composer
    assert composer.build() == expected


def test_paragraph() -> None:
    """A paragraph is appended as given."""
    composer = ContentComposer()

    result = composer.paragraph("A paragraph.")

    assert result is composer
    assert composer.build() == "A paragraph."


def test_paragraph_with_multiple_parts() -> None:
    """The parts of a paragraph are joined without separator."""
    composer = ContentComposer()

    result = composer.paragraph("Hello, ", "world", "!")

    assert result is composer
    assert composer.build() == "Hello, world!"


def test_paragraph_with_no_parts() -> None:
    """A paragraph without parts is empty."""
    composer = ContentComposer()

    result = composer.paragraph()

    assert result is composer
    assert composer.build() == ""


def test_divider() -> None:
    """A divider is a horizontal rule."""
    composer = ContentComposer()

    result = composer.divider()

    assert result is composer
    assert composer.build() == "---"


def test_bullet_list() -> None:
    """Each item becomes a "- " line."""
    composer = ContentComposer()

    result = composer.bullet_list(
        [
            "First item",
            "Second item",
            "Third item",
        ]
    )

    assert result is composer
    assert composer.build() == ("- First item\n- Second item\n- Third item")


def test_empty_bullet_list() -> None:
    """An empty bullet list builds nothing."""
    composer = ContentComposer()

    result = composer.bullet_list([])

    assert result is composer
    assert composer.build() == ""


def test_bullet_list_with_empty_items() -> None:
    """Empty items are kept as empty bullets."""
    composer = ContentComposer()

    composer.bullet_list(["", "Item", ""])

    assert composer.build() == "- \n- Item\n- "


def test_ordered_list() -> None:
    """Each item becomes a numbered line."""
    composer = ContentComposer()

    result = composer.ordered_list(
        [
            "First item",
            "Second item",
            "Third item",
        ]
    )

    assert result is composer
    assert composer.build() == ("1. First item\n2. Second item\n3. Third item")


def test_empty_ordered_list() -> None:
    """An empty ordered list builds nothing."""
    composer = ContentComposer()

    result = composer.ordered_list([])

    assert result is composer
    assert composer.build() == ""


def test_ordered_list_numbers_items_from_one() -> None:
    """Numbering starts at 1 and follows the items."""
    composer = ContentComposer()

    composer.ordered_list(["A", "B", "C", "D"])

    assert composer.build() == ("1. A\n2. B\n3. C\n4. D")


def test_quote() -> None:
    """A quote is prefixed with "> "."""
    composer = ContentComposer()

    result = composer.quote("A quoted sentence.")

    assert result is composer
    assert composer.build() == "> A quoted sentence."


def test_quote_with_multiple_parts() -> None:
    """The parts of a quote are joined without separator."""
    composer = ContentComposer()

    result = composer.quote("Hello, ", "world", "!")

    assert result is composer
    assert composer.build() == "> Hello, world!"


def test_quote_with_no_parts() -> None:
    """A quote without parts is just the prefix."""
    composer = ContentComposer()

    result = composer.quote()

    assert result is composer
    assert composer.build() == "> "


def test_image() -> None:
    """An image uses the Markdown image syntax with its alternative text."""
    composer = ContentComposer()

    result = composer.image(
        "docs/images/kleptofox.png",
        alt="Kleptography mascot",
    )

    assert result is composer
    assert composer.build() == ("![Kleptography mascot](docs/images/kleptofox.png)")


def test_image_without_alt_text() -> None:
    """The alternative text defaults to empty."""
    composer = ContentComposer()

    result = composer.image("docs/images/kleptofox.png")

    assert result is composer
    assert composer.build() == "![](docs/images/kleptofox.png)"


def test_image_with_empty_alt_text() -> None:
    """An explicit empty alternative text is allowed."""
    composer = ContentComposer()

    composer.image("image.png", alt="")

    assert composer.build() == "![](image.png)"


def test_block_with_string() -> None:
    """A string block is appended verbatim."""
    composer = ContentComposer()

    result = composer.block("Some Markdown content.")

    assert result is composer
    assert composer.build() == "Some Markdown content."


def test_block_with_callout_composer() -> None:
    """A callout block is appended as its built HTML."""
    composer = ContentComposer()
    callout = CalloutComposer.note("Some note.")

    result = composer.block(callout)

    assert result is composer
    assert composer.build() == callout.build()


def test_block_with_callout_uses_build_result() -> None:
    """A callout block keeps its custom title."""
    composer = ContentComposer()
    callout = CalloutComposer.warning(
        "Warning content",
        title="Custom warning",
    )

    composer.block(callout)

    assert composer.build() == (
        '<div class="callout callout-warning">'
        '<div class="callout-title">Custom warning</div>'
        '<div class="callout-content">Warning content</div>'
        "</div>"
    )


def test_formula() -> None:
    """A formula is wrapped in display delimiters."""
    composer = ContentComposer()

    result = composer.formula(r"A = g^{a} \bmod p")

    assert result is composer
    assert composer.build() == "$$\nA = g^{a} \\bmod p\n$$"


def test_formula_preserves_multiline_latex() -> None:
    """A formula keeps its LaTeX unchanged."""
    composer = ContentComposer()
    latex = r"\begin{aligned}a &= b \\ c &= d\end{aligned}"

    composer.formula(latex)

    assert composer.build() == f"$$\n{latex}\n$$"


@pytest.mark.parametrize(
    ("method", "text", "expected"),
    [
        ("bold", "important", "**important**"),
        ("italic", "emphasis", "*emphasis*"),
        ("code", "mod_pow", "`mod_pow`"),
        ("math", "g^{a}", "$g^{a}$"),
    ],
)
def test_inline_formatting(method: str, text: str, expected: str) -> None:
    """Each inline helper wraps the text in its Markdown markers."""
    composer = ContentComposer()

    result = getattr(composer, method)(text)

    assert result == expected


@pytest.mark.parametrize(
    ("method", "text"),
    [
        ("bold", ""),
        ("italic", ""),
        ("code", ""),
        ("math", ""),
    ],
)
def test_inline_formatting_with_empty_text(method: str, text: str) -> None:
    """Inline helpers accept empty text."""
    assert getattr(ContentComposer, method)(text) in {"****", "**", "``", "$$"}


def test_inline_formatting_with_special_characters() -> None:
    """Inline helpers do not escape special characters."""
    assert ContentComposer.bold("a * b") == "**a * b**"
    assert ContentComposer.italic("a * b") == "*a * b*"
    assert ContentComposer.code("a ` b") == "`a ` b`"
    assert ContentComposer.math(r"\frac{a}{b}") == r"$\frac{a}{b}$"


def test_inline_formatting_does_not_modify_composer() -> None:
    """Inline helpers return text without appending blocks."""
    composer = ContentComposer()

    bold = composer.bold("important")
    italic = composer.italic("educational")
    code = composer.code("mod_pow")
    math = composer.math("g^{a}")

    assert composer.build() == ""
    assert bold == "**important**"
    assert italic == "*educational*"
    assert code == "`mod_pow`"
    assert math == "$g^{a}$"


def test_blocks_are_separated_by_blank_lines() -> None:
    """Blocks are joined with blank lines."""
    composer = ContentComposer()

    composer.h1("Title")
    composer.paragraph("Text.")
    composer.h2("Section")
    composer.h3("Subsection")

    assert composer.build() == ("# Title\n\nText.\n\n## Section\n\n### Subsection")


def test_fluent_block_composition() -> None:
    """Block methods can be chained."""
    composer = (
        ContentComposer().h1("Title").h2("Section").h3("Subsection").paragraph("Text.")
    )

    assert composer.build() == ("# Title\n\n## Section\n\n### Subsection\n\nText.")


def test_inline_formatting_can_be_composed() -> None:
    """Inline helpers can build the parts of a paragraph."""
    composer = ContentComposer()

    composer.paragraph(
        "This is ",
        composer.bold("important"),
        " and ",
        composer.italic("educational"),
        ", with ",
        composer.math("A = g^{a}"),
        ".",
    )

    assert composer.build() == (
        "This is **important** and *educational*, with $A = g^{a}$."
    )


def test_all_block_operations_can_be_composed() -> None:
    """Every block method can be chained in one expression."""
    composer = (
        ContentComposer()
        .h1("Title")
        .paragraph("Introduction.")
        .divider()
        .bullet_list(["One", "Two"])
        .ordered_list(["First", "Second"])
        .quote("A quote.")
        .image("image.png", alt="An image")
        .formula("p = 2q + 1")
    )

    assert composer.build() == (
        "# Title\n\n"
        "Introduction.\n\n"
        "---\n\n"
        "- One\n"
        "- Two\n\n"
        "1. First\n"
        "2. Second\n\n"
        "> A quote.\n\n"
        "![An image](image.png)\n\n"
        "$$\np = 2q + 1\n$$"
    )


def test_multiple_blocks_are_kept_in_insertion_order() -> None:
    """Blocks are built in the order they were added."""
    composer = ContentComposer()

    composer.block("first")
    composer.block("second")
    composer.block("third")

    assert composer.build() == "first\n\nsecond\n\nthird"


def test_build_does_not_clear_blocks() -> None:
    """Building twice gives the same result."""
    composer = ContentComposer()

    composer.h1("Title")

    first = composer.build()
    second = composer.build()

    assert first == "# Title"
    assert second == "# Title"


def test_build_reflects_blocks_added_after_previous_build() -> None:
    """Blocks added after a build appear in the next one."""
    composer = ContentComposer()

    composer.h1("Title")
    assert composer.build() == "# Title"

    composer.paragraph("Text.")

    assert composer.build() == "# Title\n\nText."


def test_empty_string_block_is_preserved() -> None:
    """An empty block still counts as a block."""
    composer = ContentComposer()

    composer.block("")
    composer.block("content")

    assert composer.build() == "\n\ncontent"


def test_content_composer_initializes_empty_blocks() -> None:
    """A new composer has no blocks."""
    composer = ContentComposer()

    assert composer._blocks == []
