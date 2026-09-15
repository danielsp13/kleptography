from kleptography.app.content.composer import ContentComposer


def test_empty_composer() -> None:
    composer = ContentComposer()

    assert composer.build() == ""


def test_h1() -> None:
    composer = ContentComposer()

    composer.h1("Title")

    assert composer.build() == "# Title"


def test_h2() -> None:
    composer = ContentComposer()

    composer.h2("Section")

    assert composer.build() == "## Section"


def test_h3() -> None:
    composer = ContentComposer()

    composer.h3("Subsection")

    assert composer.build() == "### Subsection"


def test_paragraph() -> None:
    composer = ContentComposer()

    composer.paragraph("A paragraph.")

    assert composer.build() == "A paragraph."


def test_paragraph_with_multiple_parts() -> None:
    composer = ContentComposer()

    composer.paragraph("Hello, ", "world", "!")

    assert composer.build() == "Hello, world!"


def test_bold() -> None:
    assert ContentComposer.bold("important") == "**important**"


def test_italic() -> None:
    assert ContentComposer.italic("emphasis") == "*emphasis*"


def test_code() -> None:
    assert ContentComposer.code("mod_pow") == "`mod_pow`"


def test_blocks_are_separated_by_blank_lines() -> None:
    composer = ContentComposer()

    composer.h1("Title")
    composer.paragraph("Text.")
    composer.h2("Section")
    composer.h3("Subsection")

    assert composer.build() == ("# Title\n\nText.\n\n## Section\n\n### Subsection")


def test_fluent_block_composition() -> None:
    composer = (
        ContentComposer().h1("Title").h2("Section").h3("Subsection").paragraph("Text.")
    )

    assert composer.build() == ("# Title\n\n## Section\n\n### Subsection\n\nText.")


def test_inline_formatting_can_be_composed() -> None:
    composer = ContentComposer()

    composer.paragraph(
        "This is ",
        composer.bold("important"),
        " and ",
        composer.italic("educational"),
        ".",
    )

    assert composer.build() == ("This is **important** and *educational*.")


def test_inline_formatting_does_not_modify_composer() -> None:
    composer = ContentComposer()

    bold = composer.bold("important")
    italic = composer.italic("educational")
    code = composer.code("mod_pow")

    assert composer.build() == ""
    assert bold == "**important**"
    assert italic == "*educational*"
    assert code == "`mod_pow`"


def test_divider() -> None:
    composer = ContentComposer()

    composer.divider()

    assert composer.build() == "---"


def test_bullet_list() -> None:
    composer = ContentComposer()

    composer.bullet_list(
        [
            "First item",
            "Second item",
            "Third item",
        ]
    )

    assert composer.build() == ("- First item\n- Second item\n- Third item")


def test_ordered_list() -> None:
    composer = ContentComposer()

    composer.ordered_list(
        [
            "First item",
            "Second item",
            "Third item",
        ]
    )

    assert composer.build() == ("1. First item\n2. Second item\n3. Third item")


def test_empty_bullet_list() -> None:
    composer = ContentComposer()

    composer.bullet_list([])

    assert composer.build() == ""


def test_empty_ordered_list() -> None:
    composer = ContentComposer()

    composer.ordered_list([])

    assert composer.build() == ""


def test_quote() -> None:
    composer = ContentComposer()

    composer.quote("A quoted sentence.")

    assert composer.build() == "> A quoted sentence."


def test_quote_with_inline_formatting() -> None:
    composer = ContentComposer()

    composer.quote(
        "This is ",
        composer.bold("important"),
        ".",
    )

    assert composer.build() == "> This is **important**."


def test_image() -> None:
    composer = ContentComposer()

    composer.image(
        "docs/images/kleptofox.png",
        alt="Kleptography mascot",
    )

    assert composer.build() == ("![Kleptography mascot](docs/images/kleptofox.png)")


def test_image_without_alt_text() -> None:
    composer = ContentComposer()

    composer.image("docs/images/kleptofox.png")

    assert composer.build() == "![](docs/images/kleptofox.png)"


def test_all_block_operations_can_be_composed() -> None:
    composer = (
        ContentComposer()
        .h1("Title")
        .paragraph("Introduction.")
        .divider()
        .bullet_list(["One", "Two"])
        .ordered_list(["First", "Second"])
        .quote("A quote.")
        .image("image.png", alt="An image")
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
        "![An image](image.png)"
    )
