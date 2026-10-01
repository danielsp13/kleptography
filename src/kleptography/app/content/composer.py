"""A fluent builder for the Markdown of the educational content."""

from __future__ import annotations

from kleptography.app.content.callouts import CalloutComposer


class ContentComposer:
    """Compose educational content as Markdown.

    Block methods append a block and return the composer, so calls can be
    chained. The static helpers format inline text. ``build()`` joins the
    blocks with blank lines.
    """

    def __init__(self) -> None:
        """Start with no blocks."""
        self._blocks: list[str] = []

    def h1(self, text: str) -> ContentComposer:
        """Append a level-1 heading.

        Args:
            text: The heading text.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append(f"# {text}")
        return self

    def h2(self, text: str) -> ContentComposer:
        """Append a level-2 heading.

        Args:
            text: The heading text.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append(f"## {text}")
        return self

    def h3(self, text: str) -> ContentComposer:
        """Append a level-3 heading.

        Args:
            text: The heading text.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append(f"### {text}")
        return self

    def paragraph(self, *parts: str) -> ContentComposer:
        """Append a paragraph made of the concatenated parts.

        Args:
            *parts: The pieces of text, joined without separator.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append("".join(parts))
        return self

    def divider(self) -> ContentComposer:
        """Append a horizontal rule.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append("---")
        return self

    def bullet_list(self, items: list[str]) -> ContentComposer:
        """Append an unordered list.

        Args:
            items: The Markdown of each item.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append("\n".join(f"- {item}" for item in items))
        return self

    def ordered_list(self, items: list[str]) -> ContentComposer:
        """Append a numbered list.

        Args:
            items: The Markdown of each item.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append(
            "\n".join(f"{index}. {item}" for index, item in enumerate(items, start=1))
        )
        return self

    def quote(self, *parts: str) -> ContentComposer:
        """Append a block quote made of the concatenated parts.

        Args:
            *parts: The pieces of text, joined without separator.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append(f"> {''.join(parts)}")
        return self

    def image(self, src: str, alt: str = "") -> ContentComposer:
        """Append an image with its alternative text.

        Args:
            src: The URL or path of the image.
            alt: The alternative text.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append(f"![{alt}]({src})")
        return self

    def formula(self, latex: str) -> ContentComposer:
        """Append a display LaTeX formula (``$$...$$``).

        Args:
            latex: The LaTeX formula, without delimiters.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append(f"$$\n{latex}\n$$")
        return self

    def block(self, content: str | CalloutComposer) -> ContentComposer:
        """Append raw Markdown or HTML, or a built callout.

        Args:
            content: Markdown or HTML, or a callout to build.

        Returns:
            The composer, for chaining.
        """
        self._blocks.append(content if isinstance(content, str) else content.build())
        return self

    @staticmethod
    def bold(text: str) -> str:
        """Return ``text`` in bold.

        Args:
            text: The text to format.
        """
        return f"**{text}**"

    @staticmethod
    def italic(text: str) -> str:
        """Return ``text`` in italics.

        Args:
            text: The text to format.
        """
        return f"*{text}*"

    @staticmethod
    def code(text: str) -> str:
        """Return ``text`` as inline code.

        Args:
            text: The text to format.
        """
        return f"`{text}`"

    @staticmethod
    def math(latex: str) -> str:
        """Return ``latex`` as an inline formula (``$...$``).

        Args:
            latex: The LaTeX formula, without delimiters.
        """
        return f"${latex}$"

    def build(self) -> str:
        """Return the blocks joined with blank lines."""
        return "\n\n".join(self._blocks)
