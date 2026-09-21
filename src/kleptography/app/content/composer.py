from __future__ import annotations

from kleptography.app.content.callouts import CalloutComposer


class ContentComposer:
    """Compose educational content as Markdown."""

    def __init__(self) -> None:
        self._blocks: list[str] = []

    def h1(self, text: str) -> ContentComposer:
        self._blocks.append(f"# {text}")
        return self

    def h2(self, text: str) -> ContentComposer:
        self._blocks.append(f"## {text}")
        return self

    def h3(self, text: str) -> ContentComposer:
        self._blocks.append(f"### {text}")
        return self

    def paragraph(self, *parts: str) -> ContentComposer:
        self._blocks.append("".join(parts))
        return self

    def divider(self) -> ContentComposer:
        self._blocks.append("---")
        return self

    def bullet_list(self, items: list[str]) -> ContentComposer:
        self._blocks.append("\n".join(f"- {item}" for item in items))
        return self

    def ordered_list(self, items: list[str]) -> ContentComposer:
        self._blocks.append(
            "\n".join(f"{index}. {item}" for index, item in enumerate(items, start=1))
        )
        return self

    def quote(self, *parts: str) -> ContentComposer:
        self._blocks.append(f"> {''.join(parts)}")
        return self

    def image(self, src: str, alt: str = "") -> ContentComposer:
        self._blocks.append(f"![{alt}]({src})")
        return self

    def block(self, content: str | CalloutComposer) -> ContentComposer:
        self._blocks.append(content if isinstance(content, str) else content.build())
        return self

    @staticmethod
    def bold(text: str) -> str:
        return f"**{text}**"

    @staticmethod
    def italic(text: str) -> str:
        return f"*{text}*"

    @staticmethod
    def code(text: str) -> str:
        return f"`{text}`"

    def build(self) -> str:
        return "\n\n".join(self._blocks)
