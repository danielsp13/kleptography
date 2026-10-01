"""Callout boxes (note, tip, warning, ...) rendered as HTML."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CalloutComposer:
    """Compose a callout as HTML suitable for Streamlit.

    The content is inserted as HTML, so it must use HTML markup instead of
    Markdown or LaTeX.

    Attributes:
        type: The kind of callout, one of ``TYPES``.
        title: The title shown above the content.
        content: The HTML content of the callout.

    Raises:
        ValueError: If ``type`` is not one of ``TYPES``.
    """

    type: str
    title: str
    content: str

    TYPES = {
        "note",
        "tip",
        "warning",
        "danger",
        "info",
        "success",
    }

    def __post_init__(self) -> None:
        """Check that the callout type is known."""
        if self.type not in self.TYPES:
            raise ValueError(
                f"Unknown callout type: {self.type!r}. "
                f"Expected one of: {', '.join(sorted(self.TYPES))}"
            )

    def build(self) -> str:
        """Return the callout as HTML."""
        return (
            f'<div class="callout callout-{self.type}">'
            f'<div class="callout-title">{self.title}</div>'
            f'<div class="callout-content">{self.content}</div>'
            "</div>"
        )

    @classmethod
    def note(cls, content: str, title: str = "Note") -> CalloutComposer:
        """Return a note callout.

        Args:
            content: The HTML content of the callout.
            title: The title shown above the content.
        """
        return cls("note", title, content)

    @classmethod
    def tip(cls, content: str, title: str = "Tip") -> CalloutComposer:
        """Return a tip callout.

        Args:
            content: The HTML content of the callout.
            title: The title shown above the content.
        """
        return cls("tip", title, content)

    @classmethod
    def warning(cls, content: str, title: str = "Warning") -> CalloutComposer:
        """Return a warning callout.

        Args:
            content: The HTML content of the callout.
            title: The title shown above the content.
        """
        return cls("warning", title, content)

    @classmethod
    def danger(cls, content: str, title: str = "Danger") -> CalloutComposer:
        """Return a danger callout.

        Args:
            content: The HTML content of the callout.
            title: The title shown above the content.
        """
        return cls("danger", title, content)

    @classmethod
    def info(cls, content: str, title: str = "Info") -> CalloutComposer:
        """Return an info callout.

        Args:
            content: The HTML content of the callout.
            title: The title shown above the content.
        """
        return cls("info", title, content)

    @classmethod
    def success(cls, content: str, title: str = "Success") -> CalloutComposer:
        """Return a success callout.

        Args:
            content: The HTML content of the callout.
            title: The title shown above the content.
        """
        return cls("success", title, content)

    @staticmethod
    def css() -> str:
        """Return the ``<style>`` block that every page using callouts emits once."""
        return """
        <style>
        .callout {
            padding: 1rem 1.1rem;
            margin: 1rem 0;
            border-left: 5px solid;
            border-radius: 0.5rem;
            background: rgba(127, 127, 127, 0.08);
        }

        .callout-title {
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .callout-content {
            line-height: 1.5;
        }

        .callout-content p:last-child {
            margin-bottom: 0;
        }

        /* Note */
        .callout-note {
            border-color: #6b7280;
            background: rgba(107, 114, 128, 0.10);
        }

        .callout-note .callout-title {
            color: #4b5563;
        }

        /* Tip */
        .callout-tip {
            border-color: #10b981;
            background: rgba(16, 185, 129, 0.10);
        }

        .callout-tip .callout-title {
            color: #059669;
        }

        /* Warning */
        .callout-warning {
            border-color: #f59e0b;
            background: rgba(245, 158, 11, 0.10);
        }

        .callout-warning .callout-title {
            color: #d97706;
        }

        /* Danger */
        .callout-danger {
            border-color: #ef4444;
            background: rgba(239, 68, 68, 0.10);
        }

        .callout-danger .callout-title {
            color: #dc2626;
        }

        /* Info */
        .callout-info {
            border-color: #3b82f6;
            background: rgba(59, 130, 246, 0.10);
        }

        .callout-info .callout-title {
            color: #2563eb;
        }

        /* Success */
        .callout-success {
            border-color: #22c55e;
            background: rgba(34, 197, 94, 0.10);
        }

        .callout-success .callout-title {
            color: #16a34a;
        }
        </style>
        """
