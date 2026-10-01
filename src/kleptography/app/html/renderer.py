"""Injection of raw HTML, with optional CSS, into a Streamlit page."""

import streamlit as st


def render_html(
    html: str,
    *,
    css: str | None = None,
) -> None:
    """Render raw HTML in the page, preceded by an optional stylesheet.

    Args:
        html: The HTML to render.
        css: The CSS to inject in a ``<style>`` element, if any.
    """
    if css:
        html = f"""
        <style>
        {css}
        </style>

        {html}
        """

    st.html(html)
