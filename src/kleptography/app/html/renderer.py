import streamlit as st


def render_html(
    html: str,
    *,
    css: str | None = None,
) -> None:
    if css:
        html = f"""
        <style>
        {css}
        </style>

        {html}
        """

    st.html(html)
