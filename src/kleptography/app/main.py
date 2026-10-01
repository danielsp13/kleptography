"""Entry point of the Streamlit application."""

import streamlit as st

from kleptography.app.navigation import all_pages


def main() -> None:
    """Configure the page and run the page selected by the URL."""
    st.set_page_config(
        page_title="Kleptography",
        page_icon="🦊",
        layout="wide",
    )

    st.navigation(all_pages(), position="hidden").run()


if __name__ == "__main__":
    main()
