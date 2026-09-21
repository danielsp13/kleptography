import streamlit as st

from kleptography.app.pages.home import render_page_home


def main() -> None:
    st.set_page_config(
        page_title="Kleptography",
        page_icon="🦊",
        layout="wide",
    )

    render_page_home()


if __name__ == "__main__":
    main()
