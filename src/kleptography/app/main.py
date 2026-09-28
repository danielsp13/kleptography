import streamlit as st

from kleptography.app.navigation import all_pages


def main() -> None:
    st.set_page_config(
        page_title="Kleptography",
        page_icon="🦊",
        layout="wide",
    )

    st.navigation(all_pages(), position="hidden").run()


if __name__ == "__main__":
    main()
