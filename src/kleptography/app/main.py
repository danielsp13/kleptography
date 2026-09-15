import streamlit as st

from kleptography.app.content.home import build_home_content


def main() -> None:
    st.set_page_config(
        page_title="Kleptography",
        page_icon="🦊",
        layout="wide",
    )

    st.markdown(build_home_content())


if __name__ == "__main__":
    main()
