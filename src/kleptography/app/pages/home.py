import streamlit as st

from kleptography.app.components.footer import render_component_footer
from kleptography.app.components.header import render_component_header
from kleptography.app.components.navigation import (
    SectionCard,
    render_component_section_cards,
)
from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.home import build_home_content
from kleptography.app.navigation import (
    diffie_hellman_page,
    encrypted_channel_page,
    young_yung_setup_page,
)


def render_page_home() -> None:
    render_component_header()

    st.markdown(
        CalloutComposer.css(),
        unsafe_allow_html=True,
    )

    _render_sections()

    st.markdown(
        build_home_content(),
        unsafe_allow_html=True,
    )

    render_component_footer()


def _render_sections() -> None:
    st.markdown("## Interactive sections")

    render_component_section_cards(
        [
            SectionCard(
                title="Diffie-Hellman key exchange",
                description=(
                    "Run an honest exchange between Alice and Bob with a toy or "
                    "a standardized group, and follow every step: which values "
                    "are private, which travel over the network, and why both "
                    "end up with the same secret."
                ),
                status="Available",
                url_path=diffie_hellman_page().url_path,
            ),
            SectionCard(
                title="Young–Yung SETUP on Diffie-Hellman",
                description=(
                    "The same exchange with a hidden trapdoor that lets an "
                    "attacker recover the shared secret while every message "
                    "still looks normal. Learn the idea, follow the formulae, "
                    "and take the attacker's seat."
                ),
                status="Available",
                url_path=young_yung_setup_page().url_path,
            ),
            SectionCard(
                title="Encrypted channel compromised by the SETUP",
                description=(
                    "Turn the exchange into a real channel: ephemeral keys, a "
                    "key derivation and AES-GCM over several sessions. Use it "
                    "as a participant, then read it as the attacker, without "
                    "breaking a single cipher."
                ),
                status="Available",
                url_path=encrypted_channel_page().url_path,
            ),
        ]
    )
