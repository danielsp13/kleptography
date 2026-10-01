"""Outline of the Young–Yung SETUP section: its tabs and their headings."""

from __future__ import annotations

from kleptography.app.components.navigation import PageAnchor, SectionTab

# The tabs of the section and their headings, for the tabs and the sidebar.
# The anchors of "The idea" and "Formulae" are the ones Streamlit derives
# from the Markdown headings of build_setup_concept_content and
# build_setup_formulae_content.
TABS = (
    SectionTab(
        "The idea",
        ":material/lightbulb:",
        (
            PageAnchor("What is a SETUP?", "what-is-a-setup"),
            PageAnchor(
                "Why a public key makes the difference",
                "why-a-public-key-makes-the-difference",
            ),
            PageAnchor("Who is who", "who-is-who"),
            PageAnchor(
                "How much leaks: (m, n)-leakage schemes",
                "how-much-leaks-m-n-leakage-schemes",
            ),
            PageAnchor("Why is it so hard to detect?", "why-is-it-so-hard-to-detect"),
            PageAnchor("What is at stake", "what-is-at-stake"),
        ),
    ),
    SectionTab(
        "Formulae",
        ":material/function:",
        (
            PageAnchor("Notation", "notation"),
            PageAnchor(
                "Arithmetic in a subgroup of prime order",
                "arithmetic-in-a-subgroup-of-prime-order",
            ),
            PageAnchor("What the device computes", "what-the-device-computes"),
            PageAnchor("What the attacker computes", "what-the-attacker-computes"),
            PageAnchor(
                "Why the attacker recovers the key",
                "why-the-attacker-recovers-the-key",
            ),
            PageAnchor(
                "A Diffie-Hellman exchange hidden inside another",
                "a-diffie-hellman-exchange-hidden-inside-another",
            ),
            PageAnchor("Why nobody else can do it", "why-nobody-else-can-do-it"),
            PageAnchor(
                "One key out of two: a (1,2)-leakage scheme",
                "one-key-out-of-two-a-1-2-leakage-scheme",
            ),
            PageAnchor("Worked example", "worked-example"),
            PageAnchor("Implementation choices", "implementation-choices"),
        ),
    ),
    SectionTab(
        "Experiment",
        ":material/science:",
        (
            PageAnchor("1 · Choose the public parameters", "yy-parameters"),
            PageAnchor("2 · The attacker builds the backdoor", "yy-backdoor"),
            PageAnchor("3 · Choose the private keys", "yy-keys"),
            PageAnchor("4 · Run the experiment", "yy-run"),
        ),
    ),
)
