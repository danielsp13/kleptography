"""Educational content of the home page."""

from __future__ import annotations

from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.composer import ContentComposer

DOCUMENTATION_URL = (
    "https://github.com/danielsp13/kleptography/blob/main/docs/README.md"
)


def build_home_content() -> str:
    """Return the introduction and roadmap of the home page as Markdown."""
    content = ContentComposer()

    content.h2("Introduction")

    content.paragraph(
        "Kleptography is the study of cryptographic constructions that "
        "appear to behave normally while incorporating a hidden mechanism "
        "that allows an attacker with secret trapdoor information to recover "
        "otherwise protected information."
    )

    content.paragraph(
        "The subject provides a useful perspective for understanding an "
        "important distinction in cryptography: a construction can be "
        "mathematically sound in isolation while its implementation or "
        "construction process may introduce capabilities that are invisible "
        "to its users."
    )

    content.paragraph(
        "This project is an educational environment for studying that "
        "problem through mathematical explanations, reference implementations, "
        "and practical experiments."
    )

    content.divider()

    content.h2("Background")

    content.paragraph(
        "The foundations of this project follow the work of ",
        content.bold("Adam L. Young and Moti Yung"),
        ", who introduced the term ",
        content.bold("kleptography"),
        " in their EUROCRYPT 1997 paper "
        '"Kleptography: Using Cryptography Against Cryptography".',
    )

    content.paragraph(
        "Young and Yung studied how cryptographic systems could be deliberately "
        "constructed or modified to provide an attacker with a hidden capability "
        "for recovering secret information. Their work introduced different "
        "forms of Secretly Embedded Trapdoor with Universal Protection (SETUP) "
        "and demonstrated a strong construction based on the discrete logarithm "
        "problem, including an application to the Diffie-Hellman key exchange."
    )

    content.paragraph(
        "The experiments developed in this project use that work as their "
        "primary conceptual starting point."
    )

    content.block(
        CalloutComposer.info(
            content=(
                "A. L. Young and M. Yung, "
                '"Kleptography: Using Cryptography Against Cryptography," '
                "in Advances in Cryptology — EUROCRYPT '97, "
                "LNCS 1233, pp. 62-74, Springer, 1997."
            ),
            title="Reference",
        )
    )

    content.divider()

    content.h2("Learning objectives")

    content.paragraph(
        "The primary goal is not to provide a collection of ready-to-use "
        "cryptographic tools, but to provide a way of learning how "
        "kleptographic constructions work."
    )

    content.bullet_list(
        [
            (
                "Understand the mathematical foundations of the underlying "
                "cryptographic scheme."
            ),
            "Distinguish a legitimate construction from a deliberately modified one.",
            "Understand the role of a trapdoor and the attacker who possesses it.",
            (
                "Study how secret information can be embedded into apparently "
                "legitimate outputs."
            ),
            (
                "Observe what information is available to an ordinary user "
                "and to the attacker."
            ),
            "Relate the mathematical construction to its concrete implementation.",
            (
                "Develop an intuition for the security assumptions behind "
                "the construction."
            ),
        ]
    )

    content.divider()

    content.h2("Experimental methodology")

    content.paragraph(
        "Each case study follows the same educational progression. "
        "The intention is to make the difference between the legitimate "
        "and kleptographic constructions observable rather than treating "
        "the attack as a black-box result."
    )

    content.bullet_list(
        [
            (
                "Mathematical background — introduce the relevant cryptographic "
                "concepts."
            ),
            "Reference construction — implement the legitimate scheme.",
            "Kleptographic construction — introduce the hidden mechanism.",
            ("Experiment — execute both constructions under comparable conditions."),
            ("Observation — identify the information visible to each participant."),
            (
                "Analysis — connect the observed behaviour with the underlying "
                "mathematics."
            ),
        ]
    )

    content.paragraph(
        "The experiments are intended to be reproducible and inspectable. "
        "Whenever possible, the implementation exposes the parameters, "
        "intermediate values, and relationships necessary to understand "
        "why the construction behaves as observed."
    )

    content.divider()

    content.h2("First case study: Diffie-Hellman")

    content.paragraph(
        "The first case study focuses on the ",
        content.bold("Diffie-Hellman key exchange"),
        ". This construction provides a useful starting point because its "
        "security is closely connected to the discrete logarithm problem, "
        "which also plays a central role in the Young-Yung kleptographic "
        "construction described in their EUROCRYPT 1997 work.",
    )

    content.paragraph(
        "The study first establishes how an ordinary Diffie-Hellman "
        "exchange works and why the participants can derive a shared secret. "
        "The following experiments examine how the construction can be "
        "modified to incorporate a hidden trapdoor mechanism, and what that "
        "trapdoor gives away once the exchange protects a real channel."
    )

    content.paragraph(
        content.bold("Implementation status:"),
        " the honest Diffie-Hellman exchange, the Young-Yung SETUP on it "
        "and an encrypted channel (Diffie-Hellman, a key derivation function "
        "and AES-GCM) compromised by that SETUP are available as "
        "interactive sections.",
    )

    content.divider()

    content.h2("Research roadmap")

    content.bullet_list(
        [
            (
                ":green-badge[Done] Establish the mathematical and "
                "implementation foundations."
            ),
            ":green-badge[Done] Implement the reference Diffie-Hellman construction.",
            (
                ":green-badge[Done] Study and implement the corresponding "
                "Young-Yung construction."
            ),
            ":green-badge[Done] Build interactive experiments around the construction.",
            (
                ":green-badge[Done] Expose the relevant intermediate values and "
                "attacker knowledge."
            ),
            ":green-badge[Done] Document the security assumptions and limitations.",
            (
                ":orange-badge[Next] Use the same methodology to study "
                "additional cryptographic constructions, such as RSA key "
                "generation and post-quantum schemes."
            ),
        ]
    )

    content.divider()

    content.h2("Documentation")

    content.paragraph(
        "The interactive sections are built on a Python library that can be "
        "used and studied on its own. Its ",
        "[developer documentation](" + DOCUMENTATION_URL + ")",
        " describes the architecture, the number theory, the Diffie-Hellman "
        "implementation, the Young-Yung SETUP, the key derivation and AES-GCM "
        "primitives, and the encrypted channel, with diagrams and runnable "
        "examples.",
    )

    content.divider()

    content.h2("Scope")

    content.paragraph(
        "The project is intended exclusively for educational, research, "
        "and experimental purposes. The implementations are designed to "
        "make cryptographic concepts and kleptographic mechanisms easier "
        "to study, inspect, and reproduce."
    )

    content.block(
        CalloutComposer.warning(
            content=(
                "The cryptographic implementations provided by this project "
                "are experimental educational material and must not be used "
                "as production-grade cryptographic software."
            ),
            title="Important",
        )
    )

    return content.build()
