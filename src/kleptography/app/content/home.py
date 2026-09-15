from kleptography.app.content.composer import ContentComposer


def build_home_content() -> str:
    content = ContentComposer()

    content.h1("Kleptography")

    content.h2("Cryptography against cryptography")

    content.paragraph(
        "An open-source educational project for studying and demonstrating ",
        content.bold("kleptographic techniques"),
        ".",
    )

    content.paragraph(
        "Kleptography studies cryptographic constructions that appear to "
        "behave normally while deliberately leaking secret information to "
        "an attacker who knows a hidden trapdoor."
    )

    content.divider()

    content.h3("What is this project about?")

    content.paragraph("This application will provide interactive demonstrations of:")

    content.bullet_list(
        [
            "🔐 " + content.bold("Legitimate cryptographic schemes"),
            "🕵️ " + content.bold("SETUP / kleptographic constructions"),
            "🔎 " + content.bold("Information that becomes observable to an attacker"),
            "🧮 "
            + content.bold("The mathematical mechanisms behind the constructions"),
            "📊 "
            + content.bold(
                "Side-by-side comparisons between normal and kleptographic behaviour"
            ),
        ]
    )

    content.paragraph(
        "The first target is ",
        content.bold("Diffie-Hellman"),
        ", with other cryptographic schemes planned for the future.",
    )

    content.quote(
        content.bold("Educational project"),
        "\n\n",
        "The implementations and demonstrations are intended for learning, "
        "analysis, and experimentation. They must not be considered "
        "production-grade cryptographic software.",
    )

    content.divider()

    content.h3("Explore")

    content.h3("Diffie-Hellman")

    content.paragraph(
        "Learn how the legitimate Diffie-Hellman key exchange works, "
        "from the underlying mathematics to an interactive demonstration."
    )

    content.paragraph(content.bold("Coming soon."))

    content.h3("Kleptography")

    content.paragraph(
        "Explore how a SETUP construction can modify a cryptographic "
        "scheme while preserving behaviour that appears normal to an "
        "observer."
    )

    content.paragraph(content.bold("Coming soon."))

    content.divider()

    content.paragraph("Kleptography — an open-source educational project")

    return content.build()
