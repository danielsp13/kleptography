"""The site header: logo, title, description and tags."""

from kleptography import __version__
from kleptography.app.assets.loader import asset_data_uri
from kleptography.app.css.loader import load_css
from kleptography.app.html.loader import render_template
from kleptography.app.html.renderer import render_html


def render_component_header() -> None:
    """Render the site header."""
    logo = asset_data_uri(
        "logos",
        "kleptofox.png",
        mime_type="image/png",
    )

    html = render_template(
        "header.html",
        logo=logo,
        title="Kleptography",
        subtitle="Cryptography against cryptography",
        description="An open-source educational project for studying and "
        + "demonstrating kleptographic techniques.",
        version=__version__,
        release_date="2026-10-01",
        author_name="Daniel Pérez Ruiz",
        author_role="Cryptography Software Engineer @",
        company="jtsec Beyond IT Security",
        company_url="https://www.jtsec.es/",
        linkedin_url="https://www.linkedin.com/in/daniel-perez-ruiz",
        github_url="https://github.com/danielsp13",
        email="danielperezruiz.pro@gmail.com",
        tags=[
            "Cryptography",
            "Kleptography",
            "Python",
            "Open Source",
            "Security",
            "Cryptographic Protocols",
        ],
        kleptographic_mechanisms=[
            "Diffie-Hellman",
        ],
    )

    render_html(
        html,
        css=load_css("header.css"),
    )
