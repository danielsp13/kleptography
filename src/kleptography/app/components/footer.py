"""The site footer: version, author and links."""

from kleptography.app.css.loader import load_css
from kleptography.app.html.loader import render_template
from kleptography.app.html.renderer import render_html


def render_component_footer() -> None:
    """Render the site footer."""
    html = render_template(
        "footer.html",
        title="Kleptography",
        subtitle="Cryptography against cryptography",
        version="1.0.0",
        release_date="2026-09-21",
        year="2026",
        author_name="Daniel Pérez Ruiz",
        repository_url="https://github.com/danielsp13",
        documentation_url="https://github.com/danielsp13",
        license_url="https://github.com/danielsp13",
    )

    render_html(
        html,
        css=load_css("footer.css"),
    )
