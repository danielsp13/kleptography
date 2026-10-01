"""The step-by-step timeline of the last run of the Diffie-Hellman section."""

from __future__ import annotations

import streamlit as st

from kleptography.app.components.controls import render_component_step_navigation
from kleptography.app.components.protocol import (
    ValueDisplay,
    render_component_protocol_step,
)
from kleptography.app.content.numbers import NumberFormat
from kleptography.app.pages.diffie_hellman.experiment import ExchangeRun
from kleptography.app.pages.diffie_hellman.state import REVEALED, RUN
from kleptography.crypto.dh.parameters import DiffieHellmanParameters


def render_timeline_section(
    parameters: DiffieHellmanParameters,
    number_format: NumberFormat,
) -> None:
    """Render the step-by-step timeline of the last run."""
    run: ExchangeRun | None = st.session_state.get(RUN)

    if run is None:
        st.caption("Run the exchange to follow it step by step.")
        return

    if run.parameters != parameters:
        st.info(
            "The parameters changed since the last run. Run the exchange again "
            "to see it with the new group.",
            icon=":material/refresh:",
        )
        return

    total = len(run.steps)
    revealed = min(st.session_state.get(REVEALED, 1), total)

    st.progress(revealed / total, text=f"Step {revealed} of {total}")

    display = ValueDisplay(number_format, run.parameters.bit_length)
    for step in run.steps[:revealed]:
        render_component_protocol_step(step, display=display)

    render_component_step_navigation(state_key=REVEALED, revealed=revealed, total=total)
