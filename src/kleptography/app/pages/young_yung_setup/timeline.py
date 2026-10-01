"""The step-by-step timeline of the last run of the Young–Yung SETUP section."""

from __future__ import annotations

import streamlit as st

from kleptography.app.components.controls import render_component_step_navigation
from kleptography.app.components.protocol import ValueDisplay
from kleptography.app.components.young_yung_setup import (
    SETUP_STEP_COUNT,
    Backdoor,
    SetupRun,
    render_component_setup_step,
)
from kleptography.app.content.numbers import NumberFormat
from kleptography.app.pages.young_yung_setup.state import REVEALED, RUN
from kleptography.crypto.dh.parameters import DiffieHellmanParameters


def render_timeline_section(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    number_format: NumberFormat,
) -> None:
    """Render the step-by-step timeline of the last run."""
    run: SetupRun | None = st.session_state.get(RUN)

    if run is None:
        st.caption("Run the experiment to follow it step by step.")
        return

    if run.parameters != parameters or run.configuration != backdoor.configuration:
        st.info(
            "The group or the backdoor changed since the last run. Run the "
            "experiment again to see it with the new values.",
            icon=":material/refresh:",
        )
        return

    revealed = min(st.session_state.get(REVEALED, 1), SETUP_STEP_COUNT)

    st.progress(
        revealed / SETUP_STEP_COUNT,
        text=f"Step {revealed} of {SETUP_STEP_COUNT}",
    )

    display = ValueDisplay(number_format, run.parameters.bit_length)
    for number in range(1, revealed + 1):
        render_component_setup_step(number, run, display=display)

    render_component_step_navigation(
        state_key=REVEALED, revealed=revealed, total=SETUP_STEP_COUNT
    )
