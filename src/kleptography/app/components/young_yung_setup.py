"""Components that render a Young–Yung SETUP experiment step by step.

A run is two traced Diffie-Hellman exchanges between a compromised device
(in Alice's role) and an honest Bob, the SETUP derivation that happened
between them, and the attacker's recovery. Every value is read from the
``crypto`` objects of the run; nothing is computed here.
"""

from __future__ import annotations

from dataclasses import dataclass

import streamlit as st

from kleptography.app.components.protocol import (
    ValueDisplay,
    Visibility,
    render_component_parameters,
    render_component_value,
)
from kleptography.app.content.numbers import is_small
from kleptography.app.content.young_yung_setup import (
    SETUP_STEP_DEFINITIONS,
    ExchangeSummary,
    build_backdoor_content,
    build_setup_leakage_content,
    build_setup_observers_content,
    hash_formula,
    power_formula,
    r_formula,
    z1_formula,
    z2_formula,
    z_formula,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.records import SetupDerivation, SetupRecovery

SETUP_STEP_COUNT = len(SETUP_STEP_DEFINITIONS)


@dataclass(frozen=True, slots=True)
class SetupRun:
    """An executed SETUP experiment.

    Attributes:
        parameters: The group of both exchanges.
        attacker: The attacker, holding the private key ``X``.
        configuration: The SETUP embedded in the device.
        first_exchange: Values of the first (honest-looking) exchange.
        second_exchange: Values of the second exchange, with the leaked key.
        derivation: How the device derived ``a2`` from ``a1``.
        recovery: How the attacker recovered ``a2``.
        recovered_shared_secret: The second shared secret, as computed by
            the attacker.
    """

    parameters: DiffieHellmanParameters
    attacker: YoungYungAttacker
    configuration: YoungYungConfiguration
    first_exchange: ExchangeSummary
    second_exchange: ExchangeSummary
    derivation: SetupDerivation
    recovery: SetupRecovery
    recovered_shared_secret: int


def render_component_backdoor(
    *,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    display: ValueDisplay,
) -> None:
    """Render the attacker's key pair and the constants hidden in the device.

    Args:
        attacker: The attacker, holding ``X``.
        configuration: The SETUP embedded in the device.
        display: How values are displayed.
    """
    parameters = configuration.parameters
    # Y is stored in the configuration: recomputing g^X costs a full modular
    # exponentiation (about a second with FFDHE8192) on every rerun.
    public_key = configuration.attacker_public_key
    attacker_column, device_column = st.columns(2)

    with attacker_column, st.container(border=True):
        st.markdown("#### :material/vpn_key: Attacker")
        _value("Private key $X$", attacker.private_key, Visibility.ATTACKER, display)
        st.latex(
            power_formula(
                "Y",
                "g",
                "X",
                base=parameters.generator,
                exponent=attacker.private_key,
                prime=parameters.prime,
                result=public_key,
            )
        )
        _value("Public key $Y$", public_key, Visibility.DEVICE, display)

    with device_column, st.container(border=True):
        st.markdown("#### :material/memory: Inside Alice's device")
        _value(
            "Multiplier $\\alpha$",
            configuration.multiplier_a,
            Visibility.DEVICE,
            display,
        )
        _value("Offset $\\beta$", configuration.offset_b, Visibility.DEVICE, display)
        _value(
            "Correction $W$ (odd)",
            configuration.correction_w,
            Visibility.DEVICE,
            display,
        )
        st.markdown(
            "Hash $H$: SHAKE-256 of $z$, reduced to an exponent in $[1, q - 1]$."
        )


def render_component_setup_step(
    number: int,
    run: SetupRun,
    *,
    display: ValueDisplay,
) -> None:
    """Render one explanatory step of an executed SETUP experiment.

    Args:
        number: The step number, from 1 to ``SETUP_STEP_COUNT``.
        run: The executed experiment.
        display: How values are displayed.
    """
    renderers = {
        1: _render_parameters,
        2: _render_backdoor,
        3: _render_first_exchange,
        4: _render_derivation,
        5: _render_second_exchange,
        6: _render_transcript,
        7: _render_recovery,
        8: _render_recovered_secret,
    }
    definition = SETUP_STEP_DEFINITIONS[number - 1]

    with st.container(border=True):
        st.markdown(f"### Step {number} · {definition.title}")
        st.markdown(definition.explanation)
        st.latex(definition.formula)
        renderers[number](run, display)


def _value(
    label: str,
    value: int,
    visibility: Visibility,
    display: ValueDisplay,
) -> None:
    """Render an integer with the run's display settings."""
    render_component_value(
        label,
        value,
        visibility=visibility,
        number_format=display.number_format,
        width_bits=display.width_bits,
    )


def _render_parameters(run: SetupRun, display: ValueDisplay) -> None:
    """Render step 1: the public parameters of the group."""
    render_component_parameters(
        prime=run.parameters.prime,
        generator=run.parameters.generator,
        subgroup_order=run.parameters.subgroup_order,
        display=display,
    )


def _render_backdoor(run: SetupRun, display: ValueDisplay) -> None:
    """Render step 2: the attacker's keys and the embedded configuration."""
    render_component_backdoor(
        attacker=run.attacker,
        configuration=run.configuration,
        display=display,
    )
    st.markdown(build_backdoor_content(), unsafe_allow_html=True)


def _render_exchange(
    run: SetupRun,
    exchange: ExchangeSummary,
    *,
    index: int,
    device_key_origin: str,
    display: ValueDisplay,
) -> None:
    """Render one exchange, the device and Bob side by side."""
    prime = run.parameters.prime
    generator = run.parameters.generator
    device_column, bob_column = st.columns(2)

    with device_column, st.container(border=True):
        st.markdown("#### :material/memory: Alice's device")
        _value(
            f"Private key $a_{index}$ ({device_key_origin})",
            exchange.device_private_key,
            Visibility.DEVICE,
            display,
        )
        st.latex(
            power_formula(
                f"A_{index}",
                "g",
                f"a_{index}",
                base=generator,
                exponent=exchange.device_private_key,
                prime=prime,
                result=exchange.device_public_key,
            )
        )
        _value(
            f"Public key $A_{index}$",
            exchange.device_public_key,
            Visibility.PUBLIC,
            display,
        )
        st.latex(
            power_formula(
                f"s_{index}",
                f"B_{index}",
                f"a_{index}",
                base=exchange.peer_public_key,
                exponent=exchange.device_private_key,
                prime=prime,
                result=exchange.device_shared_secret,
            )
        )
        _value(
            f"Shared secret $s_{index}$",
            exchange.device_shared_secret,
            Visibility.SHARED_SECRET,
            display,
        )

    with bob_column, st.container(border=True):
        st.markdown("#### :material/person: Bob (honest)")
        _value(
            f"Private key $b_{index}$",
            exchange.peer_private_key,
            Visibility.PRIVATE,
            display,
        )
        st.latex(
            power_formula(
                f"B_{index}",
                "g",
                f"b_{index}",
                base=generator,
                exponent=exchange.peer_private_key,
                prime=prime,
                result=exchange.peer_public_key,
            )
        )
        _value(
            f"Public key $B_{index}$",
            exchange.peer_public_key,
            Visibility.PUBLIC,
            display,
        )
        st.latex(
            power_formula(
                f"s_{index}",
                f"A_{index}",
                f"b_{index}",
                base=exchange.device_public_key,
                exponent=exchange.peer_private_key,
                prime=prime,
                result=exchange.peer_shared_secret,
            )
        )
        _value(
            f"Shared secret $s_{index}$",
            exchange.peer_shared_secret,
            Visibility.SHARED_SECRET,
            display,
        )

    if exchange.device_shared_secret == exchange.peer_shared_secret:
        st.success(
            f"Alice and Bob share the same secret $s_{index}$: the exchange "
            "worked as expected.",
            icon=":material/check_circle:",
        )
    else:
        st.error(
            "The participants computed different secrets. The exchange failed.",
            icon=":material/error:",
        )


def _render_first_exchange(run: SetupRun, display: ValueDisplay) -> None:
    """Render step 3: the first exchange, with an honest a1."""
    exchange = run.first_exchange
    _render_exchange(
        run,
        exchange,
        index=1,
        device_key_origin=(
            "chosen at random" if exchange.device_key_generated else "chosen by you"
        ),
        display=display,
    )
    st.info(
        "The attacker, listening on the network, stores $A_1$.",
        icon=":material/radar:",
    )


def _render_derivation(run: SetupRun, display: ValueDisplay) -> None:
    """Render step 4: the SETUP derivation of a2 inside the device."""
    derivation = run.derivation
    configuration = run.configuration
    parameters = run.parameters

    with st.container(border=True):
        st.markdown("#### :material/memory: Inside Alice's device")
        st.markdown(
            f"Random correction bit: $t = {derivation.correction_bit}$ &nbsp; "
            ":orange-badge[:material/memory: Hidden in the device]"
        )
        st.latex(
            z_formula(
                generator=parameters.generator,
                previous_private_key=derivation.previous_private_key,
                correction_w=configuration.correction_w,
                correction_bit=derivation.correction_bit,
                attacker_public_key=configuration.attacker_public_key,
                multiplier_a=configuration.multiplier_a,
                offset_b=configuration.offset_b,
                prime=parameters.prime,
                z=derivation.z,
            )
        )
        _value("Hidden value $z$", derivation.z, Visibility.DEVICE, display)
        st.latex(
            hash_formula("a_2", "z", z=derivation.z, result=derivation.private_key)
        )
        _value(
            "Next private key $a_2$",
            derivation.private_key,
            Visibility.DEVICE,
            display,
        )

    st.caption(
        "An honest device would sample $a_2$ at random. Here $a_2$ depends "
        "on $a_1$ and $Y$, but it looks just as random."
    )


def _render_second_exchange(run: SetupRun, display: ValueDisplay) -> None:
    """Render step 5: the second exchange, with the derived a2."""
    _render_exchange(
        run,
        run.second_exchange,
        index=2,
        device_key_origin="derived by the SETUP",
        display=display,
    )


def _render_transcript(run: SetupRun, display: ValueDisplay) -> None:
    """Render step 6: the public transcript of both exchanges."""
    messages = (
        ("Alice → Bob, exchange 1: $A_1$", run.first_exchange.device_public_key),
        ("Bob → Alice, exchange 1: $B_1$", run.first_exchange.peer_public_key),
        ("Alice → Bob, exchange 2: $A_2$", run.second_exchange.device_public_key),
        ("Bob → Alice, exchange 2: $B_2$", run.second_exchange.peer_public_key),
    )

    for row in (messages[:2], messages[2:]):
        for column, (label, value) in zip(st.columns(2), row, strict=True):
            with column:
                _value(label, value, Visibility.PUBLIC, display)

    st.success(
        "All four values passed the protocol's public key validation "
        r"($1 < y < p$ and $y^{q} \equiv 1 \pmod{p}$), exactly like honest ones.",
        icon=":material/check_circle:",
    )
    st.markdown(build_setup_observers_content(), unsafe_allow_html=True)


def _render_recovery(run: SetupRun, display: ValueDisplay) -> None:
    """Render step 7: the attacker's recovery of a2 from A1 and A2."""
    recovery = run.recovery
    configuration = run.configuration
    parameters = run.parameters
    z1, z2 = recovery.z_candidates

    with st.container(border=True):
        st.markdown("#### :material/vpn_key: Attacker's workspace")
        st.latex(
            r_formula(
                first_public_key=recovery.first_public_key,
                multiplier_a=configuration.multiplier_a,
                generator=parameters.generator,
                offset_b=configuration.offset_b,
                prime=parameters.prime,
                r=recovery.r,
            )
        )
        _value("$r$", recovery.r, Visibility.ATTACKER, display)
        st.latex(
            z1_formula(
                first_public_key=recovery.first_public_key,
                r=recovery.r,
                attacker_private_key=run.attacker.private_key,
                prime=parameters.prime,
                z1=z1,
            )
        )
        _value("Candidate $z_1$ (if $t = 0$)", z1, Visibility.ATTACKER, display)
        st.latex(
            z2_formula(
                z1=z1,
                generator=parameters.generator,
                correction_w=configuration.correction_w,
                prime=parameters.prime,
                z2=z2,
            )
        )
        _value("Candidate $z_2$ (if $t = 1$)", z2, Visibility.ATTACKER, display)

    st.markdown("Each candidate gives a possible key. Only one reproduces $A_2$:")

    columns = st.columns(2)
    for index, (column, z, candidate) in enumerate(
        zip(
            columns, recovery.z_candidates, recovery.private_key_candidates, strict=True
        ),
        start=1,
    ):
        with column, st.container(border=True):
            st.markdown(f"#### Candidate $t = {index - 1}$")
            st.latex(
                hash_formula(rf"\hat{{a}}_{index}", f"z_{index}", z=z, result=candidate)
            )
            _value(
                rf"Candidate key $\hat{{a}}_{index}$",
                candidate,
                Visibility.ATTACKER,
                display,
            )
            _render_candidate_check(run, candidate, index=index)

    if recovery.correction_bit == run.derivation.correction_bit:
        st.success(
            f"The attacker has $a_2$, and knows the device drew "
            f"$t = {recovery.correction_bit}$, without ever seeing it.",
            icon=":material/lock_open:",
        )
    else:
        st.success(
            "The attacker has $a_2$. In such a tiny group both candidates "
            "happen to hash to the same key, so the first one already matches "
            "and the attacker cannot tell which $t$ the device drew. It does "
            "not matter: the key is the same.",
            icon=":material/lock_open:",
        )


def _render_candidate_check(run: SetupRun, candidate: int, *, index: int) -> None:
    """Render whether a candidate exponent reproduces A2."""
    # Only the matching candidate's power is known (it is A2), so the
    # rejected one is shown symbolically.
    if candidate != run.recovery.private_key:
        st.markdown(
            rf"$g^{{\hat{{a}}_{index}}} \not\equiv A_2$ &nbsp; "
            ":red-badge[:material/close: Does not match $A_2$]"
        )
        return

    generator = run.parameters.generator
    prime = run.parameters.prime
    second_public_key = run.recovery.second_public_key
    check = (
        rf"{generator}^{{{candidate}}} \bmod {prime} = {second_public_key} = A_2"
        if is_small(candidate, prime, second_public_key)
        else rf"g^{{\hat{{a}}_{index}}} \equiv A_2"
    )
    st.markdown(f"${check}$ &nbsp; :green-badge[:material/check: Matches $A_2$]")


def _render_recovered_secret(run: SetupRun, display: ValueDisplay) -> None:
    """Render step 8: the shared secret recovered by the attacker."""
    second = run.second_exchange
    recovered = run.recovered_shared_secret

    with st.container(border=True):
        st.markdown("#### :material/vpn_key: Attacker")
        st.latex(
            power_formula(
                "s_2",
                "B_2",
                "a_2",
                base=second.peer_public_key,
                exponent=run.recovery.private_key,
                prime=run.parameters.prime,
                result=recovered,
            )
        )
        _value("Recovered shared secret $s_2$", recovered, Visibility.ATTACKER, display)

    if recovered == second.device_shared_secret == second.peer_shared_secret:
        st.success(
            "The attacker's $s_2$ is exactly the secret Alice and Bob share. "
            "The backdoor worked, and the exchange never looked different.",
            icon=":material/verified:",
        )
    else:
        st.error(
            "The recovered secret does not match the one Alice and Bob share.",
            icon=":material/error:",
        )

    st.markdown(build_setup_leakage_content(), unsafe_allow_html=True)
