"""Educational content for the Young–Yung SETUP section on Diffie-Hellman.

The section tells the same story three times: as an idea (what a SETUP is
and why this one is a (1,2)-leakage scheme), as mathematics (the complete
derivation of why the attacker recovers the key), and as an experiment
(a step-by-step run). This module holds the text and LaTeX of all three and
the helpers that substitute concrete values into formulas. It never performs
cryptographic computations: every number comes from the ``crypto`` API.

Notation follows the honest Diffie-Hellman section for the protocol roles:
the device plays Alice, with private keys ``a1``, ``a2`` and public keys
``A1``, ``A2``; Bob has ``b1``, ``b2`` and ``B1``, ``B2``; the shared secrets
are ``s1``, ``s2``. The SETUP machinery keeps the symbols of Young and Yung
(EUROCRYPT '97): the attacker's key pair ``(X, Y)``, the correction ``W``, the
bit ``t``, the hash ``H`` and the values ``z`` and ``r``. The paper's constants
``a`` and ``b`` are written ``alpha`` and ``beta`` here, and its keys ``c1``,
``c2`` / ``m1``, ``m2`` are ``a1``, ``a2`` / ``A1``, ``A2``. The formulae tab
shows this correspondence to the reader.
"""

from __future__ import annotations

from dataclasses import dataclass

from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.composer import ContentComposer
from kleptography.app.content.diffie_hellman import StepDefinition
from kleptography.app.content.numbers import is_small
from kleptography.crypto.dh.tracing.events import (
    Actor,
    ProtocolEvent,
    ProtocolEventType,
)

REFERENCE = (
    "A. L. Young and M. Yung, "
    '"Kleptography: Using Cryptography Against Cryptography," '
    "in Advances in Cryptology — EUROCRYPT '97, "
    "LNCS 1233, pp. 62-74, Springer, 1997."
)

SETUP_STEP_DEFINITIONS: tuple[StepDefinition, ...] = (
    StepDefinition(
        title="Agree on the public parameters",
        explanation=(
            "Exactly as in an honest exchange, Alice and Bob agree on a prime "
            "$p = 2q + 1$ and a generator $g$ of the subgroup of order $q$. "
            "The attacker works in the **same group**: that is what lets the "
            "backdoor hide inside ordinary public keys."
        ),
        formula=r"p = 2q + 1, \qquad g^{q} \equiv 1 \pmod{p}",
    ),
    StepDefinition(
        title="The attacker plants the backdoor",
        explanation=(
            "Long before any exchange, the attacker (for example, whoever "
            "designs or manufactures the device) creates an ordinary "
            "Diffie-Hellman key pair: a private key $X$ that never leaves "
            "their hands, and a public key $Y = g^{X}$. The device is shipped "
            "with $Y$, three constants $\\alpha$, $\\beta$ and $W$ ($W$ odd) and "
            "a hash "
            "function $H$ built in. Alice cannot see inside it: to her it is "
            "a black box that performs Diffie-Hellman."
        ),
        formula=r"Y = g^{X} \bmod p",
    ),
    StepDefinition(
        title="First exchange: the device behaves honestly",
        explanation=(
            "Alice's device picks a truly random private key $a_1$ and sends "
            "$A_1 = g^{a_1}$. Bob, who is honest, does the same with $b_1$. "
            "Both compute the same shared secret $s_1$. Nothing unusual "
            "happens, but the attacker, listening on the network, **records "
            "$A_1$**: it will be the key to the next exchange."
        ),
        formula=(
            r"A_1 = g^{a_1}, \quad B_1 = g^{b_1}, \qquad "
            r"s_1 = B_1^{a_1} = A_1^{b_1} = g^{a_1 b_1} \bmod p"
        ),
    ),
    StepDefinition(
        title="Between exchanges: the device derives its next key",
        explanation=(
            "When a new key is needed, an honest device would pick another "
            "random number. The compromised one does not: it flips a random "
            "bit $t$, mixes its **previous** private key $a_1$ with the "
            "attacker's public key $Y$ into a group element $z$, and hashes "
            "$z$ into the new private key $a_2$. This happens inside the "
            "device: nobody sees $t$, $z$ or $a_2$."
        ),
        formula=(
            r"z = g^{\,a_1 - W t} \cdot Y^{\,-\alpha a_1 - \beta} \bmod p, "
            r"\qquad a_2 = H(z)"
        ),
    ),
    StepDefinition(
        title="Second exchange: the leaked key goes out",
        explanation=(
            "The device sends $A_2 = g^{a_2}$, a perfectly valid public key. "
            "Bob picks a fresh key $b_2$, and both compute the second shared "
            "secret $s_2$. The exchange succeeds, as always."
        ),
        formula=(
            r"A_2 = g^{a_2}, \quad B_2 = g^{b_2}, \qquad "
            r"s_2 = B_2^{a_2} = A_2^{b_2} = g^{a_2 b_2} \bmod p"
        ),
    ),
    StepDefinition(
        title="What travels over the network",
        explanation=(
            "These four public keys are everything that crossed the network. "
            "They are valid elements of the subgroup, the exchanges "
            "succeeded, and $a_2$ is the output of a hash, so it looks just "
            "as random as $a_1$. **Eve and the attacker see exactly the same "
            "messages.** The only difference between them is that the "
            "attacker knows $X$."
        ),
        formula=(
            r"\text{transcript} = (A_1,\ B_1,\ A_2,\ B_2), \qquad "
            r"1 < A_i, B_i < p, \quad A_i^{q} \equiv B_i^{q} \equiv 1"
        ),
    ),
    StepDefinition(
        title="The attacker recovers the second private key",
        explanation=(
            "From $A_1$ and the constants $\\alpha$ and $\\beta$, the attacker "
            "computes $r$. With the private key $X$, it removes the mask that the "
            "device put on $z$ and obtains $z_1$. The attacker does not know "
            "the bit $t$, so it also computes the other possible value $z_2$, "
            "hashes both into the candidate keys $\\hat{a}_1$ and $\\hat{a}_2$, and "
            "keeps the one whose public key equals the $A_2$ it observed."
        ),
        formula=(
            r"r = A_1^{\alpha} \cdot g^{\beta}, \qquad "
            r"z_1 = \frac{A_1}{r^{X}}, \qquad z_2 = \frac{z_1}{g^{W}}, "
            r"\qquad \hat{a}_i = H(z_i), \quad g^{\hat{a}_i} \overset{?}{=} A_2"
        ),
    ),
    StepDefinition(
        title="The attacker reads the second shared secret",
        explanation=(
            "Knowing $a_2$, the attacker computes $s_2$ exactly like Alice "
            "does, from Bob's public key $B_2$. Alice and Bob still share "
            "the same secret, and they have no reason to suspect that "
            "someone else has it too."
        ),
        formula=r"s_2 = B_2^{a_2} \bmod p",
    ),
)


@dataclass(frozen=True, slots=True)
class ExchangeSummary:
    """The values of one traced exchange between the device and Bob.

    The device always plays Alice's role in this section.

    Attributes:
        device_private_key: The device's exponent (``a1`` or ``a2``).
        device_key_generated: Whether the exponent was sampled during the
            exchange (``False`` if it existed before it started).
        device_public_key: The device's public key sent over the network.
        peer_private_key: Bob's exponent (``b1`` or ``b2``).
        peer_public_key: Bob's public key sent over the network.
        device_shared_secret: The secret computed by the device.
        peer_shared_secret: The secret computed by Bob.
    """

    device_private_key: int
    device_key_generated: bool
    device_public_key: int
    peer_private_key: int
    peer_public_key: int
    device_shared_secret: int
    peer_shared_secret: int


def summarize_exchange(events: tuple[ProtocolEvent, ...]) -> ExchangeSummary:
    """Extract the values of an exchange from its timeline.

    Args:
        events: The timeline of an exchange where the device is Alice.

    Returns:
        The summary of the exchange.

    Raises:
        LookupError: If the timeline lacks one of the expected events.
    """

    def field(event_type: ProtocolEventType, actor: Actor, key: str) -> int:
        for event in events:
            if event.event_type is event_type and event.actor is actor:
                value = event.data[key]
                if not isinstance(value, int):
                    raise TypeError(f"Event field {key!r} is not an integer.")
                return value
        raise LookupError(f"No {event_type} event for {actor}.")

    return ExchangeSummary(
        device_private_key=field(
            ProtocolEventType.PUBLIC_KEY_COMPUTED, Actor.ALICE, "exponent"
        ),
        device_key_generated=any(
            event.event_type is ProtocolEventType.PRIVATE_KEY_GENERATED
            and event.actor is Actor.ALICE
            for event in events
        ),
        device_public_key=field(
            ProtocolEventType.PUBLIC_KEY_SENT, Actor.ALICE, "public_key"
        ),
        peer_private_key=field(
            ProtocolEventType.PUBLIC_KEY_COMPUTED, Actor.BOB, "exponent"
        ),
        peer_public_key=field(
            ProtocolEventType.PUBLIC_KEY_SENT, Actor.BOB, "public_key"
        ),
        device_shared_secret=field(
            ProtocolEventType.SHARED_SECRET_COMPUTED, Actor.ALICE, "shared_secret"
        ),
        peer_shared_secret=field(
            ProtocolEventType.SHARED_SECRET_COMPUTED, Actor.BOB, "shared_secret"
        ),
    )


def _substituted(symbolic: str, concrete: str, *values: int) -> str:
    """Return ``concrete`` if every value is small enough, else ``symbolic``."""
    return concrete if is_small(*values) else symbolic


def power_formula(
    result_symbol: str,
    base_symbol: str,
    exponent_symbol: str,
    *,
    base: int,
    exponent: int,
    prime: int,
    result: int,
) -> str:
    """Return the LaTeX of ``result = base^exponent mod p``.

    Concrete values are substituted only when they are small enough.

    Args:
        result_symbol: The LaTeX symbol of the result.
        base_symbol: The LaTeX symbol of the base.
        exponent_symbol: The LaTeX symbol of the exponent.
        base: The value of the base.
        exponent: The value of the exponent.
        prime: The prime modulus p.
        result: The value of the result.
    """
    return _substituted(
        rf"{result_symbol} = {base_symbol}^{{{exponent_symbol}}} \bmod p",
        rf"{result_symbol} = {base}^{{{exponent}}} \bmod {prime} = {result}",
        base,
        exponent,
        prime,
        result,
    )


def z_formula(
    *,
    generator: int,
    previous_private_key: int,
    correction_w: int,
    correction_bit: int,
    attacker_public_key: int,
    multiplier_a: int,
    offset_b: int,
    prime: int,
    z: int,
) -> str:
    """Return the LaTeX of the device's computation of ``z``.

    Args:
        generator: The generator g.
        previous_private_key: The previous exponent of the device.
        correction_w: The constant W.
        correction_bit: The bit t.
        attacker_public_key: The attacker's public key Y.
        multiplier_a: The constant alpha (the paper's a).
        offset_b: The constant beta (the paper's b).
        prime: The prime modulus p.
        z: The resulting value z.
    """
    return _substituted(
        r"z = g^{\,a_1 - W t} \cdot Y^{\,-\alpha a_1 - \beta} \bmod p",
        rf"z = {generator}^{{\,{previous_private_key} - {correction_w} "
        rf"\cdot {correction_bit}}} \cdot {attacker_public_key}^{{\,-{multiplier_a}"
        rf" \cdot {previous_private_key} - {offset_b}}} \bmod {prime} = {z}",
        generator,
        previous_private_key,
        correction_w,
        attacker_public_key,
        multiplier_a,
        offset_b,
        prime,
        z,
    )


def hash_formula(
    result_symbol: str, argument_symbol: str, *, z: int, result: int
) -> str:
    """Return the LaTeX of ``result = H(argument)``.

    Args:
        result_symbol: The LaTeX symbol of the result.
        argument_symbol: The LaTeX symbol of the argument.
        z: The value of the argument.
        result: The value of the result.
    """
    return _substituted(
        rf"{result_symbol} = H({argument_symbol})",
        rf"{result_symbol} = H({argument_symbol}) = H({z}) = {result}",
        z,
        result,
    )


def r_formula(
    *,
    first_public_key: int,
    multiplier_a: int,
    generator: int,
    offset_b: int,
    prime: int,
    r: int,
    first_symbol: str = "A_1",
) -> str:
    """Return the LaTeX of the attacker's computation of ``r``.

    Args:
        first_public_key: The device's previous public key.
        multiplier_a: The constant alpha (the paper's a).
        generator: The generator g.
        offset_b: The constant beta (the paper's b).
        prime: The prime modulus p.
        r: The resulting value r.
        first_symbol: The LaTeX symbol of the previous public key.
    """
    return _substituted(
        rf"r = {{{first_symbol}}}^{{\alpha}} \cdot g^{{\beta}} \bmod p",
        rf"r = {first_public_key}^{{{multiplier_a}}} \cdot {generator}^{{{offset_b}}}"
        rf" \bmod {prime} = {r}",
        first_public_key,
        multiplier_a,
        generator,
        offset_b,
        prime,
        r,
    )


def z1_formula(
    *,
    first_public_key: int,
    r: int,
    attacker_private_key: int,
    prime: int,
    z1: int,
    first_symbol: str = "A_1",
) -> str:
    """Return the LaTeX of the attacker's first candidate ``z1``.

    Args:
        first_public_key: The device's previous public key.
        r: The value r.
        attacker_private_key: The attacker's private key X.
        prime: The prime modulus p.
        z1: The resulting candidate.
        first_symbol: The LaTeX symbol of the previous public key.
    """
    return _substituted(
        rf"z_1 = \frac{{{first_symbol}}}{{r^{{X}}}} \bmod p",
        rf"z_1 = \frac{{{first_public_key}}}{{{r}^{{{attacker_private_key}}}}}"
        rf" \bmod {prime} = {z1}",
        first_public_key,
        r,
        attacker_private_key,
        prime,
        z1,
    )


def z2_formula(
    *,
    z1: int,
    generator: int,
    correction_w: int,
    prime: int,
    z2: int,
) -> str:
    """Return the LaTeX of the attacker's second candidate ``z2``.

    Args:
        z1: The first candidate.
        generator: The generator g.
        correction_w: The constant W.
        prime: The prime modulus p.
        z2: The resulting candidate.
    """
    return _substituted(
        r"z_2 = \frac{z_1}{g^{W}} \bmod p",
        rf"z_2 = \frac{{{z1}}}{{{generator}^{{{correction_w}}}}} \bmod {prime}"
        rf" = {z2}",
        z1,
        generator,
        correction_w,
        prime,
        z2,
    )


def build_setup_intro_content() -> str:
    """Return the introduction of the SETUP section as Markdown."""
    content = ContentComposer()

    content.paragraph(
        "Alice does not compute Diffie-Hellman by hand: a device does it for "
        "her (a hardware module, a VPN appliance, a closed-source library). "
        "Every exchange it performs succeeds, every public key it sends is "
        "valid, and nothing in its output looks wrong. Yet its designer "
        "planted a ",
        content.bold("SETUP"),
        " (Secretly Embedded Trapdoor with Universal Protection): a backdoor "
        "that lets the designer, and ",
        content.italic("only"),
        " the designer, read Alice's secrets.",
    )

    content.paragraph(
        "This section follows the construction of Young and Yung on "
        "Diffie-Hellman from the ",
        content.bold("attacker's point of view"),
        ". Read the idea first, then the mathematics that make it work, and "
        "finally run it yourself and watch the attacker recover a secret "
        "that the protocol was supposed to protect.",
    )

    content.block(
        CalloutComposer.note(
            content=(
                "This section builds on the honest Diffie-Hellman section. If "
                "the public parameters, private keys and shared secrets of a "
                "normal exchange are not familiar yet, start there."
            ),
            title="Before you start",
        )
    )

    return content.build()


def build_setup_concept_content() -> str:
    """Return the explanation of what a SETUP is, as Markdown."""
    content = ContentComposer()

    content.h2("What is a SETUP?")

    content.paragraph(
        "Young and Yung introduced ",
        content.bold("kleptography"),
        " to study attacks that use cryptography against cryptography. Its "
        "central object is the ",
        content.bold("SETUP"),
        " mechanism: an algorithmic modification of a well-known "
        "cryptosystem, hidden inside a device that its users cannot inspect. "
        "Paraphrasing their definition, a SETUP has these properties:",
    )

    content.ordered_list(
        [
            (
                "**Same interface.** The modified device takes the same inputs "
                "and produces outputs that follow the same public specification "
                "as the original cryptosystem."
            ),
            (
                "**Only a public key inside.** The device contains the "
                "attacker's *public* key $Y$ and uses it to hide information "
                "in its outputs."
            ),
            (
                "**The trapdoor stays outside.** The matching private key $X$ "
                "is never in the device: only the attacker holds it."
            ),
            (
                "**Indistinguishable outputs.** Nobody except the attacker "
                "can tell, in reasonable (polynomial) time, the outputs of the "
                "modified device from those of an honest one."
            ),
            (
                "**Universal protection.** Even someone who reverse-engineers "
                "the device and finds the SETUP cannot recover the leaked "
                "keys: they only find $Y$, never $X$."
            ),
        ]
    )

    content.block(
        CalloutComposer.info(
            content=(
                "The list above paraphrases the definition of the paper. Young "
                "and Yung also distinguish <strong>weak</strong>, "
                "<strong>regular</strong> and <strong>strong</strong> SETUPs, "
                "depending on who is able to tell the outputs apart. Refer to "
                "the paper for the precise definitions."
            ),
            title="Paraphrased definition",
        )
    )

    content.h3("Why a public key makes the difference")

    content.paragraph(
        "A naive backdoor would embed a secret in the device, for example a "
        "symmetric key used to encrypt Alice's private keys, or a predictable "
        "random number generator. Whoever opens the device finds that secret "
        "and can use the backdoor too, or can even prove it exists. A SETUP "
        "only embeds a public key, so opening the device reveals *how* the "
        "leak works but not how to read it. That is the "
        "*universal protection* in its name: the backdoor is exclusive to "
        "its owner.",
    )

    content.h3("Who is who")

    content.paragraph(
        "| Role | What they know | What they want |\n"
        "| --- | --- | --- |\n"
        "| **Alice's device** | $Y$, $\\alpha$, $\\beta$, $W$, $H$ and its own private "
        "keys $a_1$, $a_2$ | Leak $a_2$ to the attacker without being noticed |\n"
        "| **Alice** | Her public keys and shared secrets | A private "
        "conversation with Bob |\n"
        "| **Bob** (honest) | His keys $b_1$, $b_2$ and the shared secrets | A "
        "private conversation with Alice |\n"
        "| **Eve** (eavesdropper) | Every public value: $p$, $g$, $A_1$, $B_1$, "
        "$A_2$, $B_2$ | The shared secrets, but she has no trapdoor |\n"
        "| **Attacker** | What Eve knows, plus $X$ and the device's constants "
        "| The shared secret $s_2$ |"
    )

    content.h2("How much leaks: (m, n)-leakage schemes")

    content.paragraph(
        "Young and Yung measure the bandwidth of a SETUP with the notion of an ",
        content.bold("(m, n)-leakage scheme"),
        ": a SETUP that leaks ",
        content.math("m"),
        " keys (or secret messages) over ",
        content.math("n"),
        " keys output by the device, with ",
        content.math(r"m \le n"),
        ". A SETUP that leaks one key in every output it produces is a "
        "(1,1)-leakage scheme.",
    )

    content.paragraph(
        "The Diffie-Hellman SETUP is a ",
        content.bold("(1,2)-leakage scheme"),
        ": over two public keys output by the device, the attacker learns ",
        content.bold("one"),
        " private key.",
    )

    content.paragraph(
        "| | Exchange 1 | Exchange 2 |\n"
        "| --- | --- | --- |\n"
        "| Device's private key | $a_1$, truly random | $a_2 = H(z)$, derived "
        "from $a_1$ and $Y$ |\n"
        "| Public key sent | $A_1 = g^{a_1}$ | $A_2 = g^{a_2}$ |\n"
        "| Role in the leak | **Carrier**: lets the attacker compute $z$ | "
        "**Victim**: its key is recovered |\n"
        "| Can the attacker read the shared secret? | No: it would have to "
        "solve a discrete logarithm | **Yes** |"
    )

    content.paragraph(
        "A Diffie-Hellman public key $g^{x}$ cannot carry information about "
        "its own exponent without giving it away. Instead, the device makes "
        "the *next* exponent predictable for the attacker from the *previous* "
        "public key. One output is spent as the carrier, and the key of the "
        "other one leaks: one key out of two.",
    )

    content.h2("Why is it so hard to detect?")

    content.bullet_list(
        [
            (
                "Every public key is a valid element of the subgroup, so it "
                "passes exactly the same checks as an honest one."
            ),
            "Every exchange succeeds: Alice and Bob always share the same secret.",
            (
                "$a_2$ is the output of a hash function, so it looks as random "
                "as a freshly sampled key."
            ),
            (
                "Recognizing the link between $A_1$ and $A_2$ without $X$ is, "
                "informally, as hard as the Diffie-Hellman problem the "
                "exchange itself relies on."
            ),
            (
                "Reverse-engineering the device reveals $Y$, $\\alpha$, $\\beta$, "
                "$W$ and $H$: enough to learn that a backdoor exists, never enough to "
                "use it."
            ),
        ]
    )

    content.h2("What is at stake")

    content.paragraph(
        "In a real protocol, the shared secret is not used directly: it is "
        "fed to a key derivation function that produces the keys encrypting "
        "the conversation. An attacker who knows $s_2$ derives the same keys "
        "and reads, or even alters, everything protected by the second "
        "exchange. The cryptography did not fail: the device was working "
        "*for someone else* from the start."
    )

    content.block(CalloutComposer.info(content=REFERENCE, title="Reference"))

    return content.build()


def build_setup_formulae_content() -> str:
    """Return the complete mathematical development of the SETUP."""
    content = ContentComposer()

    content.h2("Notation")

    content.paragraph(
        "| Symbol | Meaning | Who knows it |\n"
        "| --- | --- | --- |\n"
        "| $p,\\ g,\\ q$ | Public group: prime $p = 2q + 1$, generator $g$ of "
        "order $q$ | Everyone |\n"
        "| $X$ | Attacker's private key, $1 \\le X \\le q - 1$ | Attacker |\n"
        "| $Y = g^{X}$ | Attacker's public key | Device, attacker |\n"
        "| $\\alpha,\\ \\beta,\\ W$ | Constants of the SETUP ($W$ odd) | Device, "
        "attacker |\n"
        "| $H$ | Hash function mapping group elements to exponents | Device, "
        "attacker |\n"
        "| $a_1,\\ a_2$ | Device's private keys in exchanges 1 and 2 | Device |\n"
        "| $A_1,\\ A_2$ | Device's public keys, $A_i = g^{a_i}$ | Everyone |\n"
        "| $t$ | Random correction bit, $t \\in \\{0, 1\\}$ | Device |\n"
        "| $b_1,\\ b_2$ / $B_1,\\ B_2$ | Bob's private / public keys | Bob / "
        "everyone |\n"
        "| $s_1,\\ s_2$ | Shared secrets of exchanges 1 and 2 | Alice, Bob "
        "(and the attacker, for $s_2$) |"
    )

    content.paragraph(
        "The protocol roles use the notation of the honest Diffie-Hellman "
        "section: the device plays Alice (",
        content.math("a_i"),
        ", ",
        content.math("A_i"),
        ") and Bob keeps ",
        content.math("b_i"),
        ", ",
        content.math("B_i"),
        ". Young and Yung present the construction next to their ElGamal "
        "SETUP and use different letters, so this is how the symbols map to "
        "the paper:",
    )

    content.paragraph(
        "| Here | In the paper | Meaning |\n"
        "| --- | --- | --- |\n"
        "| $a_1,\\ a_2$ | $c_1,\\ c_2$ | Device's private keys |\n"
        "| $A_1,\\ A_2$ | $m_1,\\ m_2$ | Device's public keys |\n"
        "| $\\alpha,\\ \\beta$ | $a,\\ b$ | Constants of the SETUP |\n"
        "| $X,\\ Y,\\ W,\\ t,\\ H,\\ z$ | Same | Unchanged |"
    )

    content.paragraph(
        "Greek letters keep the constants apart from the keys, so that in ",
        content.math(r"\alpha a_1 + \beta"),
        " the constants are clearly not the keys of Alice or Bob.",
    )

    content.h2("Arithmetic in a subgroup of prime order")

    content.paragraph(
        "Every value lives in the subgroup generated by ",
        content.math("g"),
        ", which has ",
        content.math("q"),
        " elements. Since ",
        content.math(r"g^{q} \equiv 1"),
        ", exponents can be reduced modulo ",
        content.math("q"),
        "; a negative exponent means the inverse modulo ",
        content.math("p"),
        ", and dividing means multiplying by that inverse:",
    )

    content.formula(
        r"g^{e} \equiv g^{\,e \bmod q}, \qquad "
        r"g^{-e} \equiv \left(g^{e}\right)^{-1}, \qquad "
        r"\frac{u}{v} \equiv u \cdot v^{-1} \pmod{p}"
    )

    content.paragraph(
        "The rule that makes Diffie-Hellman work is also the one that makes "
        "the SETUP work: exponents multiply, so the order in which two "
        "exponents are applied does not matter.",
    )

    content.formula(r"\left(g^{u}\right)^{v} = g^{uv} = \left(g^{v}\right)^{u}")

    content.h2("What the device computes")

    content.ordered_list(
        [
            (
                "**Exchange 1.** Pick a random $a_1 \\in [1, q - 1]$ and send "
                "$A_1 = g^{a_1} \\bmod p$."
            ),
            "**Correction bit.** Pick a random bit $t \\in \\{0, 1\\}$.",
            (
                "**Hidden value.** Compute "
                "$z = g^{\\,a_1 - W t} \\cdot Y^{\\,-\\alpha a_1 - \\beta} \\bmod p$."
            ),
            "**Next key.** Set $a_2 = H(z)$.",
            "**Exchange 2.** Send $A_2 = g^{a_2} \\bmod p$.",
        ]
    )

    content.h2("What the attacker computes")

    content.paragraph(
        "The attacker only uses public values, the constants and ", "$X$:"
    )

    content.ordered_list(
        [
            "$r = A_1^{\\alpha} \\cdot g^{\\beta} \\bmod p$.",
            "$z_1 = A_1 / r^{X} \\bmod p$.",
            (
                "If $g^{H(z_1)} \\equiv A_2$, then $a_2 = H(z_1)$. Otherwise "
                "$z_2 = z_1 / g^{W} \\bmod p$ and $a_2 = H(z_2)$."
            ),
            "$s_2 = B_2^{a_2} \\bmod p$, where $B_2$ is Bob's second public key.",
        ]
    )

    content.h2("Why the attacker recovers the key")

    content.paragraph(
        content.bold("1. The value r."),
        " Substituting ",
        content.math("A_1 = g^{a_1}"),
        " shows that ",
        content.math("r"),
        " is a power of ",
        content.math("g"),
        " whose exponent depends on the secret ",
        content.math("a_1"),
        ":",
    )
    content.formula(
        r"r = A_1^{\alpha} \cdot g^{\beta}"
        r" = \left(g^{a_1}\right)^{\alpha} \cdot g^{\beta}"
        r" = g^{\,\alpha a_1 + \beta}"
    )

    content.paragraph(
        content.bold("2. The mask."),
        " Raising ",
        content.math("r"),
        " to ",
        content.math("X"),
        " gives the same value as raising ",
        content.math("Y"),
        " to ",
        content.math(r"\alpha a_1 + \beta"),
        ". The attacker can compute the left side (it knows ",
        content.math("X"),
        "); the device can compute the right side (it knows ",
        content.math("a_1"),
        "):",
    )
    content.formula(
        r"r^{X} = \left(g^{\,\alpha a_1 + \beta}\right)^{X}"
        r" = \left(g^{X}\right)^{\alpha a_1 + \beta} = Y^{\,\alpha a_1 + \beta}"
    )

    content.paragraph(
        content.bold("3. Unmasking z."),
        " Rewrite the device's formula for ",
        content.math("z"),
        " by splitting its two factors:",
    )
    content.formula(
        r"z = g^{\,a_1 - W t} \cdot Y^{\,-\alpha a_1 - \beta}"
        r" = \frac{g^{a_1}}{Y^{\,\alpha a_1 + \beta}} \cdot g^{-W t}"
        r" = \frac{A_1}{r^{X}} \cdot g^{-W t} = z_1 \cdot g^{-W t}"
    )

    content.paragraph(
        content.bold("4. The correction bit."),
        " The attacker does not know ",
        content.math("t"),
        ", but it only has two possible values, so ",
        content.math("z"),
        " is one of two candidates:",
    )
    content.formula(
        r"t = 0 \;\Rightarrow\; z = z_1, \qquad "
        r"t = 1 \;\Rightarrow\; z = \frac{z_1}{g^{W}} = z_2"
    )

    content.paragraph(
        content.bold("5. Picking the right candidate."),
        " Hashing gives two candidate keys, ",
        content.math("H(z_1)"),
        " and ",
        content.math("H(z_2)"),
        ". The attacker saw ",
        content.math("A_2 = g^{a_2}"),
        " on the network, so the correct one is the candidate ",
        content.math(r"\hat{a}_i = H(z_i)"),
        " with ",
        content.math(r"g^{\hat{a}_i} \equiv A_2"),
        ":",
    )
    content.formula(r"a_2 = H(z), \qquad g^{\hat{a}_i} \overset{?}{\equiv} A_2")

    content.paragraph(
        content.bold("6. The shared secret."),
        " With ",
        content.math("a_2"),
        " the attacker does what Alice does:",
    )
    content.formula(r"s_2 = B_2^{a_2} = \left(g^{b_2}\right)^{a_2} = g^{b_2 a_2}")

    content.h2("A Diffie-Hellman exchange hidden inside another")

    content.paragraph(
        "Step 2 is the heart of the construction, and it is Diffie-Hellman "
        "itself. The device and the attacker agree on a shared value without "
        "ever talking to each other: ",
        content.math(r"r = g^{\alpha a_1 + \beta}"),
        " plays the role of the device's public key, which anyone can compute from ",
        content.math("A_1"),
        ", and ",
        content.math("Y = g^X"),
        " plays the role of the attacker's public key. Their shared value is "
        "the mask that hides ",
        content.math("z"),
        ":",
    )
    content.formula(
        r"\underbrace{Y^{\,\alpha a_1 + \beta}}_{\text{device}}"
        r" \;=\; g^{X (\alpha a_1 + \beta)} \;=\;"
        r" \underbrace{r^{X}}_{\text{attacker}}"
        r"\qquad\text{just like}\qquad"
        r"\underbrace{B_1^{a_1}}_{\text{Alice}} = g^{a_1 b_1}"
        r" = \underbrace{A_1^{b_1}}_{\text{Bob}}"
    )

    content.h2("Why nobody else can do it")

    content.paragraph(
        "Eve, and even someone who reverse-engineered the device and knows ",
        content.math(r"\alpha"),
        ", ",
        content.math(r"\beta"),
        ", ",
        content.math("W"),
        ", ",
        content.math("Y"),
        " and ",
        content.math("H"),
        ", can compute ",
        content.math("r"),
        ". To remove the mask they would need ",
        content.math("r^X"),
        " knowing only ",
        content.math(r"r = g^{\alpha a_1 + \beta}"),
        " and ",
        content.math("Y = g^X"),
        ". Computing ",
        content.math("g^{uv}"),
        " from ",
        content.math("g^u"),
        " and ",
        content.math("g^v"),
        " is exactly the ",
        content.bold("computational Diffie-Hellman problem"),
        ": the same problem that protects an honest exchange.",
    )

    content.block(
        CalloutComposer.warning(
            content=(
                "In the toy groups of the experiment, anyone can find "
                "<em>X</em> from <em>Y</em> by brute force, and with it use "
                "the backdoor. The protection of a SETUP is only as strong as "
                "the group it lives in."
            ),
            title="Only in a properly sized group",
        )
    )

    content.h2("One key out of two: a (1,2)-leakage scheme")

    content.paragraph(
        "In the terminology of Young and Yung, a SETUP is an ",
        content.bold("(m, n)-leakage scheme"),
        " when the attacker recovers ",
        content.math("m"),
        " private keys from ",
        content.math("n"),
        " public keys output by the device. This SETUP is a ",
        content.bold("(1,2)-leakage scheme"),
        ": from the two public keys ",
        content.math("A_1"),
        " and ",
        content.math("A_2"),
        ", the attacker recovers exactly one private key, ",
        content.math("a_2"),
        ".",
    )
    content.formula(
        r"\underbrace{(A_1,\ A_2)}_{n\,=\,2\ \text{public keys}}"
        r"\;\xrightarrow{\;\;X\;\;}\;"
        r"\underbrace{a_2}_{m\,=\,1\ \text{private key}}"
        r"\qquad a_1 \ \text{stays secret}"
    )

    content.paragraph(
        "The first key is the price of the leak. ",
        content.math("a_1"),
        " is truly random, and ",
        content.math("A_1 = g^{a_1}"),
        " is only used as a carrier: nothing in the construction reveals ",
        content.math("a_1"),
        " to the attacker. Computing ",
        content.math("s_1"),
        " from the transcript still requires solving the discrete logarithm "
        "(or Diffie-Hellman) problem. A Diffie-Hellman public key cannot "
        "carry its own exponent without giving it away, so one output must "
        "be spent as the carrier of the next one: that is why the bandwidth "
        "is one key out of two, and not one out of one.",
    )

    content.h2("Worked example")

    content.paragraph(
        "A tiny example that can be checked by hand. To keep the numbers "
        "small, the hash is replaced by the ",
        content.bold("toy function"),
        " ",
        content.math(r"H(v) = (v \bmod 10) + 1"),
        ", which is an educational simplification with no security at all. "
        "These are the same values used by the project's tests.",
    )

    content.formula(
        r"\begin{aligned}"
        r"&\text{Group:} && p = 23,\ g = 2,\ q = 11 \\"
        r"&\text{Attacker:} && X = 3,\quad Y = 2^{3} = 8 \\"
        r"&\text{Constants:} && \alpha = 2,\ \beta = 2,\ W = 3 \\"
        r"&\text{Exchange 1:} && a_1 = 6,\quad A_1 = 2^{6} \bmod 23 = 18 \\"
        r"&\text{Device } (t = 0)\text{:} && "
        r"z = 2^{6} \cdot 8^{-14} \bmod 23 = 18 \cdot 4 \bmod 23 = 3 \\"
        r"& && a_2 = H(3) = 4,\quad A_2 = 2^{4} \bmod 23 = 16 \\"
        r"&\text{Bob:} && b_2 = 7,\quad B_2 = 2^{7} \bmod 23 = 13 \\"
        r"&\text{Shared secret:} && s_2 = 13^{4} \bmod 23 = 18"
        r"\end{aligned}"
    )

    content.paragraph(
        "The attacker only sees ", "$A_1 = 18$, $A_2 = 16$ and $B_2 = 13$:"
    )

    content.formula(
        r"\begin{aligned}"
        r"r &= 18^{2} \cdot 2^{2} \bmod 23 = 8, \qquad r^{X} = 8^{3} \bmod 23 = 6 \\"
        r"z_1 &= 18 / 6 \bmod 23 = 3 \;\Rightarrow\; H(3) = 4,"
        r"\quad 2^{4} \bmod 23 = 16 = A_2 \ \checkmark \\"
        r"s_2 &= 13^{4} \bmod 23 = 18 \ \checkmark"
        r"\end{aligned}"
    )

    content.paragraph(
        "Had the device drawn ",
        content.math("t = 1"),
        ", it would have computed ",
        content.math(r"z = 2^{6 - 3} \cdot 8^{-14} \bmod 23 = 9"),
        ", ",
        content.math("a_2 = H(9) = 10"),
        " and ",
        content.math("A_2 = 2^{10} \\bmod 23 = 12"),
        ". The attacker's first candidate fails (",
        content.math(r"16 \ne 12"),
        "), and the second one, ",
        content.math(r"z_2 = 3 / 2^{3} \bmod 23 = 9"),
        ", gives ",
        content.math("H(9) = 10"),
        " and ",
        content.math(r"2^{10} \bmod 23 = 12 = A_2"),
        ".",
    )

    content.h2("Implementation choices")

    content.bullet_list(
        [
            (
                "**The hash $H$.** The paper uses a hash function that maps $z$ "
                "to an exponent. This project instantiates it with SHAKE-256 "
                "over a domain tag and the fixed-width encoding of $z$, "
                "reduced to $[1, q - 1]$. That instantiation is the project's "
                "choice."
            ),
            (
                "**The group.** The experiment works in the subgroup of prime "
                "order $q$ of a safe prime."
            ),
            (
                "**Only two exchanges.** The experiment runs exactly the "
                "setting of the (1,2)-leakage scheme: one exchange as the "
                "carrier and one with the leaked key. If asked for more keys, "
                "this implementation derives each one from the previous one."
            ),
        ]
    )

    return content.build()


def build_backdoor_content() -> str:
    """Return the explanation of what an inspection of the device reveals."""
    return CalloutComposer.warning(
        content=(
            "Someone who opens the device finds <em>Y</em>, <em>α</em>, "
            "<em>β</em>, <em>W</em> and <em>H</em>. That is enough to prove "
            "that a backdoor exists, but not to use it: the private key "
            "<em>X</em> was never inside."
        ),
        title="What a reverse engineer would find",
    ).build()


def build_setup_observers_content() -> str:
    """Return the comparison between Eve and the attacker."""
    return CalloutComposer.danger(
        content=(
            "<strong>Eve</strong> sees these four values and can do nothing "
            "with them without solving a discrete logarithm. The "
            "<strong>attacker</strong> sees the very same four values, but "
            "with <em>X</em> it can link <em>A<sub>1</sub></em> to "
            "<em>a<sub>2</sub></em>. Nothing in the messages tells them apart "
            "from an honest transcript."
        ),
        title="Same messages, different knowledge",
    ).build()


def build_setup_leakage_content() -> str:
    """Return the closing explanation of the (1,2)-leakage."""
    return CalloutComposer.info(
        content=(
            "The attacker has <em>a<sub>2</sub></em> and <em>s<sub>2</sub></em>, "
            "but not <em>a<sub>1</sub></em> or <em>s<sub>1</sub></em>: the first "
            "public key was spent carrying the information. One key leaked out "
            "of the two the device produced, which makes this a "
            "<strong>(1,2)-leakage scheme</strong>. Any key derived from "
            "<em>s<sub>2</sub></em> to encrypt the conversation is now in the "
            "attacker's hands."
        ),
        title="One key out of two",
    ).build()
