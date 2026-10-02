"""Educational content for the encrypted channel compromised by the SETUP.

The section extends the Young–Yung case study from a key exchange to a
complete secure channel: ephemeral Diffie-Hellman, a key derivation function
and authenticated encryption, run over several sessions. It is told from two
points of view: a participant, who uses the channel legitimately, and the
attacker, who only sees public data plus its trapdoor. This module holds the
text and LaTeX; it never performs cryptographic computations.

Notation follows the SETUP section: the device plays Alice, with private
keys ``a_i`` and public keys ``A_i`` in session ``i``; Bob has ``b_i`` and
``B_i``; the shared secret is ``s_i`` and the session key ``K_i``. A message
``m`` is encrypted with a nonce ``n`` into a ciphertext ``c`` and a tag
``tau``.
"""

from __future__ import annotations

from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.composer import ContentComposer
from kleptography.app.content.diffie_hellman import StepDefinition
from kleptography.app.content.young_yung_setup import REFERENCE

CIPHERSUITE_NAME = "KLEPTO_DHE_FFDHE_WITH_AES_256_GCM_SHA256"
"""An illustrative name for the channel's ciphersuite, in the style of TLS."""

STANDARDS = (
    "NIST SP 800-56C Rev. 2, <em>Recommendation for Key-Derivation Methods in "
    "Key-Establishment Schemes</em> (one-step KDF), 2020.<br>"
    "NIST SP 800-38D, <em>Recommendation for Block Cipher Modes of Operation: "
    "Galois/Counter Mode (GCM) and GMAC</em>, 2007.<br>"
    "RFC 7919, <em>Negotiated Finite Field Diffie-Hellman Ephemeral Parameters "
    "for TLS</em>, 2016."
)


DEFAULT_MESSAGES: tuple[tuple[str, str], ...] = (
    ("Hi Bob, are we still on for tomorrow?", "Yes. Meeting at 10:00 in room B."),
    ("The access code for the lab is 4721.", "Thanks, I will change it next week."),
    ("Budget approved: 25 000 EUR for Q3.", "Great news, I will tell the team."),
    ("Please keep this between us.", "Understood, it stays here."),
    ("Last one: delete the draft.", "Done. Talk to you tomorrow."),
)
"""Default texts of each session: (Alice to Bob, Bob to Alice)."""


def session_step_definitions(number: int) -> tuple[StepDefinition, ...]:
    """Return the three explanatory steps of session ``number``.

    Args:
        number: The session number, starting at 1.

    Returns:
        The key exchange, key derivation and messages steps, with the
        session index substituted into their formulas.
    """
    i = number
    return (
        StepDefinition(
            title="Ephemeral key exchange",
            explanation=(
                "Alice's device and Bob generate brand-new key pairs for this "
                "session and run an ordinary Diffie-Hellman exchange. Both "
                "end up with the same shared secret."
            ),
            formula=(
                rf"A_{i} = g^{{a_{i}}}, \quad B_{i} = g^{{b_{i}}}, \qquad "
                rf"s_{i} = B_{i}^{{a_{i}}} = A_{i}^{{b_{i}}} \bmod p"
            ),
        ),
        StepDefinition(
            title="Session key derivation",
            explanation=(
                "Each party encodes its shared secret as a fixed-length "
                "big-endian byte string $Z$ (as long as $p$) and hashes it "
                "with a counter and a fixed label, $\\mathit{OtherInfo}$. "
                "Nothing random is involved: equal secrets give equal keys."
            ),
            formula=(
                rf"K_{i} = \mathrm{{SHA\text{{-}}256}}(\texttt{{00000001}} "
                rf"\,\Vert\, Z_{i} \,\Vert\, \mathit{{OtherInfo}})"
            ),
        ),
        StepDefinition(
            title="Encrypted messages",
            explanation=(
                f"The sender encrypts each message under $K_{i}$ with a fresh "
                "random nonce $n$. The nonce, the ciphertext $c$ and the tag "
                "$\\tau$ travel over the network. The recipient decrypts "
                "with its own copy of the key; the tag proves that the "
                "message was not modified and that both keys are equal."
            ),
            formula=(
                rf"(c,\ \tau) = \mathrm{{AES\text{{-}}GCM}}_{{K_{i}}}(n,\ m)"
                rf" \qquad m = \mathrm{{AES\text{{-}}GCM}}^{{-1}}_{{K_{i}}}"
                rf"(n,\ c,\ \tau)"
            ),
        ),
    )


def build_channel_intro_content() -> str:
    """Return the introduction of the encrypted channel section as Markdown."""
    content = ContentComposer()

    content.paragraph(
        "Nobody uses Diffie-Hellman just to agree on a number. Real protocols "
        "such as TLS, SSH or IPsec turn the shared secret into a ",
        content.bold("session key"),
        " and use it to encrypt the conversation. This section builds such a "
        "channel between Alice and Bob, over several sessions, and puts the "
        "compromised device of the previous section inside it.",
    )

    content.paragraph(
        "The result is the real stake of a SETUP: the attacker does not break "
        "AES, SHA-256 or Diffie-Hellman, and yet it reads the conversation. "
        "You will see it from two points of view: a ",
        content.bold("participant"),
        ", who uses the channel exactly as intended, and the ",
        content.bold("attacker"),
        ", who only sees the traffic on the network and holds a trapdoor.",
    )

    content.block(
        CalloutComposer.note(
            content=(
                "This section builds on the Young–Yung SETUP section: how the "
                "device derives a new private key from the previous one, and "
                "how the attacker recovers it. If that is not familiar yet, "
                "start there."
            ),
            title="Before you start",
        )
    )

    return content.build()


def build_channel_concept_content() -> str:
    """Return the explanation of the channel and how the SETUP breaks it."""
    content = ContentComposer()

    content.h2("From a key exchange to a secure channel")

    content.paragraph(
        "Alice and Bob talk in ",
        content.bold("sessions"),
        ". Every session starts with a fresh Diffie-Hellman exchange: both "
        "parties generate new, ",
        content.italic("ephemeral"),
        " key pairs, which are thrown away when the session ends. Each party "
        "then derives the session key from its shared secret, and every "
        "message of the session is encrypted under that key.",
    )

    content.formula(
        r"A_i = g^{a_i},\quad B_i = g^{b_i},\qquad "
        r"s_i = B_i^{a_i} = A_i^{b_i} \bmod p,\qquad K_i = \mathrm{KDF}(s_i)"
    )
    content.formula(
        r"(c,\ \tau) = \mathrm{AES\text{-}GCM}_{K_i}(n,\ m), \qquad "
        r"m = \mathrm{AES\text{-}GCM}^{-1}_{K_i}(n,\ c,\ \tau)"
    )

    content.paragraph(
        "Ephemeral keys promise that sessions are ",
        content.bold("independent"),
        ": the keys of one session reveal nothing about those of any other "
        "one. That is precisely the property the SETUP breaks.",
    )

    content.h3("The ciphersuite")

    content.paragraph(
        "Like a TLS cipher suite, the channel is fully described by the "
        "primitives it combines. Its illustrative name is ",
        content.code(CIPHERSUITE_NAME),
        ":",
    )

    content.paragraph(
        "| Component | Primitive | What it does |\n"
        "| --- | --- | --- |\n"
        "| **Key exchange** | Ephemeral finite-field Diffie-Hellman (toy or "
        "RFC 7919 group) | Gives both parties the same secret $s_i$ in every "
        "session |\n"
        "| **Key derivation** | One-step KDF of NIST SP 800-56C with SHA-256 | "
        "Turns $s_i$ into a 256-bit key: "
        "$K_i = \\mathrm{SHA\\text{-}256}(\\texttt{00000001}"
        " \\,\\Vert\\, Z \\,\\Vert\\, \\mathit{OtherInfo})$, "
        "where $Z$ is $s_i$ as a fixed-length "
        "big-endian byte string |\n"
        "| **Encryption** | AES-256-GCM (NIST SP 800-38D) | Encrypts each "
        "message with a random 96-bit nonce $n$ and authenticates it with a "
        "128-bit tag $\\tau$ |"
    )

    content.block(
        CalloutComposer.info(
            content=(
                f"<code>{CIPHERSUITE_NAME}</code> is a name made up for this "
                "application, not a registered TLS cipher suite. The "
                "primitives are standard, but the channel is educational: "
                "public keys are not authenticated, there is no replay "
                "protection and no key confirmation. Do not use it as a "
                "model for a real protocol."
            ),
            title="Illustrative ciphersuite",
        )
    )

    content.h3("What everyone knows")

    content.paragraph(
        "Following ",
        content.bold("Kerckhoffs's principle"),
        ", the whole system is public: the group, the ciphersuite, the KDF "
        "label, even the existence of the device. Security must rest on the "
        "keys alone. The nonces, ciphertexts and tags travel with each "
        "message, so they are public too.",
    )

    content.paragraph(
        "| Role | What they know | What they read |\n"
        "| --- | --- | --- |\n"
        "| **Alice** (through the device) | Her keys $a_i$, the secrets $s_i$ "
        "and the keys $K_i$ | Every message |\n"
        "| **Bob** (honest) | His keys $b_i$, the secrets $s_i$ and the keys "
        "$K_i$ | Every message |\n"
        "| **Eve** (eavesdropper) | The ciphersuite, $p$, $g$, every $A_i$ "
        "and $B_i$, and every $(n, c, \\tau)$ | Nothing |\n"
        "| **Attacker** | What Eve knows, plus its private key $X$ and the "
        "device's constants $Y$, $\\alpha$, $\\beta$, $W$, $H$ | Every "
        "session but the first |"
    )

    content.h2("How the SETUP breaks the channel")

    content.paragraph(
        "The device generates Alice's ephemeral key of every session. In "
        "session 1 it behaves honestly. From session 2 on, it derives each "
        "new private key from the previous one, exactly as in the SETUP "
        "section: ",
        content.math(r"a_i = H(z_i)"),
        ", where ",
        content.math("z_i"),
        " mixes ",
        content.math("a_{i-1}"),
        " with the attacker's public key ",
        content.math("Y"),
        ". In this application the device keeps chaining: ",
        content.math("a_3"),
        " comes from ",
        content.math("a_2"),
        ", and so on.",
    )

    content.paragraph(
        "The attacker applies the recovery of the SETUP section to every "
        "pair of consecutive public keys, and then simply does what Alice "
        "does:",
    )

    content.formula(
        r"(A_{i-1},\ A_i) \xrightarrow{\ X\ } a_i "
        r"\;\longrightarrow\; s_i = B_i^{a_i} \bmod p "
        r"\;\longrightarrow\; K_i = \mathrm{KDF}(s_i) "
        r"\;\longrightarrow\; m = \mathrm{AES\text{-}GCM}^{-1}_{K_i}(n,\ c,\ \tau)"
    )

    content.paragraph(
        "No cipher is broken. SHA-256 and AES-256-GCM do exactly what they "
        "promise; the attacker simply holds the right key. The KDF has no "
        "salt and no randomness, so the key is a deterministic function of "
        "the shared secret: whoever knows ",
        content.math("s_i"),
        " knows ",
        content.math("K_i"),
        ".",
    )

    content.h3("Session 1 stays confidential")

    content.paragraph(
        "The first session has no previous public key to pair with, so its "
        "key never leaks. This is the (1,2)-leakage of the SETUP made "
        "visible at the application level:",
    )

    content.paragraph(
        "| | Session 1 | Session 2 | Session 3 | … | Session N |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| Alice's private key | $a_1$, truly random | $H(z_2)$ from $a_1$ | "
        "$H(z_3)$ from $a_2$ | … | $H(z_N)$ from $a_{N-1}$ |\n"
        "| Bob reads | Yes | Yes | Yes | … | Yes |\n"
        "| Eve reads | No | No | No | … | No |\n"
        "| Attacker reads | **No** | **Yes** | **Yes** | … | **Yes** |"
    )

    content.h3("Why nothing looks wrong")

    content.bullet_list(
        [
            (
                "Every public key is a valid element of the subgroup, and "
                "every exchange succeeds."
            ),
            (
                "Bob decrypts every message, and every authentication tag "
                "is valid: the channel works perfectly."
            ),
            (
                "Each $a_i$ is the output of a hash function, so it looks as "
                "random as a freshly sampled ephemeral key."
            ),
            (
                "Eve records exactly the same traffic as the attacker and "
                "reads nothing: without $X$, the link between $A_{i-1}$ and "
                "$A_i$ stays hidden."
            ),
        ]
    )

    content.block(
        CalloutComposer.warning(
            content=(
                "With a toy group, the shared secret has only a few bits, so "
                "anyone, Eve included, can try every possible value, derive "
                "each key and stop at the one whose GCM tag verifies. Only a "
                "standardized group makes the attacker's advantage real."
            ),
            title="Toy groups are brute-forceable",
        )
    )

    content.block(
        CalloutComposer.info(
            content=f"{REFERENCE}<br>{STANDARDS}",
            title="References",
        )
    )

    return content.build()


def build_participant_intro_content() -> str:
    """Return the introduction of the participant's point of view."""
    content = ContentComposer()

    content.paragraph(
        "Take the place of Alice and Bob. Choose a group, decide whether "
        "Alice's device is honest or carries the SETUP, write the messages "
        "of each session and run the channel. You will see everything the "
        "participants see: their ephemeral keys, the session keys and every "
        "message before and after encryption.",
    )

    content.paragraph(
        "Run it once with each device and compare: from the participants' seat, ",
        content.bold("both channels look exactly the same"),
        ".",
    )

    return content.build()


def build_device_choice_content() -> str:
    """Return the callout that explains what the device choice changes."""
    return CalloutComposer.info(
        content=(
            "The device generates Alice's ephemeral keys. An honest device "
            "picks every key at random. A compromised one picks the first "
            "key at random and derives each later key from the previous one "
            "and the attacker's public key <em>Y</em>. Neither Alice nor Bob "
            "can see this choice: it happens inside the device. The "
            "attacker's backdoor is shown in the <strong>Attacker</strong> "
            "tab."
        ),
        title="What changes inside the device",
    ).build()


def build_messages_tip_content() -> str:
    """Return the callout that invites the reader to write the messages."""
    return CalloutComposer.tip(
        content=(
            "The texts below are only examples. Click any field and write "
            "your own messages: they are encrypted exactly as you type them, "
            "and you will find them again, as ciphertext, in the "
            "<strong>Attacker</strong> tab."
        ),
        title="Write your own messages",
    ).build()


def build_indistinguishable_content() -> str:
    """Return the callout that closes the participant's point of view."""
    return CalloutComposer.note(
        content=(
            "Every session above has valid public keys, matching session "
            "keys and messages that Bob reads correctly. With an honest or a "
            "compromised device, this view is identical: nothing the "
            "participants can observe reveals the SETUP. Switch to the "
            "<strong>Attacker</strong> tab to see what the same traffic "
            "looks like from the other side."
        ),
        title="Nothing looks wrong",
    ).build()


def workbench_step_definitions(number: int) -> tuple[StepDefinition, ...]:
    """Return the four steps of the attacker's workbench for session ``number``.

    Args:
        number: The session the attacker works on, starting at 1.

    Returns:
        The recovery, shared secret, key derivation and decryption steps.
    """
    i = number
    previous = f"A_{{{i - 1}}}"
    recover_step = StepDefinition(
        title=f"Recover Alice's private key $a_{{{i}}}$",
        explanation=(
            f"Pair the public key of this session, $A_{{{i}}}$, with the "
            f"one of the previous session, ${previous}$. With $X$, the "
            "attacker removes the mask the device put on $z$, tries both "
            "values of the hidden bit $t$ and keeps the candidate whose "
            f"public key reproduces $A_{{{i}}}$."
        ),
        formula=(
            rf"r = {previous}^{{\alpha}} g^{{\beta}},\quad "
            rf"z_1 = \frac{{{previous}}}{{r^{{X}}}},\quad "
            rf"z_2 = \frac{{z_1}}{{g^{{W}}}},\quad "
            rf"\hat{{a}}_k = H(z_k),\quad g^{{\hat{{a}}_k}} \overset{{?}}{{=}} "
            rf"A_{{{i}}}"
        ),
    )
    if i == 1:
        recover_step = StepDefinition(
            title="Recover Alice's private key $a_{1}$",
            explanation=(
                "The recovery pairs each public key with the previous one, and "
                "$A_1$ has none: the device drew $a_1$ at random, as an honest "
                "one would. The only way to $a_1$ is the discrete logarithm of "
                "$A_1$, the same problem Eve faces."
            ),
            formula=r"a_1 \xleftarrow{\$} [1,\ q - 1],\quad A_1 = g^{a_1} \bmod p",
        )
    return (
        recover_step,
        StepDefinition(
            title=f"Compute the shared secret $s_{{{i}}}$",
            explanation=(
                "With a private key of Alice, the attacker computes the "
                f"shared secret exactly as she does, from Bob's public key "
                f"$B_{{{i}}}$, which travelled over the network. Type a key "
                "or use the recovered one."
            ),
            formula=rf"s_{{{i}}} = B_{{{i}}}^{{\,a_{{{i}}}}} \bmod p",
        ),
        StepDefinition(
            title=f"Derive the session key $K_{{{i}}}$",
            explanation=(
                "The KDF is public and has no secret input other than the "
                "shared secret, so the attacker runs it like any participant. "
                "Type a secret or use the computed one."
            ),
            formula=(
                rf"K_{{{i}}} = \mathrm{{SHA\text{{-}}256}}(\texttt{{00000001}} "
                rf"\,\Vert\, Z_{{{i}}} \,\Vert\, \mathit{{OtherInfo}})"
            ),
        ),
        StepDefinition(
            title="Decrypt a message with AES-256-GCM",
            explanation=(
                "Pick a message of this session: its nonce, ciphertext and tag "
                "are public. Type a 256-bit key in hexadecimal or use the "
                "derived one. AES-GCM checks the tag first: a wrong key is "
                "rejected instead of producing garbage."
            ),
            formula=(
                rf"m = \mathrm{{AES\text{{-}}GCM}}^{{-1}}_{{K_{{{i}}}}}"
                r"(n,\ c,\ \tau) \quad \text{or} \quad \bot"
            ),
        ),
    )


def build_attacker_intro_content() -> str:
    """Return the introduction of the attacker's point of view."""
    content = ContentComposer()

    content.paragraph(
        "Now take the attacker's seat. You see only what crossed the "
        "network in the last run of the Participant tab, plus the artifacts "
        "of your own backdoor. You do not know which device Alice used: "
        "find out by trying to read her sessions.",
    )

    content.paragraph(
        "The workbench below is manual: each step takes a value you type, so "
        "you can follow the recovery, or feed it wrong values and watch the "
        "chain break. Buttons copy the value of the previous step when you "
        "just want to move on.",
    )

    return content.build()


def build_artifacts_content() -> str:
    """Return the callout that explains the attacker's artifacts."""
    return CalloutComposer.warning(
        content=(
            "You built this backdoor. The private key <em>X</em> never left "
            "your hands; <em>Y</em> and the constants are inside every device "
            "you compromised, and anyone who reverse-engineers one of them "
            "finds them too. Without <em>X</em> they are useless."
        ),
        title="Your artifacts",
    ).build()


def build_first_session_content() -> str:
    """Return the callout shown when the attacker picks session 1."""
    return CalloutComposer.info(
        content=(
            "Session 1 has no previous public key to pair with, so there is "
            "nothing to unmask: its key was drawn at random even by a "
            "compromised device. This is the (1,2)-leakage at work. Without "
            "<em>a</em><sub>1</sub> there is no shared secret, no session key "
            "and nothing to decrypt, so the workbench stops here: like Eve, "
            "you keep only the ciphertexts of the transcript. Pick a later "
            "session to read it."
        ),
        title="Nothing to recover in session 1",
    ).build()


def build_recovery_failed_content() -> str:
    """Return the callout shown when no candidate reproduces A_i."""
    return CalloutComposer.danger(
        content=(
            "Neither candidate reproduces this public key: it was not derived "
            "from the previous one by your SETUP. Most likely Alice used an "
            "honest device, whose keys are independent. Nothing stops you "
            "from following the chain with either candidate: you will get a "
            "shared secret and a session key, but they are the wrong ones, "
            "and AES-GCM will reject them."
        ),
        title="The SETUP is not there",
    ).build()


def build_eve_content() -> str:
    """Return the callout that compares the attacker with Eve."""
    return CalloutComposer.danger(
        content=(
            "Eve recorded exactly the same traffic and knows the same "
            "ciphersuite. She can run steps 2 to 4 like you, but she has no "
            "<em>X</em> for step 1, so she would have to solve a discrete "
            "logarithm first. With a standardized group, she reads nothing."
        ),
        title="Eve versus the attacker",
    ).build()
