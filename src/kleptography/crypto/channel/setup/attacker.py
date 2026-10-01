"""The attacker of an encrypted channel whose Alice is the compromised device.

It sees only the public transcript. Each consecutive pair of Alice's public
keys leaks her exponent of the later session, which gives the session key
and every message of that session. Session 1 stays confidential.
"""

from __future__ import annotations

from kleptography.crypto.aead.aes_gcm import decrypt
from kleptography.crypto.aead.exceptions import AeadAuthenticationError
from kleptography.crypto.channel.records import (
    ChannelTranscript,
    SessionTranscript,
    TranscriptMessage,
)
from kleptography.crypto.channel.setup.records import (
    ChannelInterception,
    InterceptedMessage,
    InterceptedSession,
    InterceptionOutcome,
)
from kleptography.crypto.dh.exceptions import DiffieHellmanParametersMismatch
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.exceptions import (
    InvalidSetupConfiguration,
    SetupRecoveryError,
)
from kleptography.crypto.dh.setup.records import SetupCandidates
from kleptography.crypto.dh.validation import validate_public_key
from kleptography.crypto.kdf.one_step import derive_key
from kleptography.math.modular import mod_pow


def intercept_channel(
    transcript: ChannelTranscript,
    *,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> ChannelInterception:
    """Read every session of a channel that the transcript allows.

    Session 1 is never recoverable. For each later session the attacker
    recovers Alice's exponent from her previous and current public keys,
    computes the shared secret and the session key, and decrypts the
    messages. A session whose recovery fails is reported, not raised.

    Args:
        transcript: The public transcript of the channel.
        attacker: The attacker who built the SETUP.
        configuration: The configuration embedded in Alice's device.

    Returns:
        The interception of every session, with its intermediate values.

    Raises:
        InvalidSetupConfiguration: If the configuration is for another group
            or does not embed this attacker's public key.
        DiffieHellmanParametersMismatch: If the transcript uses another group.
        InvalidPublicKey: If a public key of the transcript is invalid.
    """
    # Checked up front, so the result does not depend on the number of sessions.
    if (
        configuration.parameters != attacker.parameters
        or configuration.attacker_public_key != attacker.public_key
    ):
        raise InvalidSetupConfiguration(
            "The configuration does not embed this attacker's public key."
        )
    if transcript.parameters != configuration.parameters:
        raise DiffieHellmanParametersMismatch(
            "The channel and the SETUP configuration use different DH groups."
        )

    sessions = transcript.sessions
    intercepted = [_not_recovered(sessions[0], InterceptionOutcome.NOT_RECOVERABLE)]
    # Each consecutive pair (A_{i-1}, A_i) leaks a_i: the (1,2)-leakage.
    for previous, current in zip(sessions, sessions[1:]):
        intercepted.append(
            _intercept_session(
                previous,
                current,
                attacker=attacker,
                configuration=configuration,
            )
        )

    return ChannelInterception(
        parameters=transcript.parameters, sessions=tuple(intercepted)
    )


def _intercept_session(
    previous: SessionTranscript,
    current: SessionTranscript,
    *,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> InterceptedSession:
    """Intercept one session from the previous and current transcripts."""
    parameters = configuration.parameters
    validate_public_key(
        current.bob_public_key,
        prime=parameters.prime,
        subgroup_order=parameters.subgroup_order,
    )

    # The candidates come from A_{i-1} alone; only the check uses A_i.
    candidates = attacker.compute_candidates(
        first_public_key=previous.alice_public_key, configuration=configuration
    )
    try:
        recovery = attacker.match_candidates(
            candidates, second_public_key=current.alice_public_key
        )
    except SetupRecoveryError:
        return _not_recovered(
            current, InterceptionOutcome.RECOVERY_FAILED, candidates=candidates
        )

    # From here on the attacker is just Alice: same secret, same KDF, same AEAD.
    shared_secret = mod_pow(
        current.bob_public_key, recovery.private_key, parameters.prime
    )
    key_derivation = derive_key(shared_secret, secret_length=parameters.byte_length)

    return InterceptedSession(
        transcript=current,
        outcome=InterceptionOutcome.RECOVERED,
        candidates=candidates,
        recovery=recovery,
        shared_secret=shared_secret,
        key_derivation=key_derivation,
        messages=tuple(
            _decrypt_message(message, key_derivation.key)
            for message in current.messages
        ),
    )


def _decrypt_message(message: TranscriptMessage, key: bytes) -> InterceptedMessage:
    """Decrypt one message, or keep it unreadable if the tag rejects it."""
    # A matching candidate is a_i itself (g has order q), so the key is right.
    # The tag can still reject a message whose ciphertext was tampered with.
    try:
        plaintext = decrypt(key, message.encrypted).decode("ascii")
    except AeadAuthenticationError:
        return InterceptedMessage(transcript=message, plaintext=None)
    return InterceptedMessage(transcript=message, plaintext=plaintext)


def _not_recovered(
    session: SessionTranscript,
    outcome: InterceptionOutcome,
    *,
    candidates: SetupCandidates | None = None,
) -> InterceptedSession:
    """Build a session that reveals nothing, with its outcome."""
    return InterceptedSession(
        transcript=session,
        outcome=outcome,
        candidates=candidates,
        recovery=None,
        shared_secret=None,
        key_derivation=None,
        messages=tuple(
            InterceptedMessage(transcript=message, plaintext=None)
            for message in session.messages
        ),
    )
