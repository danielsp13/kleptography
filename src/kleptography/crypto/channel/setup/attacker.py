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
from kleptography.crypto.dh.validation import validate_public_key
from kleptography.crypto.kdf.one_step import derive_key
from kleptography.math.modular import mod_pow


def intercept_channel(
    transcript: ChannelTranscript,
    *,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> ChannelInterception:
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
    parameters = configuration.parameters
    validate_public_key(
        current.bob_public_key,
        prime=parameters.prime,
        subgroup_order=parameters.subgroup_order,
    )

    try:
        recovery = attacker.recover(
            first_public_key=previous.alice_public_key,
            second_public_key=current.alice_public_key,
            configuration=configuration,
        )
    except SetupRecoveryError:
        return _not_recovered(current, InterceptionOutcome.RECOVERY_FAILED)

    # From here on the attacker is just Alice: same secret, same KDF, same AEAD.
    shared_secret = mod_pow(
        current.bob_public_key, recovery.private_key, parameters.prime
    )
    key_derivation = derive_key(shared_secret, secret_length=parameters.byte_length)

    return InterceptedSession(
        transcript=current,
        outcome=InterceptionOutcome.RECOVERED,
        recovery=recovery,
        shared_secret=shared_secret,
        key_derivation=key_derivation,
        messages=tuple(
            _decrypt_message(message, key_derivation.key)
            for message in current.messages
        ),
    )


def _decrypt_message(message: TranscriptMessage, key: bytes) -> InterceptedMessage:
    # A matching candidate is a_i itself (g has order q), so the key is right.
    # The tag can still reject a message whose ciphertext was tampered with.
    try:
        plaintext = decrypt(key, message.encrypted).decode("ascii")
    except AeadAuthenticationError:
        return InterceptedMessage(transcript=message, plaintext=None)
    return InterceptedMessage(transcript=message, plaintext=plaintext)


def _not_recovered(
    session: SessionTranscript, outcome: InterceptionOutcome
) -> InterceptedSession:
    return InterceptedSession(
        transcript=session,
        outcome=outcome,
        recovery=None,
        shared_secret=None,
        key_derivation=None,
        messages=tuple(
            InterceptedMessage(transcript=message, plaintext=None)
            for message in session.messages
        ),
    )
