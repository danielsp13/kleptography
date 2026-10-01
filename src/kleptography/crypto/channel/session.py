"""
One session of the encrypted channel: ephemeral DH, key derivation, messages.

A session follows the usual pattern of real secure channels:

1. Both parties generate fresh (ephemeral) DH key pairs and run the key
   exchange.
2. Each party derives the session key from its shared secret with the
   one-step KDF (SHA-256).
3. Each message is encrypted with AES-256-GCM under the sender's key and
   decrypted under the recipient's key.

The channel only uses the public API of the participants. It does not know,
and cannot tell, whether one of them is a compromised device: a device
replaces an honest participant without any change here. It is educational
code, not a hardened protocol: there is no authentication of the public
keys, no replay protection and no key confirmation step.
"""

from __future__ import annotations

from collections.abc import Sequence

from kleptography.crypto.aead.aes_gcm import decrypt, encrypt
from kleptography.crypto.channel.records import (
    ChannelMessage,
    ChannelSession,
    PlainMessage,
)
from kleptography.crypto.dh.exceptions import DiffieHellmanParametersMismatch
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange
from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.kdf.one_step import derive_key
from kleptography.crypto.kdf.records import KeyDerivation


def run_session(
    alice: DiffieHellmanParticipant,
    bob: DiffieHellmanParticipant,
    messages: Sequence[PlainMessage],
    *,
    number: int,
) -> ChannelSession:
    """
    Run one session of the channel and exchange its messages.

    Both participants always get a fresh key pair through
    ``generate_keypair()`` before the exchange (ephemeral DH), replacing any
    previous one. In the exchange timeline the keys are therefore traced as
    provided: they exist when the exchange starts.

    Args:
        alice: The participant playing Alice.
        bob: The participant playing Bob.
        messages: The messages of the session, in sending order. It may be
            empty.
        number: The position of the session in the channel, starting at 1.

    Returns:
        The ``ChannelSession`` with the exchange timeline, both key
        derivations and every message.

    Raises:
        DiffieHellmanParametersMismatch: If the participants use different
            groups. No key is generated in that case.
        InvalidChannelSessions: If ``number`` is lower than 1.
    """
    if alice.parameters != bob.parameters:
        raise DiffieHellmanParametersMismatch(
            "Alice and Bob must use the same Diffie-Hellman parameters."
        )

    alice.generate_keypair()
    bob.generate_keypair()

    context = ProtocolExecutionContext()
    result = perform_key_exchange(alice, bob, observer=context)

    # The exchange reuses the key pairs just generated, so both are set.
    assert alice.public_key is not None
    assert bob.public_key is not None

    secret_length = (alice.parameters.prime.bit_length() + 7) // 8
    derivations = {
        Actor.ALICE: derive_key(
            result.alice_shared_secret, secret_length=secret_length
        ),
        Actor.BOB: derive_key(result.bob_shared_secret, secret_length=secret_length),
    }

    return ChannelSession(
        number=number,
        events=context.events,
        alice_public_key=alice.public_key,
        bob_public_key=bob.public_key,
        alice_key_derivation=derivations[Actor.ALICE],
        bob_key_derivation=derivations[Actor.BOB],
        messages=tuple(_deliver(message, derivations) for message in messages),
    )


def _deliver(
    message: PlainMessage,
    derivations: dict[Actor, KeyDerivation],
) -> ChannelMessage:
    encrypted = encrypt(
        derivations[message.sender].key,
        message.text.encode("ascii"),
    )
    received = decrypt(derivations[message.recipient].key, encrypted)
    return ChannelMessage(
        sender=message.sender,
        plaintext=message.text,
        encrypted=encrypted,
        received_plaintext=received.decode("ascii"),
    )
