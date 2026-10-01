"""One-step key derivation (NIST SP 800-56C Rev. 2, Section 4.1) with SHA-256.

A Diffie-Hellman shared secret is a group element, not a uniformly random
string of bits, so it is not used directly as a symmetric key. The one-step
KDF hashes it, together with a counter and a context label, into a key:

    K = SHA-256(0x00000001 || Z || OtherInfo)

where ``Z`` is the shared secret encoded big-endian with a fixed width (the
byte length of the group's prime, as in the I2OSP primitive of RFC 8017).
One SHA-256 block already gives the 32 bytes of an AES-256 key, so the
counter never goes past 1. The construction comes from the ``cryptography``
library (``ConcatKDFHash``) and is never reimplemented here.

There is no salt and no randomness: the key is a deterministic function of
the shared secret. That is standard practice, and it is also why anyone who
recovers the shared secret, such as a kleptographic attacker, recovers the
key. It is educational code, not a hardened key schedule.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from kleptography.crypto.kdf.exceptions import InvalidKdfInput
from kleptography.crypto.kdf.records import KEY_SIZE, KeyDerivation

OTHER_INFO = b"kleptography-encrypted-channel"
"""Fixed context label (``OtherInfo``) bound into every derived key."""


def derive_key(shared_secret: int, *, secret_length: int) -> KeyDerivation:
    """Derive a 32-byte key from a shared secret.

    Args:
        shared_secret: The shared secret, a positive integer.
        secret_length: The fixed byte length of ``Z``. For Diffie-Hellman it
            is the byte length of the prime ``p``, so every secret of the
            group is encoded with the same width.

    Returns:
        The ``KeyDerivation`` with ``Z``, the label and the derived key.

    Raises:
        InvalidKdfInput: If ``secret_length`` is not positive, or
            ``shared_secret`` is not a positive integer that fits in
            ``secret_length`` bytes.
    """
    if isinstance(secret_length, bool) or not isinstance(secret_length, int):
        raise InvalidKdfInput("The secret length must be an integer.")
    if secret_length < 1:
        raise InvalidKdfInput("The secret length must be positive.")
    if isinstance(shared_secret, bool) or not isinstance(shared_secret, int):
        raise InvalidKdfInput("The shared secret must be an integer.")
    if not 1 <= shared_secret < 1 << (8 * secret_length):
        raise InvalidKdfInput(
            f"The shared secret must be positive and fit in {secret_length} bytes."
        )

    encoded_secret = shared_secret.to_bytes(secret_length, "big")
    kdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        otherinfo=OTHER_INFO,
    )
    return KeyDerivation(
        shared_secret=shared_secret,
        encoded_secret=encoded_secret,
        other_info=OTHER_INFO,
        key=kdf.derive(encoded_secret),
    )
