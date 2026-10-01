# Primitives (`kleptography.crypto.kdf`, `kleptography.crypto.aead`)

The encrypted channel ([channel.md](channel.md)) turns a Diffie-Hellman
shared secret into a symmetric key and uses it to protect messages. These
two packages provide those steps. Both are thin, validated wrappers around
the `cryptography` library: **no primitive is reimplemented here**.

Neither package imports anything else from the project. They take integers
and bytes, never Diffie-Hellman objects, so a future target (RSA, ML-DSA)
can reuse them unchanged.

## Key derivation (KDF)

### Why a KDF

A Diffie-Hellman shared secret is a group element, not a uniformly random
string of bits, and its size depends on the group. It is therefore not used
directly as an AES key. A key derivation function hashes it, together with
a context label, into a key of the right size.

### The construction

NIST SP 800-56C Rev. 2, Section 4.1 (one-step KDF), with SHA-256, through
`cryptography`'s `ConcatKDFHash`:

```text
K = SHA-256(0x00000001 ‖ Z ‖ OtherInfo)
```

| Part | Value |
| --- | --- |
| counter | `0x00000001`: one SHA-256 block already gives the 32 bytes of an AES-256 key |
| `Z` | the shared secret, big-endian, with a fixed width: the byte length of `p` (as I2OSP) |
| `OtherInfo` | the fixed label `b"kleptography-encrypted-channel"` (`OTHER_INFO`) |

There is no salt and no randomness: the key is a deterministic function of
the shared secret. That is standard practice, and it is also why anyone who
learns the shared secret can recompute the key.

### API (`kdf/one_step.py`, `kdf/records.py`)

#### `derive_key(shared_secret, *, secret_length) -> KeyDerivation`

- `shared_secret`: a positive integer.
- `secret_length`: the fixed byte length of `Z`. For Diffie-Hellman, pass
  `parameters.byte_length`, so every secret of the group has the same width.
  The KDF never sees the group itself.
- Raises `InvalidKdfInput` unless both arguments are integers (not `bool`),
  `secret_length >= 1` and `1 <= shared_secret < 256^secret_length`.

#### `KeyDerivation(shared_secret, encoded_secret, other_info, key)`

A frozen record of every value involved, so an interface can show each one.

| Field | Description |
| --- | --- |
| `shared_secret` | the integer secret (hidden from `repr`) |
| `encoded_secret` | `Z`, the fixed-width bytes (hidden from `repr`) |
| `other_info` | the label |
| `key` | the 32-byte key, `KEY_SIZE = 32` (hidden from `repr`) |

It raises `InvalidKeyDerivation` if `encoded_secret` does not encode
`shared_secret` or the key is not 32 bytes.

### Example

```python
import hashlib

from kleptography.crypto.kdf.one_step import OTHER_INFO, derive_key

derivation = derive_key(6, secret_length=1)  # toy secret, 1-byte group
assert derivation.encoded_secret == b"\x06"
assert (
    derivation.key
    == hashlib.sha256(b"\x00\x00\x00\x01" + b"\x06" + OTHER_INFO).digest()
)
assert derivation.key.hex().startswith("5665325f")
```

The tests recompute every key independently with `hashlib` in the same way.

## Authenticated encryption (AEAD)

### Why AES-GCM

The channel needs both **confidentiality** (nobody without the key reads a
message) and **integrity** (nobody without the key can modify one
unnoticed). AES-256-GCM (NIST SP 800-38D) gives both: AES in counter mode
encrypts, and the GHASH authenticator produces a tag over the ciphertext.

### Choices

| Choice | Value |
| --- | --- |
| Key | 32 bytes (AES-256) only; other AES sizes are rejected |
| Nonce | 12 bytes (96 bits), random from `secrets` for every message, `NONCE_SIZE = 12` |
| Tag | 16 bytes (128 bits, the full tag), `TAG_SIZE = 16` |
| Associated data | none |

The nonce is not secret: it travels next to the ciphertext. It only has to
be unique under a key, and 96 random bits make a repetition negligible for
the few messages of a demonstration.

### API (`aead/aes_gcm.py`, `aead/records.py`)

| Function | Description | Raises |
| --- | --- | --- |
| `generate_nonce()` | 12 random bytes | — |
| `encrypt(key, plaintext, *, nonce=None)` | An `EncryptedMessage`. A fresh nonce is generated when omitted; pass one only for test vectors (reusing a nonce under the same key breaks both confidentiality and integrity). | `InvalidAeadKey`, `InvalidAeadNonce` |
| `decrypt(key, message)` | The plaintext. The tag is checked first, so a wrong key and a tampered message fail the same way. | `InvalidAeadKey`, `AeadAuthenticationError` (chained from the library's `InvalidTag`) |

#### `EncryptedMessage(nonce, ciphertext, tag)`

Frozen, and entirely **public**: this is what travels over the network.
The ciphertext is as long as the plaintext (GCM is a stream mode, with no
padding). The library returns `ciphertext ‖ tag`; the record keeps them
apart so each field can be shown. It raises `InvalidAeadNonce` or
`InvalidAeadTag` for wrong sizes.

### Example

```python
from kleptography.crypto.aead.aes_gcm import decrypt, encrypt
from kleptography.crypto.aead.exceptions import AeadAuthenticationError
from kleptography.crypto.kdf.one_step import derive_key

key = derive_key(6, secret_length=1).key
message = encrypt(key, b"hello")
assert (len(message.nonce), len(message.ciphertext), len(message.tag)) == (12, 5, 16)
assert decrypt(key, message) == b"hello"

wrong_key = derive_key(7, secret_length=1).key
try:
    decrypt(wrong_key, message)
except AeadAuthenticationError:
    pass  # nothing is revealed without the key
else:
    raise AssertionError("a wrong key must fail")
```

The tests use test cases 13–15 of McGrew and Viega's GCM specification,
plus round trips, tampering and wrong-key failures.

## Errors

| Exception | Package | Raised when |
| --- | --- | --- |
| `InvalidKdfInput` | `kdf` | Invalid secret or secret length. |
| `InvalidKeyDerivation` | `kdf` | An inconsistent `KeyDerivation`. |
| `InvalidAeadKey` | `aead` | The key is not 32 bytes. |
| `InvalidAeadNonce` | `aead` | The nonce is not 12 bytes. |
| `InvalidAeadTag` | `aead` | The tag is not 16 bytes. |
| `AeadAuthenticationError` | `aead` | The tag does not verify: wrong key or tampered message. |

They subclass `KdfError` or `AeadError`, two hierarchies independent of the
Diffie-Hellman one, and all are also `ValueError`.

## Limitations

- These wrappers are educational: no key erasure, no nonce-misuse
  resistance and no associated data binding the message to its session.
- With a toy group the shared secret has a few bits, so the key is
  brute-forceable by anyone, whatever the strength of AES. The interface
  says so.
