from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives import hashes

from kleptography.crypto.dh.parameters import DiffieHellmanParameters

# Extra output bits so that the reduction modulo q - 1 has a bias below 2^-64
# (the "extra random bits" method of FIPS 186-5, Appendix A.2.1).
_EXTRA_BYTES = 8


class SetupHashFunction(Protocol):
    def __call__(
        self,
        value: int,
        *,
        parameters: DiffieHellmanParameters,
    ) -> int: ...


def hash_to_exponent(
    value: int,
    *,
    parameters: DiffieHellmanParameters,
) -> int:
    if not 1 <= value < parameters.prime:
        raise ValueError("value is outside [1, p - 1]")

    output_length = (parameters.subgroup_order.bit_length() + 7) // 8 + _EXTRA_BYTES
    # Fixed-width big-endian encoding of z: every element of the group has
    # the same length (that of p), as in the I2OSP primitive of RFC 8017.
    input_length = (parameters.prime.bit_length() + 7) // 8

    h = hashes.Hash(hashes.SHAKE256(output_length))
    h.update(b"young-yung-setup-H")
    h.update(value.to_bytes(input_length, "big"))

    digest_bytes = h.finalize()
    digest_raw = int.from_bytes(digest_bytes, "big")

    return digest_raw % (parameters.subgroup_order - 1) + 1
