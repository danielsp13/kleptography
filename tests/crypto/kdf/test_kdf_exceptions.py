from __future__ import annotations

import pytest

from kleptography.crypto.aead.exceptions import AeadError
from kleptography.crypto.dh.exceptions import DiffieHellmanError
from kleptography.crypto.kdf.exceptions import (
    InvalidKdfInput,
    InvalidKeyDerivation,
    KdfError,
)


@pytest.mark.parametrize("other_base", [DiffieHellmanError, AeadError])
def test_kdf_error_is_independent_of_other_schemes(
    other_base: type[Exception],
) -> None:
    """KDF errors form their own hierarchy, outside the DH and AEAD ones."""
    assert not issubclass(KdfError, other_base)


@pytest.mark.parametrize(
    ("exception_type", "builtin_type"),
    [
        (InvalidKdfInput, ValueError),
        (InvalidKeyDerivation, ValueError),
    ],
)
def test_kdf_exceptions_hierarchy(
    exception_type: type[KdfError],
    builtin_type: type[Exception],
) -> None:
    """Every KDF error subclasses the base error and the matching builtin."""
    assert issubclass(exception_type, KdfError)
    assert issubclass(exception_type, builtin_type)
