"""
Presentation helpers for displaying (potentially huge) integers.

Cryptographic values can have thousands of digits. They are shown in
fixed-size groups separated by spaces so that they wrap inside their
container instead of forcing horizontal scrolling.
"""

from __future__ import annotations

from enum import StrEnum


class NumberFormat(StrEnum):
    """Base used to display integers."""

    DECIMAL = "decimal"
    HEXADECIMAL = "hexadecimal"


_GROUP_SIZE = {
    NumberFormat.DECIMAL: 3,
    NumberFormat.HEXADECIMAL: 8,
}

# Values whose decimal form is at most this long are small enough to be
# substituted into LaTeX formulas (e.g. "2^{6} \bmod 23 = 18").
_MAX_INLINE_DIGITS = 12


def format_integer(
    value: int,
    number_format: NumberFormat,
    *,
    width_bits: int | None = None,
) -> str:
    """
    Format a non-negative integer in groups separated by spaces.

    Decimal values use groups of three digits aligned to the right, as a
    thousands separator (``12 345 678``). Hexadecimal values use upper-case
    groups of eight digits aligned to the left, the layout used by RFC 7919
    (``FFFFFFFF FFFFFFFF``).

    In hexadecimal, ``width_bits`` zero-pads the value to the number of
    digits needed for that many bits. Values of the same group then share
    the same length and their groups line up when the text wraps. It is
    ignored in decimal, where leading zeros are not customary.

    Args:
        value: The integer to format.
        number_format: The base to display it in.
        width_bits: Optional fixed width, typically the bit length of the
            modulus ``p``.

    Returns:
        The grouped representation of ``value``.

    Raises:
        ValueError: If ``value`` is negative.
    """
    if value < 0:
        raise ValueError("Only non-negative integers can be formatted.")

    size = _GROUP_SIZE[number_format]

    if number_format is NumberFormat.DECIMAL:
        digits = str(value)
        head = len(digits) % size or size
        groups = [digits[:head]]
        groups.extend(digits[i : i + size] for i in range(head, len(digits), size))
        return " ".join(groups)

    width = 0 if width_bits is None else -(-width_bits // 4)
    digits = f"{value:0{width}X}"

    return " ".join(digits[i : i + size] for i in range(0, len(digits), size))


def format_bytes(data: bytes) -> str:
    """
    Format a byte string as upper-case hexadecimal in groups of four bytes.

    Byte strings (encoded secrets, keys, nonces, ciphertexts, tags) are
    always shown in hexadecimal, whatever the selected number format, with
    the same grouping as hexadecimal integers (``0011AABB 01020304``).

    Args:
        data: The bytes to format.

    Returns:
        The grouped representation of ``data``, or an empty string.
    """
    digits = data.hex().upper()
    size = _GROUP_SIZE[NumberFormat.HEXADECIMAL]

    return " ".join(digits[i : i + size] for i in range(0, len(digits), size))


def is_small(*values: int) -> bool:
    """
    Return whether all values are short enough to be shown inside formulas.

    Args:
        values: The integers to check.

    Returns:
        ``True`` if every value has at most 12 decimal digits.
    """
    return all(len(str(abs(value))) <= _MAX_INLINE_DIGITS for value in values)


def parse_integer(text: str) -> int:
    """
    Parse an integer typed by the user.

    Spaces are ignored, so grouped values produced by ``format_integer`` can
    be pasted back. A ``0x`` prefix selects hexadecimal; otherwise the text
    is read as decimal.

    Args:
        text: The user input.

    Returns:
        The parsed integer.

    Raises:
        ValueError: If the text is not a valid integer.
    """
    digits = "".join(text.split())

    if digits.lower().startswith("0x"):
        return int(digits[2:], 16)

    return int(digits, 10)


def parse_bytes(text: str) -> bytes:
    """
    Parse a byte string typed by the user in hexadecimal.

    Spaces are ignored, so values produced by ``format_bytes`` can be pasted
    back, and an optional ``0x`` prefix is accepted.

    Args:
        text: The user input.

    Returns:
        The parsed bytes.

    Raises:
        ValueError: If the text is not an even number of hexadecimal digits.
    """
    digits = "".join(text.split())

    if digits.lower().startswith("0x"):
        digits = digits[2:]

    return bytes.fromhex(digits)
