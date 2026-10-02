"""Tests for the number presentation helpers of the interface.

They check the grouping of decimal and hexadecimal integers (with and
without a fixed width), of byte strings, the size check used for formulas,
and that parsing accepts exactly what formatting produces (spaces and the
``0x`` prefix) while rejecting invalid text.
"""

from __future__ import annotations

import pytest

from kleptography.app.content.numbers import (
    NumberFormat,
    format_bytes,
    format_integer,
    is_small,
    parse_bytes,
    parse_integer,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0"),
        (7, "7"),
        (999, "999"),
        (1000, "1 000"),
        (12345678, "12 345 678"),
        (123456789, "123 456 789"),
    ],
)
def test_format_integer_decimal_groups_from_the_right(
    value: int, expected: str
) -> None:
    """Decimal digits are grouped by three as a thousands separator."""
    assert format_integer(value, NumberFormat.DECIMAL) == expected


def test_format_integer_decimal_ignores_width() -> None:
    """Decimal values are never zero-padded."""
    assert format_integer(23, NumberFormat.DECIMAL, width_bits=64) == "23"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0"),
        (0xFF, "FF"),
        (0xFFFFFFFF, "FFFFFFFF"),
        (0x1FFFFFFFF, "1FFFFFFF F"),
        (0xDEADBEEFCAFE, "DEADBEEF CAFE"),
    ],
)
def test_format_integer_hexadecimal_groups_from_the_left(
    value: int, expected: str
) -> None:
    """Hexadecimal digits are upper case and grouped by eight from the left."""
    assert format_integer(value, NumberFormat.HEXADECIMAL) == expected


@pytest.mark.parametrize(
    ("value", "width_bits", "expected"),
    [
        (0x17, 8, "17"),
        (0x2, 8, "02"),
        (0x2, 5, "02"),
        (0x12, 64, "00000000 00000012"),
        (0x1, 36, "00000000 1"),
    ],
)
def test_format_integer_hexadecimal_pads_to_width(
    value: int, width_bits: int, expected: str
) -> None:
    """The width in bits is rounded up to whole hexadecimal digits."""
    assert (
        format_integer(value, NumberFormat.HEXADECIMAL, width_bits=width_bits)
        == expected
    )


def test_format_integer_hexadecimal_aligns_values_of_one_group() -> None:
    """Values padded to the same width have the same length."""
    width_bits = 2048
    small = format_integer(2, NumberFormat.HEXADECIMAL, width_bits=width_bits)
    large = format_integer(2**2047 + 1, NumberFormat.HEXADECIMAL, width_bits=width_bits)

    assert len(small) == len(large)


def test_format_integer_hexadecimal_keeps_values_wider_than_width() -> None:
    """A value wider than the width is not truncated."""
    assert format_integer(0x1234, NumberFormat.HEXADECIMAL, width_bits=8) == "1234"


@pytest.mark.parametrize("number_format", list(NumberFormat))
def test_format_integer_rejects_negative_values(number_format: NumberFormat) -> None:
    """Negative integers raise ValueError in every format."""
    with pytest.raises(ValueError, match="non-negative"):
        format_integer(-1, number_format)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", ""),
        (b"\x00", "00"),
        (b"\x00\x11\xaa\xbb", "0011AABB"),
        (b"\x00\x11\xaa\xbb\x01\x02\x03\x04", "0011AABB 01020304"),
        (bytes(range(10)), "00010203 04050607 0809"),
    ],
)
def test_format_bytes_groups_four_bytes(data: bytes, expected: str) -> None:
    """Bytes are upper-case hexadecimal in groups of four bytes."""
    assert format_bytes(data) == expected


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ((), True),
        ((0,), True),
        ((999_999_999_999,), True),
        ((-999_999_999_999,), True),
        ((1_000_000_000_000,), False),
        ((6, 23, 1_000_000_000_000), False),
        ((6, 23, 18), True),
    ],
)
def test_is_small_limits_values_to_twelve_digits(
    values: tuple[int, ...], expected: bool
) -> None:
    """Only values of at most 12 decimal digits, sign ignored, are small."""
    assert is_small(*values) is expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("23", 23),
        ("12 345 678", 12345678),
        ("  42\t", 42),
        ("-5", -5),
        ("0x17", 23),
        ("0X17", 23),
        ("0xff", 255),
        ("0xDEADBEEF CAFE", 0xDEADBEEFCAFE),
    ],
)
def test_parse_integer_accepts_decimal_and_prefixed_hexadecimal(
    text: str, expected: int
) -> None:
    """Spaces are ignored and ``0x`` selects hexadecimal."""
    assert parse_integer(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "abc", "FF", "0x", "0xZZ", "1.5"])
def test_parse_integer_rejects_invalid_text(text: str) -> None:
    """Text that is not an integer raises ValueError."""
    with pytest.raises(ValueError):
        parse_integer(text)


@pytest.mark.parametrize(
    "value",
    [0, 1, 23, 1000, 12345678901234567890, 2**2048 - 1],
)
def test_parse_integer_reads_back_formatted_decimal(value: int) -> None:
    """A grouped decimal value can be pasted back."""
    assert parse_integer(format_integer(value, NumberFormat.DECIMAL)) == value


@pytest.mark.parametrize(
    "value",
    [0, 1, 23, 0xDEADBEEFCAFE, 2**2048 - 1],
)
def test_parse_integer_reads_back_formatted_hexadecimal(value: int) -> None:
    """A grouped hexadecimal value can be pasted back with its prefix."""
    text = format_integer(value, NumberFormat.HEXADECIMAL, width_bits=2048)

    assert parse_integer("0x" + text) == value


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", b""),
        ("00", b"\x00"),
        ("0011aabb", b"\x00\x11\xaa\xbb"),
        ("0011AABB 01020304", b"\x00\x11\xaa\xbb\x01\x02\x03\x04"),
        ("0x0102", b"\x01\x02"),
        ("0X 01 02", b"\x01\x02"),
    ],
)
def test_parse_bytes_accepts_grouped_hexadecimal(text: str, expected: bytes) -> None:
    """Spaces and an optional ``0x`` prefix are ignored."""
    assert parse_bytes(text) == expected


@pytest.mark.parametrize("text", ["0", "ABC", "GG", "0x1", "zz"])
def test_parse_bytes_rejects_invalid_text(text: str) -> None:
    """An odd number of digits or a non-hexadecimal digit raises ValueError."""
    with pytest.raises(ValueError):
        parse_bytes(text)


@pytest.mark.parametrize(
    "data",
    [b"", b"\x00", bytes(range(32)), b"\xff" * 12],
)
def test_parse_bytes_reads_back_formatted_bytes(data: bytes) -> None:
    """A formatted byte string can be pasted back."""
    assert parse_bytes(format_bytes(data)) == data
