# NäckenSec — Swedish AI Agent Security
# Copyright (c) 2026 OpenSverige
# License: AGPL-3.0 (see LICENSE-AGPL)
# Commercial licensing: licensing@opensverige.se
"""Swedish ID number validators with Luhn-10 checksum verification."""

from __future__ import annotations

import re


def luhn_check(digits: str) -> bool:
    """
    Verify a 10-digit string passes the Luhn-10 checksum (Skatteverket algorithm).

    Alternating digits (from left, starting at position 0) are multiplied by 2,
    then 1, then 2, etc. Products > 9 have their digits summed. Total must be
    divisible by 10.

    Args:
        digits: Exactly 10 digit characters (no dashes or spaces).

    Raises:
        ValueError: If input is not exactly 10 decimal digits.
    """
    if not re.fullmatch(r"\d{10}", digits):
        raise ValueError(f"luhn_check requires exactly 10 digits, got: {digits!r}")

    total = 0
    for i, ch in enumerate(digits):
        n = int(ch)
        if i % 2 == 0:
            n *= 2
        if n > 9:
            n -= 9
        total += n
    return total % 10 == 0


def normalize_personnummer(raw: str) -> str | None:
    """
    Normalize a personnummer to exactly 10 digits (YYMMDDXXXX).

    Accepts:
      - YYYYMMDD-XXXX  (12 chars with dash)
      - YYYYMMDDXXXX   (12 chars no dash)
      - YYMMDD-XXXX    (10 chars with dash -> 11 including dash)
      - YYMMDDXXXX     (10 chars no dash)

    Returns:
        10-digit string, or None if the input does not match any known format.
    """
    s = raw.strip()
    # Remove all spaces
    s = s.replace(" ", "")

    # YYYYMMDD-XXXX or YYYYMMDDXXXX
    m = re.fullmatch(r"(19|20)(\d{6})-?(\d{4})", s)
    if m:
        return m.group(2) + m.group(3)

    # YYMMDD-XXXX or YYMMDDXXXX
    m = re.fullmatch(r"(\d{6})-?(\d{4})", s)
    if m:
        return m.group(1) + m.group(2)

    return None


def is_valid_personnummer(raw: str) -> bool:
    """
    Validate a personnummer fully: format + date + Luhn.

    Accepts Swedish personnummer (YYMMDD-XXXX, YYYYMMDD-XXXX) and
    samordningsnummer (day field + 60, giving days 61-91).

    Returns:
        True if the number is structurally valid and passes Luhn.
    """
    digits = normalize_personnummer(raw)
    if digits is None:
        return False

    # Reject all-zero
    if digits == "0000000000":
        return False

    # Parse YYMMDDXXXX
    mm = int(digits[2:4])
    dd = int(digits[4:6])

    # Month must be 1-12
    if mm < 1 or mm > 12:
        return False

    # Day: 1-31 normal, 61-91 samordningsnummer
    effective_day = dd if dd <= 31 else dd - 60
    if effective_day < 1 or effective_day > 31:
        return False

    # Luhn check
    return luhn_check(digits)


def is_valid_organisationsnummer(raw: str) -> bool:
    """
    Validate a Swedish organisationsnummer.

    Format: XXXXXX-XXXX (10 digits) or 16XXXXXX-XXXX (with optional 16 prefix).
    Third digit must be >= 2 (distinguishes from personnummer).
    Must pass Luhn-10 checksum.

    Returns:
        True if valid organisationsnummer.
    """
    s = raw.strip().replace(" ", "")

    # Strip optional 16 prefix
    if s.startswith("16"):
        s = s[2:]

    # XXXXXX-XXXX or XXXXXXXXXX
    m = re.fullmatch(r"(\d{6})-?(\d{4})", s)
    if not m:
        return False

    digits = m.group(1) + m.group(2)

    # Third digit (index 2) must be >= 2
    if int(digits[2]) < 2:
        return False

    # digits is always 10 decimal chars from the regex match above
    return luhn_check(digits)
