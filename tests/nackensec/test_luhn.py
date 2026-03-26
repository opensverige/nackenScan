"""Unit tests for Swedish ID number validators."""

import pytest
from nackensec.validators import (
    luhn_check,
    is_valid_personnummer,
    is_valid_organisationsnummer,
    normalize_personnummer,
)


class TestLuhnCheck:
    """Test the raw Luhn-10 checksum algorithm."""

    def test_valid_personnummer_digits(self):
        # 8501011236 — correct check digit for 850101123X per Skatteverket algorithm
        # (plan originally specified 8501011234 which had an incorrect check digit)
        assert luhn_check("8501011236") is True

    def test_invalid_checksum(self):
        assert luhn_check("8501011235") is False

    def test_must_be_10_digits(self):
        with pytest.raises(ValueError):
            luhn_check("123")

    def test_non_digits_raise(self):
        with pytest.raises(ValueError):
            luhn_check("850101-234")


class TestNormalizePersonnummer:
    """Test normalization to 10-digit form."""

    def test_long_with_dash(self):
        assert normalize_personnummer("19850101-1236") == "8501011236"

    def test_long_without_dash(self):
        assert normalize_personnummer("198501011236") == "8501011236"

    def test_short_with_dash(self):
        assert normalize_personnummer("850101-1236") == "8501011236"

    def test_short_without_dash(self):
        assert normalize_personnummer("8501011236") == "8501011236"

    def test_invalid_format_returns_none(self):
        assert normalize_personnummer("not-a-pnr") is None

    def test_spaces_stripped(self):
        assert normalize_personnummer(" 850101-1236 ") == "8501011236"


class TestIsValidPersonnummer:
    """Full personnummer validation (format + date + Luhn)."""

    def test_valid_long_format(self):
        assert is_valid_personnummer("19850101-1236") is True

    def test_valid_short_format(self):
        assert is_valid_personnummer("850101-1236") is True

    def test_valid_no_dash(self):
        assert is_valid_personnummer("8501011236") is True

    def test_invalid_month(self):
        assert is_valid_personnummer("851301-1234") is False  # month 13

    def test_invalid_day_zero(self):
        assert is_valid_personnummer("850100-1234") is False  # day 0

    def test_invalid_day_too_high(self):
        assert is_valid_personnummer("850132-1234") is False  # day 32

    def test_samordningsnummer_valid(self):
        # Samordningsnummer: day + 60 (e.g., day 01 becomes 61)
        # 8501611233 has correct Luhn check digit for 850161123X
        assert is_valid_personnummer("850161-1233") is True

    def test_samordningsnummer_invalid_day(self):
        # day 92 (60+32) is invalid
        assert is_valid_personnummer("850192-1234") is False

    def test_bad_luhn_fails(self):
        assert is_valid_personnummer("850101-1235") is False

    def test_all_zeros_fails(self):
        assert is_valid_personnummer("000000-0000") is False


class TestIsValidOrganisationsnummer:
    """Organisationsnummer validation."""

    def test_valid_orgnr(self):
        # 556123-4567 — known test org number format
        assert is_valid_organisationsnummer("556123-4567") is True

    def test_valid_with_16_prefix(self):
        assert is_valid_organisationsnummer("16556123-4567") is True

    def test_third_digit_less_than_2_fails(self):
        # Third digit must be >= 2 (distinguishes from personnummer)
        assert is_valid_organisationsnummer("551234-5678") is False

    def test_invalid_luhn_fails(self):
        assert is_valid_organisationsnummer("556123-4568") is False

    def test_non_numeric_fails(self):
        assert is_valid_organisationsnummer("55612X-4567") is False
