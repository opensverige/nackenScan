"""Smoke tests for Swedish PII YARA rules."""

import pytest
from pathlib import Path
import yara_x


RULES_DIR = Path(__file__).parent.parent.parent / "nackensec" / "rules" / "swedish"


def compile_rules() -> yara_x.Rules:
    compiler = yara_x.Compiler()
    for yara_file in sorted(RULES_DIR.glob("*.yara")):
        compiler.new_namespace(yara_file.stem)
        compiler.add_source(yara_file.read_text(encoding="utf-8"), origin=str(yara_file))
    return compiler.build()


@pytest.fixture(scope="module")
def rules():
    return compile_rules()


def matched_rule_ids(rules: yara_x.Rules, text: str) -> set[str]:
    scanner = yara_x.Scanner(rules)
    results = scanner.scan(text.encode("utf-8"))
    return {m.identifier for m in results.matching_rules}


class TestPersonnummerRules:
    def test_detects_long_format_with_dash(self, rules):
        hits = matched_rule_ids(rules, "pnr: 19850101-1234")
        assert "swe_pii" in hits

    def test_detects_short_format_with_dash(self, rules):
        hits = matched_rule_ids(rules, "ssn: 850101-1234")
        assert "swe_pii" in hits

    def test_detects_without_dash(self, rules):
        hits = matched_rule_ids(rules, "nummer: 8501011234")
        assert "swe_pii" in hits

    def test_no_crash_on_plain_text(self, rules):
        result = matched_rule_ids(rules, "invoice number 12345")
        assert isinstance(result, set)


class TestOrganisationsnummerRules:
    def test_detects_orgnr_with_dash(self, rules):
        hits = matched_rule_ids(rules, "Org nr: 556123-4567")
        assert "swe_pii" in hits

    def test_detects_with_16_prefix(self, rules):
        hits = matched_rule_ids(rules, "org: 16556123-4567")
        assert "swe_pii" in hits


class TestBankRules:
    def test_detects_bankgiro(self, rules):
        hits = matched_rule_ids(rules, "Bankgiro: 123-4567")
        assert "swe_pii" in hits

    def test_detects_iban_se(self, rules):
        hits = matched_rule_ids(rules, "IBAN: SE45 5000 0000 0583 9825 7466")
        assert "swe_pii" in hits

    def test_detects_plusgiro(self, rules):
        hits = matched_rule_ids(rules, "Plusgiro: 12345-6")
        assert "swe_pii" in hits


class TestPhoneRules:
    def test_detects_swedish_mobile(self, rules):
        hits = matched_rule_ids(rules, "Tel: 070-123 45 67")
        assert "swe_pii" in hits

    def test_detects_intl_format(self, rules):
        hits = matched_rule_ids(rules, "+46 70 123 45 67")
        assert "swe_pii" in hits
