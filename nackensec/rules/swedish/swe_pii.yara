//////////////////////////////////////////////////////////
// Swedish PII Detection Rules
// NäckenSec — opensverige.se
// License: Apache-2.0
//
// Detects Swedish personally identifiable information in
// agent skill definitions. Python analyzer layer validates
// Luhn checksums for confirmed findings.
//////////////////////////////////////////////////////////

rule swe_pii {
    meta:
        author = "NäckenSec"
        description = "Detects Swedish PII: personnummer, organisationsnummer, bank accounts, phone numbers"
        classification = "pii"
        threat_type = "PII_EXPOSURE"
        remediation_sv = "Ta bort PII från agentdefinitionen. Använd miljövariabler eller SveaGuard mask_json för känslig data."
        requires_luhn_validation = "pnr_no_dash,pnr_short,pnr_long — downstream analyzer must validate Luhn checksum before reporting HIGH findings"

    strings:
        // Personnummer: YYYYMMDD-XXXX or YYMMDD-XXXX (with or without dash)
        $pnr_long     = /\b(19|20)\d{6}[-]?\d{4}\b/
        $pnr_short    = /\b\d{6}[-]\d{4}\b/
        $pnr_no_dash  = /\b\d{10}\b/

        // Samordningsnummer: day field is 61-91 (01-31 + 60)
        $sam_long     = /\b(19|20)\d{4}(6[1-9]|[78]\d|9[01])[-]?\d{4}\b/
        $sam_short    = /\b\d{4}(6[1-9]|[78]\d|9[01])[-]\d{4}\b/

        // Organisationsnummer: XXXXXX-XXXX (3rd digit >= 2) or with 16 prefix
        $orgnr        = /\b16[2-9]\d{5}[-]?\d{4}\b/
        $orgnr_short  = /\b[2-9]\d{5}[-]\d{4}\b/

        // IBAN Swedish: SE + 2 check digits + 20 digits (spaces allowed)
        $iban_se      = /\bSE\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}\b/

        // Bankgiro: XXX-XXXX or XXXX-XXXX (7-8 digits total)
        $bankgiro     = /\b[Bb]ankgiro\s*:?\s*\d{3,4}-\d{4}\b/
        $bg_bare      = /\bBG\s+\d{3,4}-\d{4}\b/

        // Plusgiro: 2-8 digits + dash + 1 digit
        $plusgiro     = /\b[Pp]lusgiro\s*:?\s*\d{2,7}-\d\b/
        $pg_bare      = /\bPG\s+\d{2,7}-\d\b/

        // Swedish mobile: 07X-XXX XX XX or 07XXXXXXXX
        $phone_mobile = /\b07[0-9][-\s]?\d{3}[\s]?\d{2}[\s]?\d{2}\b/

        // Swedish landline: 0XX-XXX XX XX
        $phone_land   = /\b0[1-9]\d[-\s]?\d{3}[\s]?\d{2}[\s]?\d{2}\b/

        // International Swedish: +46 7X ...
        $phone_intl   = /\+46\s?[0-9]{1,2}\s?\d{3}\s?\d{2}\s?\d{2}/

        // Clearing numbers with account (NNNN XXXXXXX)
        $clearing     = /\b[5-9]\d{3}\s+\d{7,10}\b/

        // Exclusions: common false positives
        $comment      = /\/\/.*(personnummer|pnr|ssn|phone|\btel\b)/i
        $test_label   = /\b(test|example|sample|demo|fake|dummy)\s+(pnr|personnummer|phone|tel)/i
        $yara_rule    = /\$pnr|personnummer.*regex/i

    condition:
        not $comment and
        not $test_label and
        not $yara_rule and
        (
            $pnr_long or $pnr_short or $pnr_no_dash or
            $sam_long or $sam_short or
            $orgnr or $orgnr_short or
            $iban_se or
            $bankgiro or $bg_bare or
            $plusgiro or $pg_bare or
            $phone_mobile or $phone_land or $phone_intl or
            $clearing
        )
}
