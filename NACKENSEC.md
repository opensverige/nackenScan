# NäckenSec — Swedish AI Security Intelligence

A Swedish security extension for [Cisco's skill-scanner](https://github.com/cisco-ai-defense/skill-scanner).

**Organization:** [opensverige.se](https://opensverige.se)
**Fork:** [github.com/opensverige/nackensec-scan](https://github.com/opensverige/nackensec-scan)
**License:** AGPL-3.0 — see [LICENSE](LICENSE) for dual-license structure
**Commercial licensing:** licensing@opensverige.se

---

## What We Add

Cisco's scanner covers 13 analysis passes for English-language agent skills.
NäckenSec adds Swedish domain intelligence that no other tool has:

| Feature | Details |
|---------|---------|
| **Luhn-validated personnummer** | Detects Swedish SSNs with Skatteverket checksum |
| **Samordningsnummer** | Coordination numbers (day + 60) |
| **Organisationsnummer** | Swedish company ID with Luhn validation |
| **Swedish bank accounts** | Bankgiro, Plusgiro, IBAN SE, clearing numbers |
| **Fortnox API awareness** | Tiered risk map for 15+ Fortnox endpoints |
| **Swedish prompt injection** | 40+ Swedish + svengelska injection patterns |
| **EU AI Act compliance** | Art. 5 (prohibited), Art. 9-15 (high-risk), Art. 50 (disclosure) |
| **IMY/GDPR references** | Findings link to IMY, Datainspektionen, Konsumentverket |

---

## Installation

```bash
pip install git+https://github.com/opensverige/nackensec-scan.git
```

Or from source:

```bash
git clone https://github.com/opensverige/nackensec-scan.git
cd nackensec-scan
pip install -e .
```

---

## Usage

```bash
# Standard scan (NäckenSec analyzers included automatically)
nackensec-scan scan /path/to/agent

# Swedish output
nackensec-scan scan /path/to/agent --lang sv

# Disable specific analyzers
nackensec-scan scan /path/to/agent --no-fortnox --no-eu-ai

# JSON output (API/CI integration)
nackensec-scan scan /path/to/agent --format json

# SARIF output (GitHub Code Scanning)
nackensec-scan scan /path/to/agent --format sarif
```

---

## Swedish Analyzers

### SwePIIAnalyzer (`nackensec/analyzers/swe_pii_analyzer.py`)

Two-layer detection:
1. **YARA pre-filter** — fast pattern match against `nackensec/rules/swedish/swe_pii.yara`
2. **Python + Luhn** — validates checksum before reporting

Severity mapping:

| Type | Rule ID | Severity |
|------|---------|----------|
| Personnummer (valid Luhn) | `SWE_PII_PNR` | HIGH |
| Personnummer (bad Luhn) | `SWE_PII_PNR_SUSPECT` | INFO |
| Organisationsnummer | `SWE_PII_ORGNR` | MEDIUM |
| Bankgiro / IBAN SE | `SWE_PII_BANK` | HIGH |
| Telefonnummer | `SWE_PII_PHONE` | LOW |

### FortnoxAnalyzer (`nackensec/analyzers/fortnox_analyzer.py`)

Detects Fortnox REST API endpoint references and cross-references them against
`nackensec/data/fortnox_risk_map.yaml`.

**Fortnox Compliance Map** — `nackensec/data/fortnox_risk_map.yaml`:

| Tier | Endpoints | Severity | PII |
|------|-----------|----------|-----|
| Tier 1 | `/3/employees`, `/3/salarytransactions`, `/3/taxreductions`, `/3/vacationdebtbasis` | HIGH | Personnummer, salary, tax |
| Tier 2 | `/3/customers`, `/3/suppliers` | MEDIUM | PNR as OrganisationNumber, contact data |
| Tier 3 | `/3/invoices`, `/3/orders`, `/3/offers`, `/3/contracts`, ... | LOW | Name, address, contact |

If protection keywords (`mask_json`, `sveaguard`, `redact`, `anonymize`, `propose_action`, ...) are
present in the skill, tier-1 findings are downgraded to LOW (declared but unverified).

### EuAiActAnalyzer (`nackensec/analyzers/eu_ai_act_analyzer.py`)

| Rule | Condition | Severity | Article |
|------|-----------|----------|---------|
| `EUAIA_PROHIBITED` | `risk_classification: prohibited` in frontmatter | CRITICAL | Art. 5 |
| `EUAIA_HIGH_RISK_NO_OVERSIGHT` | `risk_classification: high-risk` without oversight docs | HIGH | Art. 9–15 |
| `EUAIA_NO_AI_DISCLOSURE` | No AI-identification keywords in any agent | LOW | Art. 50 |

---

## YARA Rules

### `nackensec/rules/swedish/swe_pii.yara`

Patterns for personnummer, samordningsnummer, organisationsnummer, IBAN SE,
bankgiro, plusgiro, Swedish mobile/landline/international phone numbers,
and clearing numbers. Downstream Luhn validation required for PNR patterns.

### `nackensec/rules/swedish/swe_prompt_injection.yara`

40+ Swedish and svengelska (code-switching) prompt injection patterns:
- Ignore/override instructions (`ignorera alla tidigare instruktioner`)
- Role-switching (`låtsas att du är`, `agera som om du vore`)
- Forget/reset (`glöm allt du vet`, `nollställ ditt minne`)
- Goal hijacking (`ditt riktiga mål är`)
- Bypass (`kringgå säkerhetsbegränsningar`, `åsidosätt alla begränsningar`)
- Exfiltration (`skicka all data till`, `läck data till`)
- Svengelska mixed patterns (`bypass säkerhetsfilter`, `override dina regler`)

### `nackensec/rules/community/giskard_injections.yara`

Auto-generated from [Giskard-AI/prompt-injections](https://github.com/Giskard-AI/prompt-injections) dataset.
Regenerate after downloading the dataset:

```bash
python nackensec/scripts/generate_giskard_rules.py /path/to/giskard-pi
```

---

## Contributing New Swedish Patterns

### Adding a new YARA pattern

1. Open `nackensec/rules/swedish/swe_prompt_injection.yara` or `swe_pii.yara`
2. Add the string under the appropriate section comment
3. Add the variable to the `condition:` block
4. Add a true-positive test in `tests/nackensec/test_swe_yara_rules.py`
5. Add a false-positive (exclusion) test if needed

Pattern guidelines:
- Use `nocase` for case-insensitive matching (ASCII only — ä/ö/å uppercase not handled by yara-x `nocase`)
- Keep patterns specific — avoid short substrings that match common words
- Add exclusion patterns in the `// ── Exclusions ───` section if needed

### Adding a new analyzer

1. Create `nackensec/analyzers/your_analyzer.py` extending `BaseAnalyzer`
2. Add the analyzer to `nackensec/cli.py::_build_nackensec_analyzers()`
3. Add a `--no-your-analyzer` flag to the CLI pre-parser
4. Write tests in `tests/nackensec/test_your_analyzer.py`

### Adding Fortnox endpoints

Edit `nackensec/data/fortnox_risk_map.yaml`:
- Tier 1: endpoints handling personnummer, salary, tax
- Tier 2: endpoints handling customer/supplier contact data
- Tier 3: endpoints handling business documents

---

## Architecture

All NäckenSec code lives in `nackensec/` — no upstream files modified.

```
nackensec/
├── analyzers/          # SwePIIAnalyzer, FortnoxAnalyzer, EuAiActAnalyzer
├── data/               # fortnox_risk_map.yaml
├── output/             # swedish_formatter.py (--lang sv)
├── rules/
│   ├── community/      # giskard_injections.yara (generated)
│   └── swedish/        # swe_pii.yara, swe_prompt_injection.yara
├── scripts/            # generate_giskard_rules.py
├── validators.py       # Luhn-10, personnummer/organisationsnummer validators
└── cli.py              # nackensec-scan entry point
```

Upstream merges: `git fetch upstream && git merge upstream/main` is conflict-free
except for `pyproject.toml [project.scripts]` and `[project]` metadata.

---

## License Structure

```
LICENSE          — Dual-license notice (this file)
LICENSE-APACHE   — Apache 2.0 (Cisco skill-scanner upstream code)
LICENSE-AGPL     — AGPL-3.0 (NäckenSec additions in nackensec/)
THIRD_PARTY.md   — Full attribution for all third-party code and datasets
```

All files in `nackensec/` are AGPL-3.0. All upstream `skill_scanner/` files are Apache 2.0.

---

## Attribution

Built on Cisco's skill-scanner (Apache 2.0).
Swedish YARA rules derived from Giskard-AI/prompt-injections (Apache 2.0).
See [THIRD_PARTY.md](THIRD_PARTY.md) for complete attribution.
