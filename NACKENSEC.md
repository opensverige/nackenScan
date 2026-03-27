# NäckenSec — Swedish AI Security Intelligence

A Swedish security extension for [Cisco's skill-scanner](https://github.com/cisco-ai-defense/skill-scanner).

**Organization:** [opensverige.se](https://opensverige.se)
**Fork:** [github.com/opensverige/nackensec-scan](https://github.com/opensverige/nackensec-scan)

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

## Installation

```bash
# Clone this fork
git clone https://github.com/opensverige/nackensec-scan.git
cd nackensec-scan
pip install -e .
```

## Usage

```bash
# Standard scan (NäckenSec analyzers included automatically)
nackensec-scan scan /path/to/agent.md

# Swedish output
nackensec-scan scan /path/to/agent.md --lang sv

# Disable specific analyzers
nackensec-scan scan /path/to/agent.md --no-fortnox --no-eu-ai

# JSON output (API/CI integration)
nackensec-scan scan /path/to/agent.md --format json

# SARIF output (GitHub Code Scanning)
nackensec-scan scan /path/to/agent.md --format sarif
```

## Architecture

All NäckenSec code lives in `nackensec/` — no upstream files modified.
Upstream merges: `git fetch upstream && git merge upstream/main` should be conflict-free
except for the `nackensec-scan` entry in `pyproject.toml [project.scripts]`.

## Swedish PII Detection

Findings include Luhn-10 validation. A valid personnummer gets `severity: HIGH`.
A pattern that looks like a personnummer but fails the checksum gets `severity: INFO`
(possible test data).

```
nackensec-scan scan agent.md --format json | jq '.findings[] | select(.rule_id | startswith("SWE_PII"))'
```

## Companion Tools

| Tool | Purpose | Relation |
|------|---------|---------|
| [promptfoo](https://github.com/promptfoo/promptfoo) | Dynamic red teaming | NäckenSec scans statically, promptfoo attacks dynamically |
| [Snyk agent-scan](https://github.com/snyk/agent-scan) | MCP + skill scanning | Complementary, different focus |
| [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Upstream | Our base — 13-pass static analysis |

## Keeping Up with Upstream

```bash
git fetch upstream
git merge upstream/main
# Re-add nackensec-scan entry to pyproject.toml [project.scripts] if needed
pip install -e .
```

## Attribution

Built on Cisco's skill-scanner (Apache 2.0).
Swedish YARA rules derived from Giskard-AI/prompt-injections (Apache 2.0).
See THIRD_PARTY.md for complete attribution.
