# Third-Party Attributions

NäckenSec is built on the following open source projects:

## cisco-ai-defense/skill-scanner
- **License:** Apache 2.0
- **URL:** https://github.com/cisco-ai-defense/skill-scanner
- **Use:** Core analysis engine, base classes, YARA infrastructure
- **Note:** This repository is a fork. All upstream code retains Cisco copyright.

## Giskard-AI/prompt-injections
- **License:** Apache 2.0
- **URL:** https://github.com/Giskard-AI/prompt-injections
- **Use:** Prompt injection payload dataset → YARA rules (nackensec/rules/community/)
- **Generated rules:** nackensec/rules/community/giskard_injections.yara

## Research References (not code)

### Open-Prompt-Injection
- **License:** MIT
- **URL:** https://github.com/liu00222/Open-Prompt-Injection
- **Papers:** USENIX Security 2024, IEEE S&P 2025-2026
- **Use:** Attack taxonomy informs our finding categories

### awesome-prompt-injection
- **URL:** https://github.com/Joe-B-Security/awesome-prompt-injection
- **Use:** Reference for attack surface coverage (March 2026 edition)

### promptfoo
- **License:** MIT
- **URL:** https://github.com/promptfoo/promptfoo
- **Use:** Recommended as dynamic red teaming companion

### Snyk agent-scan
- **License:** Apache 2.0
- **URL:** https://github.com/snyk/agent-scan
- **Use:** Risk taxonomy reference for attack surface coverage

## Regulatory References

- **EU AI Act:** Förordning (EU) 2024/1689 — https://eur-lex.europa.eu/legal-content/SV/TXT/?uri=CELEX:32024R1689
- **IMY (Integritetsskyddsmyndigheten):** https://www.imy.se/
- **Konsumentverket:** https://www.konsumentverket.se/
- **Datainspektionen:** https://www.datainspektionen.se/
- **Skatteverket (Personnummer algoritm):** https://www.skatteverket.se/
