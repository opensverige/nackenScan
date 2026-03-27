"""Swedish output formatter for NäckenSec scan results."""

from __future__ import annotations

from skill_scanner.core.models import Finding, ScanResult, Severity

# Swedish severity display names
_SV_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "KRITISK",
    Severity.HIGH: "HÖG",
    Severity.MEDIUM: "MEDEL",
    Severity.LOW: "LÅG",
    Severity.INFO: "INFO",
    Severity.SAFE: "SÄKER",
}

# Swedish category display names
_SV_CATEGORY: dict[str, str] = {
    "prompt_injection": "Prompt-injektion",
    "command_injection": "Kommandoinjektion",
    "hardcoded_secrets": "Hårdkodad hemlighet",
    "data_exfiltration": "Dataexfiltrering",
    "policy_violation": "Regelöverträdelse",
    "unauthorized_tool_use": "Obehörig verktygsanvändning",
    "obfuscation": "Obfuskering",
    "social_engineering": "Social manipulation",
    "resource_abuse": "Resursmissbruk",
    "malware": "Skadlig kod",
    "harmful_content": "Skadligt innehåll",
    "supply_chain_attack": "Leveranskedjeattack",
    "skill_discovery_abuse": "Missbruk av färdighetssökning",
    "transitive_trust_abuse": "Missbruk av transiterat förtroende",
    "autonomy_abuse": "Missbruk av autonomi",
    "tool_chaining_abuse": "Missbruk av verktygskedja",
    "unicode_steganography": "Unicode-steganografi",
}


def sv_severity(severity: Severity) -> str:
    """Return the Swedish display name for a severity level."""
    return _SV_SEVERITY.get(severity, severity.value)


def sv_category(category_value: str) -> str:
    """Return the Swedish display name for a threat category value."""
    return _SV_CATEGORY.get(category_value, category_value)


def format_finding_sv(f: Finding, index: int) -> str:
    """Format a single finding in Swedish."""
    lines = [
        f"[{index}] {sv_severity(f.severity)} — {f.title}",
        f"    Regel:       {f.rule_id}",
        f"    Kategori:    {sv_category(f.category.value)}",
    ]
    if f.file_path:
        loc = f.file_path
        if f.line_number:
            loc += f":{f.line_number}"
        lines.append(f"    Plats:       {loc}")
    if f.snippet:
        lines.append(f"    Utdrag:      {f.snippet[:80]!r}")
    lines.append(f"    Beskrivning: {f.description}")
    if f.remediation:
        lines.append(f"    Åtgärd:      {f.remediation}")
    return "\n".join(lines)


def format_scan_result_sv(result: ScanResult) -> str:
    """Format a complete scan result in Swedish."""
    header_lines = [
        "=" * 72,
        f"NäckenSec Skanningsrapport",
        f"Färdighet:   {result.skill_name}",
        f"Katalog:     {result.skill_directory}",
        f"Tidpunkt:    {result.timestamp.isoformat()}",
        f"Varaktighet: {result.scan_duration_seconds:.2f}s",
    ]

    if result.analyzers_used:
        header_lines.append(f"Analyzers:   {', '.join(result.analyzers_used)}")

    max_sev = sv_severity(result.max_severity)
    safe_label = "JA" if result.is_safe else "NEJ"
    header_lines.append(f"Säker:       {safe_label}  (högsta allvarlighet: {max_sev})")
    header_lines.append(f"Fynd:        {len(result.findings)} totalt")
    header_lines.append("=" * 72)

    sections = ["\n".join(header_lines)]

    if result.findings:
        finding_lines = ["Säkerhetsfynd:", ""]
        for i, finding in enumerate(result.findings, start=1):
            finding_lines.append(format_finding_sv(finding, i))
            finding_lines.append("")
        sections.append("\n".join(finding_lines))
    else:
        sections.append("Inga säkerhetsfynd hittades.")

    return "\n\n".join(sections)
