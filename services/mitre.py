"""A small, offline MITRE ATT&CK (Enterprise) lookup.

Two jobs:

* **Enrichment** — turn a bare technique ID (``T1190``) asserted by the scanner,
  or returned by the LLM, into a named technique with its tactic.
* **Fallback mapping** — keyword-map a finding onto plausible techniques when
  no LLM is available.

This is intentionally a curated subset covering what web/infrastructure
scanners actually surface, not a full ATT&CK mirror. Extend :data:`TECHNIQUES`
as coverage needs grow, or swap this module for a STIX-backed loader; the
public functions are the only contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class TechniqueInfo:
    """One ATT&CK technique: identifier, name and its primary tactic."""

    id: str
    name: str
    tactic: str


TECHNIQUES: dict[str, TechniqueInfo] = {
    t.id: t
    for t in (
        # Reconnaissance
        TechniqueInfo("T1595", "Active Scanning", "Reconnaissance"),
        TechniqueInfo("T1595.002", "Vulnerability Scanning", "Reconnaissance"),
        TechniqueInfo("T1592", "Gather Victim Host Information", "Reconnaissance"),
        TechniqueInfo("T1590", "Gather Victim Network Information", "Reconnaissance"),
        TechniqueInfo("T1596", "Search Open Technical Databases", "Reconnaissance"),
        # Initial Access
        TechniqueInfo("T1190", "Exploit Public-Facing Application", "Initial Access"),
        TechniqueInfo("T1133", "External Remote Services", "Initial Access"),
        TechniqueInfo("T1078", "Valid Accounts", "Initial Access"),
        TechniqueInfo("T1078.001", "Default Accounts", "Initial Access"),
        TechniqueInfo("T1189", "Drive-by Compromise", "Initial Access"),
        TechniqueInfo("T1195", "Supply Chain Compromise", "Initial Access"),
        # Execution
        TechniqueInfo("T1059", "Command and Scripting Interpreter", "Execution"),
        TechniqueInfo("T1059.007", "JavaScript", "Execution"),
        TechniqueInfo("T1203", "Exploitation for Client Execution", "Execution"),
        # Persistence
        TechniqueInfo("T1505", "Server Software Component", "Persistence"),
        TechniqueInfo("T1505.003", "Web Shell", "Persistence"),
        TechniqueInfo("T1136", "Create Account", "Persistence"),
        # Privilege Escalation
        TechniqueInfo("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
        TechniqueInfo("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
        # Defense Evasion
        TechniqueInfo("T1562", "Impair Defenses", "Defense Evasion"),
        TechniqueInfo("T1553", "Subvert Trust Controls", "Defense Evasion"),
        TechniqueInfo("T1211", "Exploitation for Defense Evasion", "Defense Evasion"),
        # Credential Access
        TechniqueInfo("T1110", "Brute Force", "Credential Access"),
        TechniqueInfo("T1110.001", "Password Guessing", "Credential Access"),
        TechniqueInfo("T1552", "Unsecured Credentials", "Credential Access"),
        TechniqueInfo("T1552.001", "Credentials In Files", "Credential Access"),
        TechniqueInfo("T1040", "Network Sniffing", "Credential Access"),
        TechniqueInfo("T1557", "Adversary-in-the-Middle", "Credential Access"),
        TechniqueInfo("T1539", "Steal Web Session Cookie", "Credential Access"),
        TechniqueInfo("T1212", "Exploitation for Credential Access", "Credential Access"),
        # Discovery
        TechniqueInfo("T1046", "Network Service Discovery", "Discovery"),
        TechniqueInfo("T1518", "Software Discovery", "Discovery"),
        TechniqueInfo("T1082", "System Information Discovery", "Discovery"),
        TechniqueInfo("T1083", "File and Directory Discovery", "Discovery"),
        TechniqueInfo("T1087", "Account Discovery", "Discovery"),
        # Lateral Movement
        TechniqueInfo("T1210", "Exploitation of Remote Services", "Lateral Movement"),
        TechniqueInfo("T1550", "Use Alternate Authentication Material", "Lateral Movement"),
        # Collection
        TechniqueInfo("T1213", "Data from Information Repositories", "Collection"),
        TechniqueInfo("T1119", "Automated Collection", "Collection"),
        TechniqueInfo("T1185", "Browser Session Hijacking", "Collection"),
        # Command and Control
        TechniqueInfo("T1071", "Application Layer Protocol", "Command and Control"),
        TechniqueInfo("T1071.001", "Web Protocols", "Command and Control"),
        TechniqueInfo("T1573", "Encrypted Channel", "Command and Control"),
        # Exfiltration
        TechniqueInfo("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        TechniqueInfo("T1567", "Exfiltration Over Web Service", "Exfiltration"),
        # Impact
        TechniqueInfo("T1499", "Endpoint Denial of Service", "Impact"),
        TechniqueInfo("T1486", "Data Encrypted for Impact", "Impact"),
        TechniqueInfo("T1565", "Data Manipulation", "Impact"),
    )
}

# Keyword → technique IDs, consulted in order. First match wins per group, but
# every matching rule contributes, so a "SQL injection on admin login" maps to
# both exploitation and credential-access techniques.
_KEYWORD_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (r"sql\s*injection|sqli\b", ("T1190", "T1213")),
    (r"cross[- ]site scripting|\bxss\b", ("T1059.007", "T1185", "T1539")),
    (r"remote code execution|\brce\b|command injection", ("T1190", "T1059", "T1505.003")),
    (r"deserializ", ("T1190", "T1059")),
    (r"path traversal|directory traversal|lfi\b|local file inclusion", ("T1190", "T1083")),
    (r"ssrf|server[- ]side request forgery", ("T1190", "T1046")),
    (r"csrf|cross[- ]site request forgery", ("T1189", "T1565")),
    (r"xxe|xml external entity", ("T1190", "T1083")),
    (r"default (credential|password|account)|weak password|admin:admin", ("T1078.001", "T1110")),
    (r"brute[- ]?force|credential stuffing|no rate limit", ("T1110.001",)),
    (r"authentication bypass|missing authentication|unauthenticated", ("T1190", "T1078")),
    (r"authoriz|access control|idor|privilege", ("T1068", "T1548")),
    (r"exposed (secret|key|token)|api key|hardcoded|credentials in", ("T1552.001", "T1552")),
    (r"\.git|\.env|backup file|config file expos", ("T1552.001", "T1083")),
    (r"directory listing|directory index", ("T1083", "T1592")),
    (r"expired.*cert|self[- ]signed|certificate", ("T1553", "T1557")),
    (r"weak cipher|deprecated tls|ssl ?v[23]|tls ?1\.[01]|poodle|beast", ("T1557", "T1040")),
    (r"missing.*header|clickjack|x-frame-options|csp\b|hsts", ("T1189", "T1185")),
    (r"cookie|session", ("T1539", "T1550")),
    (r"open redirect", ("T1189",)),
    (r"subdomain takeover", ("T1584", "T1189")),
    (r"denial of service|\bdos\b|resource exhaustion", ("T1499",)),
    (r"open port|service detect|port scan|nmap", ("T1046",)),
    (r"version|banner|technology detect|fingerprint|apache detect|nginx detect", ("T1518", "T1592")),
    (r"admin (panel|interface|console)|login (page|panel) (found|detect)", ("T1190", "T1087")),
    (r"outdated|end[- ]of[- ]life|unpatched|\bcve-", ("T1190", "T1203")),
    (r"dependency|component with known vuln|supply chain", ("T1195", "T1190")),
    (r"information disclosure|verbose error|stack trace|debug", ("T1592", "T1082")),
    (r"dns\b|zone transfer", ("T1590",)),
)

_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def normalise_id(technique_id: str) -> str:
    """Upper-case and strip a technique ID; returns ``""`` if malformed."""
    candidate = (technique_id or "").strip().upper()
    return candidate if _ID_PATTERN.match(candidate) else ""


def lookup(technique_id: str) -> Optional[TechniqueInfo]:
    """Return catalog data for ``technique_id``, or ``None`` if unknown.

    Falls back to the parent technique for an unknown sub-technique, so
    ``T1190.999`` still resolves to *Exploit Public-Facing Application*.
    """
    normalised = normalise_id(technique_id)
    if not normalised:
        return None
    if normalised in TECHNIQUES:
        return TECHNIQUES[normalised]
    parent = normalised.split(".")[0]
    return TECHNIQUES.get(parent)


def enrich(technique_id: str) -> TechniqueInfo:
    """Like :func:`lookup`, but always returns something usable."""
    found = lookup(technique_id)
    if found is not None:
        return found
    normalised = normalise_id(technique_id) or (technique_id or "").strip()
    return TechniqueInfo(normalised, "Unmapped technique", "Unknown")


def map_text(*fragments: str, asserted: Iterable[str] = ()) -> list[TechniqueInfo]:
    """Map free text (title, description, evidence) onto ATT&CK techniques.

    Args:
        *fragments: Text to inspect, typically title + description + evidence.
        asserted: Technique IDs the scanner already claimed; these are always
            included first, enriched with catalog metadata.

    Returns:
        De-duplicated techniques, scanner-asserted ones first.
    """
    results: list[TechniqueInfo] = []
    seen: set[str] = set()

    for technique_id in asserted:
        info = lookup(technique_id)
        if info and info.id not in seen:
            seen.add(info.id)
            results.append(info)

    haystack = " ".join(fragment or "" for fragment in fragments).lower()
    for pattern, technique_ids in _KEYWORD_RULES:
        if re.search(pattern, haystack):
            for technique_id in technique_ids:
                info = TECHNIQUES.get(technique_id)
                if info and info.id not in seen:
                    seen.add(info.id)
                    results.append(info)
    return results


def tactics_for(techniques: Iterable[TechniqueInfo]) -> list[str]:
    """Distinct tactics covered by ``techniques``, in first-seen order."""
    ordered: list[str] = []
    for technique in techniques:
        if technique.tactic and technique.tactic not in ordered:
            ordered.append(technique.tactic)
    return ordered


__all__ = [
    "TECHNIQUES",
    "TechniqueInfo",
    "enrich",
    "lookup",
    "map_text",
    "normalise_id",
    "tactics_for",
]
