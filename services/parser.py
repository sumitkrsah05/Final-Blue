"""Resilient Red Agent report parser.

The Red Agent's JSON schema evolves. This module is the *only* place that knows
about that instability: it maps whatever arrived onto the normalised
:class:`~models.schemas.RedTeamReport` and never raises on a merely unfamiliar
document. The contract is deliberately forgiving:

* Field names are resolved through alias chains (``description`` /
  ``detail`` / ``matched_at`` / ``info.description`` ...).
* Missing values become neutral defaults, never ``KeyError``.
* Unrecognised keys survive in ``RedFinding.extra`` and ``RedTeamReport.raw``,
  so no data is silently lost and future fields can be promoted later.
* Only genuinely unusable input (unreadable file, malformed JSON, a document
  that is not an object or list) raises :class:`ReportParseError`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence, Union

import orjson

from models.schemas import RedFinding, RedTeamReport, Severity
from utils.logger import get_logger

log = get_logger(__name__)

JSONDocument = Union[Mapping[str, Any], Sequence[Any]]

# --- Alias chains ----------------------------------------------------------
# Ordered by preference; the first key present and non-empty wins.
_FINDING_LIST_KEYS = ("findings", "vulnerabilities", "issues", "results", "items")
_SUMMARY_KEYS = ("summary", "posture", "statistics", "stats", "overview", "metrics")
_TARGET_KEYS = ("target", "targets", "host", "hostname", "url", "scope", "asset", "domain")
_ENGAGEMENT_KEYS = ("engagement_id", "engagementId", "id", "run_id", "scan_id", "uuid")
_MODE_KEYS = ("mode", "assessment_mode", "test_type", "engagement_mode")

_ID_KEYS = ("id", "finding_id", "uuid", "ref", "template-id", "template_id")
_TITLE_KEYS = ("title", "name", "vulnerability", "issue", "template_name", "matcher_name")
_SEVERITY_KEYS = ("severity", "risk_level", "criticality", "level", "priority")
_DESCRIPTION_KEYS = (
    "description",
    "desc",
    "details",
    "detail",
    "summary",
    "explanation",
    "impact",
)
_EVIDENCE_KEYS = (
    "evidence",
    "proof",
    "poc",
    "request",
    "response",
    "matched_at",
    "matched-at",
    "extracted_results",
    "raw",
    "output",
)
_ASSET_KEYS = ("asset", "target", "host", "url", "endpoint", "location", "affected_asset")
_TOOL_KEYS = ("tool", "tools", "sources", "source", "scanner", "engine", "plugin")
_REFERENCE_KEYS = ("references", "reference", "refs", "links", "urls", "see_also")
_CVE_KEYS = ("cve_ids", "cve", "cves", "cve_id", "identifiers")
_TECHNIQUE_KEYS = ("techniques", "mitre", "mitre_techniques", "attack_techniques", "ttps")
_CVSS_KEYS = ("cvss", "cvss_score", "cvss_base_score", "score", "cvss3", "cvssScore")
_EPSS_KEYS = ("epss", "epss_score", "exploit_probability")
_RISK_KEYS = ("risk", "risk_score", "riskScore")
_PRIORITY_KEYS = ("priority", "remediation_priority", "urgency")
_DETECTION_KEYS = ("detection", "detected", "detection_status", "verdict")

# Keys already consumed by the normaliser; anything else lands in ``extra``.
_CONSUMED_FINDING_KEYS = frozenset(
    _ID_KEYS
    + _TITLE_KEYS
    + _SEVERITY_KEYS
    + _DESCRIPTION_KEYS
    + _EVIDENCE_KEYS
    + _ASSET_KEYS
    + _TOOL_KEYS
    + _REFERENCE_KEYS
    + _CVE_KEYS
    + _TECHNIQUE_KEYS
    + _CVSS_KEYS
    + _EPSS_KEYS
    + _RISK_KEYS
    + _PRIORITY_KEYS
    + _DETECTION_KEYS
)


class ReportParseError(ValueError):
    """Raised only when the input cannot be read as a JSON document at all."""


# ---------------------------------------------------------------------------
# Primitive extraction helpers
# ---------------------------------------------------------------------------


def _first(source: Mapping[str, Any], keys: Iterable[str]) -> Any:
    """Return the first present, non-empty value among ``keys``.

    Also looks one level into common nested containers (``info``, ``metadata``,
    ``details``) because scanner exports frequently bury fields there.
    """
    for key in keys:
        if key in source:
            value = source[key]
            if value not in (None, "", [], {}):
                return value
    for container in ("info", "metadata", "meta", "details", "attributes"):
        nested = source.get(container)
        if isinstance(nested, Mapping):
            for key in keys:
                value = nested.get(key)
                if value not in (None, "", [], {}):
                    return value
    return None


def _as_text(value: Any, *, max_chars: int = 8000) -> str:
    """Flatten any JSON value into readable text, bounded in length."""
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, (int, float, bool)):
        text = str(value)
    elif isinstance(value, Mapping):
        text = "; ".join(f"{k}: {_as_text(v, max_chars=512)}" for k, v in value.items())
    elif isinstance(value, Sequence):
        text = "; ".join(_as_text(item, max_chars=512) for item in value)
    else:
        text = str(value)
    text = text.strip()
    return text if len(text) <= max_chars else f"{text[:max_chars]}… [truncated]"


def _as_str_list(value: Any) -> list[str]:
    """Coerce a scalar / list / dict into a de-duplicated list of strings."""
    if value in (None, "", [], {}):
        return []
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, Mapping):
        candidates = [_as_text(item, max_chars=256) for item in value.values()]
    elif isinstance(value, Sequence):
        candidates = [
            item if isinstance(item, str) else _as_text(item, max_chars=256)
            for item in value
        ]
    else:
        candidates = [str(value)]

    seen: set[str] = set()
    out: list[str] = []
    for candidate in candidates:
        text = candidate.strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _as_float(value: Any) -> Optional[float]:
    """Parse a number out of a scalar, a dict (``{"score": 8.8}``) or a string."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, Mapping):
        for key in ("score", "base_score", "baseScore", "value"):
            if key in value:
                return _as_float(value[key])
        return None
    if isinstance(value, Sequence) and not isinstance(value, str):
        for item in value:
            parsed = _as_float(item)
            if parsed is not None:
                return parsed
        return None
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def _normalise_cves(value: Any) -> list[str]:
    """Keep only things that look like CVE identifiers, upper-cased."""
    return [item.upper() for item in _as_str_list(value) if item.upper().startswith("CVE-")]


def _normalise_techniques(value: Any) -> list[str]:
    """Extract MITRE technique IDs (``T1190``, ``T1059.001``) from any shape."""
    out: list[str] = []
    for item in _as_str_list(value):
        for token in item.replace(",", " ").split():
            candidate = token.strip(" .;:[]()").upper()
            if candidate.startswith("T") and candidate[1:].replace(".", "").isdigit():
                if candidate not in out:
                    out.append(candidate)
    return out


# ---------------------------------------------------------------------------
# Finding + report normalisation
# ---------------------------------------------------------------------------


def _normalise_finding(raw: Any, index: int) -> RedFinding:
    """Map one raw finding onto :class:`RedFinding`, tolerating any shape."""
    if not isinstance(raw, Mapping):
        # A bare string in the findings array still deserves to be analysed.
        return RedFinding(
            id=f"finding-{index + 1}",
            title=_as_text(raw, max_chars=200) or f"Finding {index + 1}",
            description=_as_text(raw),
        )

    cvss = _as_float(_first(raw, _CVSS_KEYS))
    severity_raw = _first(raw, _SEVERITY_KEYS)
    severity = Severity.coerce(severity_raw)
    if severity is Severity.UNKNOWN and cvss is not None:
        # No usable severity label, but a CVSS score is authoritative enough.
        severity = Severity.from_cvss(cvss)

    finding = RedFinding(
        id=_as_text(_first(raw, _ID_KEYS), max_chars=128) or f"finding-{index + 1}",
        title=_as_text(_first(raw, _TITLE_KEYS), max_chars=300) or f"Finding {index + 1}",
        severity=severity,
        cvss=cvss,
        epss=_as_float(_first(raw, _EPSS_KEYS)),
        risk_score=_as_float(_first(raw, _RISK_KEYS)),
        priority=_as_text(_first(raw, _PRIORITY_KEYS), max_chars=64) or None,
        description=_as_text(_first(raw, _DESCRIPTION_KEYS)),
        evidence=_as_text(_first(raw, _EVIDENCE_KEYS)),
        asset=_as_text(_first(raw, _ASSET_KEYS), max_chars=300),
        tools=_as_str_list(_first(raw, _TOOL_KEYS)),
        references=_as_str_list(_first(raw, _REFERENCE_KEYS)),
        cve_ids=_normalise_cves(_first(raw, _CVE_KEYS)),
        techniques=_normalise_techniques(_first(raw, _TECHNIQUE_KEYS)),
        detection=_as_text(_first(raw, _DETECTION_KEYS), max_chars=64) or None,
        extra={k: v for k, v in raw.items() if k not in _CONSUMED_FINDING_KEYS},
    )
    return finding


def _locate_findings(document: Mapping[str, Any]) -> list[Any]:
    """Find the findings array, searching nested containers if necessary."""
    for key in _FINDING_LIST_KEYS:
        value = document.get(key)
        if isinstance(value, list):
            return value
        # Some exporters key findings by id: {"findings": {"f-1": {...}}}
        if isinstance(value, Mapping) and value:
            return list(value.values())

    # Fall back to a shallow search of nested objects (e.g. {"report": {...}}).
    for value in document.values():
        if isinstance(value, Mapping):
            nested = _locate_findings(value)
            if nested:
                return nested
    return []


def _derive_target(document: Mapping[str, Any], findings: Sequence[RedFinding]) -> str:
    """Resolve the engagement target, falling back to the most common asset."""
    explicit = _first(document, _TARGET_KEYS)
    if explicit is not None:
        as_list = _as_str_list(explicit)
        if as_list:
            return ", ".join(as_list[:3])

    assets = [f.asset for f in findings if f.asset]
    if assets:
        # Most frequently referenced asset is the best guess at "the target".
        return max(set(assets), key=assets.count)
    return "unspecified target"


def _derive_summary(document: Mapping[str, Any], findings: Sequence[RedFinding]) -> dict[str, Any]:
    """Use the report's own roll-up when present, else compute one."""
    raw_summary = _first(document, _SUMMARY_KEYS)
    summary: dict[str, Any] = dict(raw_summary) if isinstance(raw_summary, Mapping) else {}
    if raw_summary is not None and not isinstance(raw_summary, Mapping):
        summary["source_summary"] = _as_text(raw_summary)

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    summary.setdefault("total_findings", len(findings))
    summary["severity_counts"] = counts
    return summary


def parse_report(source: Union[str, Path, JSONDocument]) -> RedTeamReport:
    """Parse a Red Agent report from a path, a JSON string, or a loaded object.

    Args:
        source: Filesystem path, raw JSON text, or an already-decoded
            mapping/sequence.

    Returns:
        The normalised :class:`RedTeamReport`.

    Raises:
        ReportParseError: The input could not be decoded as JSON, or decoded to
            something that is neither an object nor a list.
    """
    document, origin = _load_document(source)

    if isinstance(document, list):
        # A bare array of findings is a legitimate (if minimal) report.
        document = {"findings": document}
    if not isinstance(document, Mapping):
        raise ReportParseError(
            f"expected a JSON object or array at the top level, got {type(document).__name__}"
        )

    raw_findings = _locate_findings(document)
    if not raw_findings:
        log.warning("No findings array located in {} — producing an empty report", origin)

    findings = [_normalise_finding(raw, index) for index, raw in enumerate(raw_findings)]

    report = RedTeamReport(
        engagement_id=_as_text(_first(document, _ENGAGEMENT_KEYS), max_chars=128)
        or "unknown-engagement",
        mode=_as_text(_first(document, _MODE_KEYS), max_chars=64) or "unknown",
        target=_derive_target(document, findings),
        summary=_derive_summary(document, findings),
        findings=findings,
        attack_paths=_coerce_list(document.get("attack_paths")),
        coverage_gaps=_coerce_list(document.get("gaps") or document.get("coverage_gaps")),
        source_path=origin,
        raw=dict(document),
    )
    log.info(
        "Parsed report {} — {} finding(s), target={}",
        report.engagement_id,
        len(report.findings),
        report.target,
    )
    return report


def _coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, Mapping):
        return list(value.values())
    return [value]


def _load_document(source: Union[str, Path, JSONDocument]) -> tuple[Any, str]:
    """Decode ``source`` into a Python object plus a human-readable origin."""
    if isinstance(source, (Mapping, list)):
        return source, "<in-memory document>"

    if isinstance(source, Path) or (
        isinstance(source, str) and not source.lstrip().startswith(("{", "["))
    ):
        path = Path(source)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise ReportParseError(f"cannot read report file {path}: {exc}") from exc
        try:
            return orjson.loads(payload), str(path)
        except orjson.JSONDecodeError as exc:
            raise ReportParseError(f"invalid JSON in {path}: {exc}") from exc

    try:
        return json.loads(source), "<json string>"
    except json.JSONDecodeError as exc:
        raise ReportParseError(f"invalid JSON string: {exc}") from exc


class ReportParser:
    """Thin object wrapper, for callers that prefer dependency injection."""

    def parse(self, source: Union[str, Path, JSONDocument]) -> RedTeamReport:
        """Parse ``source`` into a normalised report. See :func:`parse_report`."""
        return parse_report(source)


__all__ = ["ReportParseError", "ReportParser", "parse_report"]
