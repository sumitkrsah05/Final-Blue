"""Pydantic contracts for everything crossing a module boundary.

Two families live here:

* **Inbound** (:class:`RedFinding`, :class:`RedTeamReport`) — the *normalised*
  view of a Red Agent report. The parser absorbs schema drift so that the rest
  of the agent only ever sees these shapes.
* **Outbound** (:class:`FindingAnalysis`, :class:`BlueAnalysis`) — the Blue
  Team deliverable, serialised to ``blue_analysis.json`` and rendered to
  ``blue_report.md``.

Outbound models are deliberately permissive about *content* (free-text fields
carry the LLM's prose) and strict about *structure*, so a malformed model reply
degrades one section rather than failing the run.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Shared vocabulary
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Normalised severity ladder. ``UNKNOWN`` is a first-class value."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Higher is worse — used for sorting and for the worst-of rollup."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }[self]

    @property
    def label(self) -> str:
        """Title-cased form for reports (``Critical``, ``High``, ...)."""
        return self.value.title()

    @classmethod
    def coerce(cls, value: Any) -> "Severity":
        """Best-effort mapping from whatever the Red Agent emitted.

        Accepts enum members, the usual strings and their aliases
        (``informational``, ``moderate``, ``sev1`` ...), and bare CVSS-style
        numbers, which are bucketed per the CVSS v3.1 qualitative scale.
        """
        if isinstance(value, cls):
            return value
        if value is None:
            return cls.UNKNOWN
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return cls.from_cvss(float(value))

        text = str(value).strip().lower()
        if not text:
            return cls.UNKNOWN
        aliases = {
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "sev0": cls.CRITICAL,
            "sev1": cls.CRITICAL,
            "p0": cls.CRITICAL,
            "emergency": cls.CRITICAL,
            "high": cls.HIGH,
            "important": cls.HIGH,
            "severe": cls.HIGH,
            "sev2": cls.HIGH,
            "p1": cls.HIGH,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "med": cls.MEDIUM,
            "sev3": cls.MEDIUM,
            "p2": cls.MEDIUM,
            "low": cls.LOW,
            "minor": cls.LOW,
            "sev4": cls.LOW,
            "p3": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "information": cls.INFO,
            "none": cls.INFO,
            "note": cls.INFO,
            "unknown": cls.UNKNOWN,
            "undetermined": cls.UNKNOWN,
        }
        if text in aliases:
            return aliases[text]
        try:  # a numeric string such as "8.8"
            return cls.from_cvss(float(text))
        except ValueError:
            return cls.UNKNOWN

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Bucket a 0–10 CVSS base score onto the severity ladder."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


# ---------------------------------------------------------------------------
# Inbound — normalised Red Agent report
# ---------------------------------------------------------------------------


class RedFinding(BaseModel):
    """One vulnerability as reported by the Red Agent, after normalisation.

    Every field except ``title`` is optional: the parser never rejects a
    finding, it fills gaps with neutral defaults and preserves anything it did
    not recognise in :attr:`extra`.
    """

    model_config = ConfigDict(extra="allow")

    id: str = ""
    title: str = "Untitled finding"
    severity: Severity = Severity.UNKNOWN
    cvss: Optional[float] = None
    epss: Optional[float] = None
    risk_score: Optional[float] = Field(
        default=None, description="Red Agent's own 0–100 risk number, if present."
    )
    priority: Optional[str] = None
    description: str = ""
    evidence: str = ""
    asset: str = ""
    tools: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(
        default_factory=list, description="MITRE technique IDs asserted by the scanner."
    )
    detection: Optional[str] = Field(
        default=None, description="Did the blue-team telemetry catch the action?"
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Unrecognised keys, kept verbatim so schema drift is never "
        "silently dropped.",
    )

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: Any) -> Severity:
        return Severity.coerce(value)

    @property
    def display_id(self) -> str:
        return self.id or self.title[:48]

    def context_block(self, *, max_chars: int = 1600) -> str:
        """Compact, token-efficient rendering handed to the LLM."""
        rows: list[tuple[str, str]] = [
            ("ID", self.display_id),
            ("Title", self.title),
            ("Severity", self.severity.label),
            ("CVSS", "n/a" if self.cvss is None else f"{self.cvss}"),
            ("EPSS", "n/a" if self.epss is None else f"{self.epss}"),
            ("Red Agent risk score", "n/a" if self.risk_score is None else f"{self.risk_score}"),
            ("Affected asset", self.asset or "not specified"),
            ("Detected by", ", ".join(self.tools) or "not specified"),
            ("CVE IDs", ", ".join(self.cve_ids) or "none"),
            ("Scanner-asserted ATT&CK techniques", ", ".join(self.techniques) or "none"),
            ("Blue-team detection status", self.detection or "unknown"),
            ("Description", self.description or "not provided by the scanner"),
            ("Evidence", (self.evidence or "not provided")[:max_chars]),
            ("References", ", ".join(self.references[:5]) or "none"),
        ]
        return "\n".join(f"{key}: {value}" for key, value in rows)


class RedTeamReport(BaseModel):
    """A whole Red Agent engagement, normalised."""

    model_config = ConfigDict(extra="allow")

    engagement_id: str = "unknown-engagement"
    mode: str = "unknown"
    target: str = "unspecified target"
    summary: dict[str, Any] = Field(
        default_factory=dict,
        description="Whatever roll-up block the report carried (summary/posture/stats).",
    )
    findings: list[RedFinding] = Field(default_factory=list)
    attack_paths: list[Any] = Field(default_factory=list)
    coverage_gaps: list[Any] = Field(default_factory=list)
    source_path: Optional[str] = None
    raw: dict[str, Any] = Field(
        default_factory=dict, repr=False, description="The untouched input document."
    )

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted_findings(self) -> list[RedFinding]:
        """Worst first: severity, then CVSS, then the Red Agent's risk score."""
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, f.cvss or 0.0, f.risk_score or 0.0),
            reverse=True,
        )


# ---------------------------------------------------------------------------
# Outbound — Blue Team analysis
# ---------------------------------------------------------------------------


class RootCause(BaseModel):
    """Why the weakness exists in the first place."""

    model_config = ConfigDict(extra="allow")

    primary: str = ""
    categories: list[str] = Field(
        default_factory=list,
        description="e.g. misconfiguration, missing patch, weak authentication, "
        "insecure default, exposed secret, missing input validation, weak TLS.",
    )
    explanation: str = ""


class BusinessImpact(BaseModel):
    """Impact assessment across the dimensions management cares about."""

    model_config = ConfigDict(extra="allow")

    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""
    financial: str = ""
    compliance: str = ""
    operational_disruption: str = ""
    reputation: str = ""
    customer_trust: str = ""
    data_exposure: str = ""
    privilege_escalation: str = ""
    lateral_movement: str = ""
    remote_compromise: str = ""
    narrative: str = Field(default="", description="Prose roll-up of the above.")


class MitreTechnique(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = ""
    name: str = ""
    tactic: str = ""
    rationale: str = ""


class MitreAttack(BaseModel):
    """ATT&CK mapping. An empty mapping with a note is a valid answer."""

    model_config = ConfigDict(extra="allow")

    tactics: list[str] = Field(default_factory=list)
    techniques: list[MitreTechnique] = Field(default_factory=list)
    notes: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.tactics and not self.techniques


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="allow")

    overall_risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    likelihood: str = "Unknown"
    impact: str = "Unknown"
    priority: str = "P3"
    risk_category: Severity = Severity.UNKNOWN
    reasoning: str = ""

    @field_validator("risk_category", mode="before")
    @classmethod
    def _coerce_category(cls, value: Any) -> Severity:
        return Severity.coerce(value)

    @field_validator("overall_risk_score", mode="before")
    @classmethod
    def _clamp_score(cls, value: Any) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            return 0.0
        return min(max(score, 0.0), 10.0)


class Recommendation(BaseModel):
    """A single remediation step, bucketed by horizon and control type."""

    model_config = ConfigDict(extra="allow")

    horizon: str = Field(
        default="short_term",
        description="immediate | short_term | long_term",
    )
    category: str = Field(
        default="hardening",
        description="patch | configuration | hardening | monitoring | detection | "
        "preventive | compensating | architecture",
    )
    action: str = ""
    rationale: str = ""
    effort: str = ""

    @field_validator("horizon", mode="before")
    @classmethod
    def _normalise_horizon(cls, value: Any) -> str:
        text = str(value or "short_term").strip().lower().replace("-", "_").replace(" ", "_")
        if text in {"now", "urgent", "immediate", "immediately"}:
            return "immediate"
        if text in {"long_term", "strategic", "long"}:
            return "long_term"
        if text in {"short_term", "short", "tactical"}:
            return "short_term"
        return text or "short_term"


class FindingAnalysis(BaseModel):
    """The Blue Team's verdict on one Red Team finding."""

    model_config = ConfigDict(extra="allow")

    id: str = ""
    title: str = ""
    severity: Severity = Severity.UNKNOWN
    asset: str = ""
    analysis: str = ""
    root_cause: RootCause = Field(default_factory=RootCause)
    business_impact: BusinessImpact = Field(default_factory=BusinessImpact)
    mitre_attack: MitreAttack = Field(default_factory=MitreAttack)
    risk_assessment: RiskAssessment = Field(default_factory=RiskAssessment)
    recommendations: list[Recommendation] = Field(default_factory=list)
    detection_rules: list[str] = Field(default_factory=list)
    analysis_source: str = Field(
        default="llm",
        description="llm | heuristic — how this section was produced, so readers "
        "can tell AI analysis from the deterministic fallback.",
    )

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: Any) -> Severity:
        return Severity.coerce(value)

    def recommendations_by_horizon(self, horizon: str) -> list[Recommendation]:
        return [r for r in self.recommendations if r.horizon == horizon]


class ExecutiveSummary(BaseModel):
    """Management-facing roll-up."""

    model_config = ConfigDict(extra="allow")

    overall_posture: str = ""
    top_risks: list[str] = Field(default_factory=list)
    most_dangerous_findings: list[str] = Field(default_factory=list)
    security_maturity: str = ""
    recommended_next_steps: list[str] = Field(default_factory=list)
    business_narrative: str = ""


class TechnicalSummary(BaseModel):
    """Engineer-facing roll-up."""

    model_config = ConfigDict(extra="allow")

    developer_guidance: str = ""
    infrastructure_recommendations: list[str] = Field(default_factory=list)
    secure_coding_guidance: list[str] = Field(default_factory=list)
    devsecops_improvements: list[str] = Field(default_factory=list)
    architecture_improvements: list[str] = Field(default_factory=list)


class AnalysisMetadata(BaseModel):
    """Provenance for the run — what analysed what, when, and how."""

    model_config = ConfigDict(extra="allow")

    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    agent: str = "Blue Team Analysis Agent"
    agent_version: str = "1.0.0"
    llm_provider: str = ""
    model_name: str = ""
    source_report: str = ""
    findings_analysed: int = 0
    llm_analysed: int = 0
    heuristic_analysed: int = 0
    degraded: bool = Field(
        default=False,
        description="True when any section fell back to heuristics because the "
        "LLM was unavailable.",
    )


class BlueAnalysis(BaseModel):
    """The complete Blue Team deliverable."""

    model_config = ConfigDict(extra="allow")

    engagement_id: str = ""
    target: str = ""
    mode: str = ""
    summary: dict[str, Any] = Field(default_factory=dict)
    overall_risk: Severity = Severity.UNKNOWN
    executive_summary: ExecutiveSummary = Field(default_factory=ExecutiveSummary)
    technical_summary: TechnicalSummary = Field(default_factory=TechnicalSummary)
    findings: list[FindingAnalysis] = Field(default_factory=list)
    metadata: AnalysisMetadata = Field(default_factory=AnalysisMetadata)

    @field_validator("overall_risk", mode="before")
    @classmethod
    def _coerce_overall(cls, value: Any) -> Severity:
        return Severity.coerce(value)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict with enums flattened to their string values."""
        return self.model_dump(mode="json")


__all__ = [
    "AnalysisMetadata",
    "BlueAnalysis",
    "BusinessImpact",
    "ExecutiveSummary",
    "FindingAnalysis",
    "MitreAttack",
    "MitreTechnique",
    "Recommendation",
    "RedFinding",
    "RedTeamReport",
    "RiskAssessment",
    "RootCause",
    "Severity",
    "TechnicalSummary",
]
