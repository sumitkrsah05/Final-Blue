"""Serialisation of a :class:`~models.schemas.BlueAnalysis` into deliverables.

Two artefacts are produced:

* ``blue_analysis.json`` — the structured record, for dashboards, ticketing
  integrations, and diffing between engagements.
* ``blue_report.md`` — the human-readable report, executive section first.

Rendering is pure: it reads the analysis object and writes files. No LLM calls,
no network. That keeps report formatting independently testable and lets the
Markdown be regenerated from stored JSON at any time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

import orjson

from models.schemas import (
    BlueAnalysis,
    FindingAnalysis,
    Recommendation,
    Severity,
)
from utils.logger import get_logger

log = get_logger(__name__)

JSON_FILENAME = "blue_analysis.json"
MARKDOWN_FILENAME = "blue_report.md"

_SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 Critical",
    Severity.HIGH: "🟠 High",
    Severity.MEDIUM: "🟡 Medium",
    Severity.LOW: "🔵 Low",
    Severity.INFO: "⚪ Info",
    Severity.UNKNOWN: "⚫ Unknown",
}

_HORIZON_TITLES = (
    ("immediate", "Immediate (0–7 days)"),
    ("short_term", "Short term (1–4 weeks)"),
    ("long_term", "Long term (1–2 quarters)"),
)

_IMPACT_ROWS = (
    ("Confidentiality", "confidentiality"),
    ("Integrity", "integrity"),
    ("Availability", "availability"),
    ("Financial", "financial"),
    ("Compliance", "compliance"),
    ("Operational disruption", "operational_disruption"),
    ("Reputation", "reputation"),
    ("Customer trust", "customer_trust"),
    ("Data exposure", "data_exposure"),
    ("Privilege escalation", "privilege_escalation"),
    ("Lateral movement", "lateral_movement"),
    ("Remote compromise", "remote_compromise"),
)


class ReportGenerator:
    """Writes the JSON and Markdown deliverables for an analysis."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = Path(output_dir)

    # --- public API ------------------------------------------------------

    def generate(self, analysis: BlueAnalysis) -> dict[str, Path]:
        """Write both artefacts and return their paths keyed by format."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        paths = {
            "json": self.write_json(analysis),
            "markdown": self.write_markdown(analysis),
        }
        log.info("Wrote {} and {}", paths["json"], paths["markdown"])
        return paths

    def write_json(self, analysis: BlueAnalysis, filename: str = JSON_FILENAME) -> Path:
        """Serialise the analysis to pretty-printed JSON."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / filename
        payload = orjson.dumps(
            analysis.to_dict(), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS
        )
        path.write_bytes(payload)
        return path

    def write_markdown(self, analysis: BlueAnalysis, filename: str = MARKDOWN_FILENAME) -> Path:
        """Render and write the Markdown report."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / filename
        path.write_text(self.render_markdown(analysis), encoding="utf-8")
        return path

    # --- rendering -------------------------------------------------------

    def render_markdown(self, analysis: BlueAnalysis) -> str:
        """Return the full Markdown report as a string."""
        sections: list[str] = [
            self._header(analysis),
            self._executive_section(analysis),
            self._risk_table(analysis),
            self._attack_coverage(analysis),
            self._findings_section(analysis),
            self._technical_section(analysis),
            self._remediation_roadmap(analysis),
            self._footer(analysis),
        ]
        return "\n\n".join(section for section in sections if section).strip() + "\n"

    def _header(self, analysis: BlueAnalysis) -> str:
        meta = analysis.metadata
        badge = _SEVERITY_BADGE.get(analysis.overall_risk, analysis.overall_risk.label)
        summary = analysis.summary
        return "\n".join(
            [
                "# Blue Team Security Analysis",
                "",
                f"**Overall risk: {badge}**",
                "",
                "| Field | Value |",
                "| --- | --- |",
                f"| Engagement ID | `{analysis.engagement_id}` |",
                f"| Target | {analysis.target} |",
                f"| Assessment mode | {analysis.mode} |",
                f"| Findings analysed | {meta.findings_analysed} |",
                f"| Highest severity | {str(summary.get('highest_severity', 'n/a')).title()} |",
                f"| Peak risk score | {summary.get('max_risk_score', 'n/a')}/10 |",
                f"| Immediate actions | {summary.get('immediate_actions', 0)} |",
                f"| Generated | {meta.generated_at} |",
                f"| Analysis engine | {meta.llm_provider} / {meta.model_name} |",
            ]
            + (
                [
                    "",
                    f"> ⚠️ **Degraded run.** {meta.heuristic_analysed} of "
                    f"{meta.findings_analysed} findings were analysed by the "
                    "deterministic heuristic engine because the LLM was unavailable. "
                    "Those sections are marked below.",
                ]
                if meta.degraded
                else []
            )
        )

    def _executive_section(self, analysis: BlueAnalysis) -> str:
        summary = analysis.executive_summary
        parts = ["## Executive Summary", "", summary.overall_posture or "_Not available._"]
        if summary.business_narrative:
            parts += ["", f"**Business impact.** {summary.business_narrative}"]
        parts += _bullet_block("### Top Risks", summary.top_risks)
        parts += _bullet_block("### Most Dangerous Findings", summary.most_dangerous_findings)
        if summary.security_maturity:
            parts += ["", "### Security Maturity", "", summary.security_maturity]
        parts += _bullet_block("### Recommended Next Steps", summary.recommended_next_steps, numbered=True)
        return "\n".join(parts)

    def _risk_table(self, analysis: BlueAnalysis) -> str:
        if not analysis.findings:
            return ""
        rows = [
            "## Risk Register",
            "",
            "| # | Finding | Severity | Risk | Priority | Likelihood | Asset |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for index, finding in enumerate(analysis.findings, start=1):
            risk = finding.risk_assessment
            rows.append(
                f"| {index} | [{_escape(finding.title)}](#{_anchor(index, finding.title)}) "
                f"| {_SEVERITY_BADGE.get(finding.severity, finding.severity.label)} "
                f"| {risk.overall_risk_score}/10 | {risk.priority} | {risk.likelihood} "
                f"| {_escape(finding.asset or 'n/a')} |"
            )
        return "\n".join(rows)

    def _attack_coverage(self, analysis: BlueAnalysis) -> str:
        """Tactic → techniques roll-up across the whole engagement."""
        by_tactic: dict[str, list[str]] = {}
        for finding in analysis.findings:
            for technique in finding.mitre_attack.techniques:
                entry = f"`{technique.id}` {technique.name}"
                bucket = by_tactic.setdefault(technique.tactic or "Unknown", [])
                if entry not in bucket:
                    bucket.append(entry)
        if not by_tactic:
            return ""
        rows = [
            "## MITRE ATT&CK Coverage",
            "",
            "Adversary behaviour these findings would enable, aggregated across the engagement.",
            "",
            "| Tactic | Techniques |",
            "| --- | --- |",
        ]
        for tactic, techniques in by_tactic.items():
            rows.append(f"| {tactic} | {', '.join(techniques)} |")
        return "\n".join(rows)

    def _findings_section(self, analysis: BlueAnalysis) -> str:
        if not analysis.findings:
            return "## Findings\n\n_No findings were reported by the Red Agent._"
        blocks = ["## Detailed Findings"]
        for index, finding in enumerate(analysis.findings, start=1):
            blocks.append(self._finding_block(index, finding))
        return "\n\n".join(blocks)

    def _finding_block(self, index: int, finding: FindingAnalysis) -> str:
        risk = finding.risk_assessment
        badge = _SEVERITY_BADGE.get(finding.severity, finding.severity.label)
        parts = [
            f"### {index}. {_escape(finding.title)}",
            "",
            f"{badge} · **Risk {risk.overall_risk_score}/10** · "
            f"**{risk.priority}** · Likelihood: {risk.likelihood} · "
            f"Impact: {risk.impact}",
            "",
            f"- **Finding ID:** `{finding.id}`",
            f"- **Affected asset:** {_escape(finding.asset or 'not specified')}",
            f"- **Risk category:** {finding.risk_assessment.risk_category.label}",
        ]
        if finding.analysis_source != "llm":
            parts.append("- **Analysis source:** heuristic engine (LLM unavailable)")

        parts += ["", "#### Vulnerability Analysis", "", finding.analysis or "_Not available._"]

        root_cause = finding.root_cause
        parts += ["", "#### Root Cause", ""]
        if root_cause.primary:
            parts.append(f"**{root_cause.primary}**")
            parts.append("")
        if root_cause.categories:
            parts.append(
                "Categories: " + ", ".join(f"`{c}`" for c in root_cause.categories)
            )
            parts.append("")
        parts.append(root_cause.explanation or "_Not available._")

        impact = finding.business_impact
        parts += ["", "#### Business Impact", ""]
        if impact.narrative:
            parts += [impact.narrative, ""]
        impact_rows = [
            (label, getattr(impact, attribute))
            for label, attribute in _IMPACT_ROWS
            if getattr(impact, attribute, "")
        ]
        if impact_rows:
            parts += ["| Dimension | Assessment |", "| --- | --- |"]
            parts += [f"| {label} | {_escape(value)} |" for label, value in impact_rows]

        mitre_map = finding.mitre_attack
        parts += ["", "#### MITRE ATT&CK Mapping", ""]
        if mitre_map.is_empty:
            parts.append(
                mitre_map.notes or "No reasonable ATT&CK mapping applies to this finding."
            )
        else:
            if mitre_map.tactics:
                parts += [f"**Tactics:** {', '.join(mitre_map.tactics)}", ""]
            parts += ["| Technique | Name | Tactic | Rationale |", "| --- | --- | --- | --- |"]
            parts += [
                f"| `{t.id}` | {_escape(t.name)} | {_escape(t.tactic)} | {_escape(t.rationale)} |"
                for t in mitre_map.techniques
            ]
            if mitre_map.notes:
                parts += ["", f"_{_escape(mitre_map.notes)}_"]

        parts += ["", "#### Risk Assessment", "", risk.reasoning or "_Not available._"]

        parts += ["", "#### Remediation", ""]
        parts.append(_render_recommendations(finding.recommendations))

        if finding.detection_rules:
            parts += ["", "#### Detection & Monitoring", ""]
            parts += [f"- {_escape(rule)}" for rule in finding.detection_rules]

        return "\n".join(parts)

    def _technical_section(self, analysis: BlueAnalysis) -> str:
        technical = analysis.technical_summary
        parts = [
            "## Technical Summary",
            "",
            technical.developer_guidance or "_Not available._",
        ]
        parts += _bullet_block("### Infrastructure Recommendations", technical.infrastructure_recommendations)
        parts += _bullet_block("### Secure Coding Guidance", technical.secure_coding_guidance)
        parts += _bullet_block("### DevSecOps Improvements", technical.devsecops_improvements)
        parts += _bullet_block("### Architecture Improvements", technical.architecture_improvements)
        return "\n".join(parts)

    def _remediation_roadmap(self, analysis: BlueAnalysis) -> str:
        """All recommendations across findings, grouped by horizon."""
        if not analysis.findings:
            return ""
        parts = [
            "## Consolidated Remediation Roadmap",
            "",
            "Every recommendation across all findings, grouped by when it should happen.",
        ]
        for horizon, title in _HORIZON_TITLES:
            rows: list[str] = []
            for index, finding in enumerate(analysis.findings, start=1):
                for rec in finding.recommendations_by_horizon(horizon):
                    rows.append(
                        f"| {finding.risk_assessment.priority} | {_escape(rec.action)} "
                        f"| `{rec.category}` | [{index}](#{_anchor(index, finding.title)}) |"
                    )
            if rows:
                parts += [
                    "",
                    f"### {title}",
                    "",
                    "| Priority | Action | Type | Finding |",
                    "| --- | --- | --- | --- |",
                ]
                parts += sorted(rows)
        return "\n".join(parts)

    def _footer(self, analysis: BlueAnalysis) -> str:
        meta = analysis.metadata
        return "\n".join(
            [
                "---",
                "",
                f"_Generated by {meta.agent} v{meta.agent_version} on {meta.generated_at} "
                f"from `{meta.source_report}`._",
                "",
                "_This analysis is derived solely from the Red Agent's findings report. "
                "The Blue Agent performs no scanning and interacts with no target system. "
                "Recommendations should be validated against the environment before "
                "deployment._",
            ]
        )


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _escape(text: str) -> str:
    """Make free text safe inside a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _anchor(index: int, title: str) -> str:
    """GitHub-style heading anchor for ``### {index}. {title}``."""
    slug = f"{index}-{title}".lower()
    return "".join(ch if ch.isalnum() or ch == " " else "" for ch in slug).replace(" ", "-")


def _bullet_block(heading: str, items: Sequence[str], *, numbered: bool = False) -> list[str]:
    if not items:
        return []
    lines = ["", heading, ""]
    for index, item in enumerate(items, start=1):
        prefix = f"{index}." if numbered else "-"
        lines.append(f"{prefix} {item}")
    return lines


def _render_recommendations(recommendations: Iterable[Recommendation]) -> str:
    """Group a finding's recommendations by horizon as nested bullets."""
    grouped: dict[str, list[Recommendation]] = {}
    for rec in recommendations:
        grouped.setdefault(rec.horizon, []).append(rec)
    if not grouped:
        return "_No recommendations were produced._"

    lines: list[str] = []
    ordered = [h for h, _ in _HORIZON_TITLES] + [
        h for h in grouped if h not in {h for h, _ in _HORIZON_TITLES}
    ]
    titles = dict(_HORIZON_TITLES)
    for horizon in ordered:
        items = grouped.get(horizon)
        if not items:
            continue
        lines.append(f"**{titles.get(horizon, horizon.replace('_', ' ').title())}**")
        lines.append("")
        for rec in items:
            effort = f" _(effort: {rec.effort})_" if rec.effort else ""
            lines.append(f"- **[{rec.category}]** {rec.action}{effort}")
            if rec.rationale:
                lines.append(f"  - _Why:_ {rec.rationale}")
        lines.append("")
    return "\n".join(lines).strip()


__all__ = ["JSON_FILENAME", "MARKDOWN_FILENAME", "ReportGenerator"]
