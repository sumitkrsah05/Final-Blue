"""Prompt library for the Blue Team Analysis Agent.

Every string the LLM ever sees is defined here. Business logic imports the
``build_*`` helpers and never concatenates prompt text of its own, so prompts
can be tuned, versioned or A/B tested without touching :mod:`services`.

Design notes:

* Each prompt demands a **single JSON object** and shows the exact skeleton.
  The service layer additionally requests ``response_format=json_object`` where
  the backend supports it, and repairs fenced/prefixed replies.
* The system prompt fixes the agent's role as *defensive*: it analyses a report
  that was already produced under an authorised engagement, and never produces
  exploit code.
"""

from __future__ import annotations

from typing import Sequence

PROMPT_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a principal Blue Team security analyst working inside an authorised \
security assessment platform. A Red Team agent has already completed an \
authorised assessment and handed you its findings report. Your job is purely \
defensive analysis: you interpret findings, explain root causes, quantify \
business risk, map adversary behaviour to MITRE ATT&CK, and prescribe \
remediation and detection.

Operating rules:
1. You never scan, attack, or interact with any system. You only reason over \
the report you are given.
2. You never write exploit code or step-by-step attack instructions. Describe \
attacker technique at the conceptual level a defender needs to build \
mitigations and detections.
3. Ground every claim in the evidence supplied. When the report is thin, say \
what is unknown and state your assumption explicitly rather than inventing \
details, CVEs, or version numbers.
4. Be concrete and actionable. Prefer "set Strict-Transport-Security: \
max-age=31536000; includeSubDomains at the edge proxy" over "improve TLS".
5. Respect the severity the scanner assigned, but correct it when the evidence \
clearly warrants it — and explain why you disagreed.
6. Output valid JSON only. No prose before or after, no markdown code fences.
"""

# ---------------------------------------------------------------------------
# Per-finding analysis
# ---------------------------------------------------------------------------

ROOT_CAUSE_CATEGORIES: Sequence[str] = (
    "misconfiguration",
    "missing patch",
    "weak authentication",
    "missing authorization",
    "insecure default",
    "exposed secret",
    "software bug",
    "missing input validation",
    "weak TLS configuration",
    "poor access control",
    "insecure dependency",
    "missing security header",
    "excessive network exposure",
    "information disclosure",
    "unknown",
)

FINDING_ANALYSIS_SCHEMA = """\
{
  "analysis": "Technical explanation: what the vulnerability is, why it exists in this context, how an attacker would abuse it, and the security implications. 4-8 sentences.",
  "root_cause": {
    "primary": "one short phrase naming the dominant cause",
    "categories": ["one or more of the allowed categories"],
    "explanation": "why this weakness most likely exists in this environment"
  },
  "business_impact": {
    "confidentiality": "impact on data confidentiality, or 'None expected' with a reason",
    "integrity": "impact on data/system integrity",
    "availability": "impact on service availability",
    "financial": "expected financial exposure and what drives it",
    "compliance": "affected regimes (PCI DSS, GDPR, HIPAA, SOC 2, ISO 27001) and the specific control at risk",
    "operational_disruption": "impact on operations and engineering effort",
    "reputation": "brand and market perception impact",
    "customer_trust": "impact on customer confidence",
    "data_exposure": "what data could be exposed, and how much",
    "privilege_escalation": "whether this enables privilege escalation, and how",
    "lateral_movement": "whether this enables movement to other systems",
    "remote_compromise": "whether this enables remote code execution or full compromise",
    "narrative": "2-4 sentence roll-up a non-technical executive can act on"
  },
  "mitre_attack": {
    "tactics": ["ATT&CK tactic names, e.g. Initial Access"],
    "techniques": [
      {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "rationale": "why this technique applies to this finding"}
    ],
    "notes": "If no reasonable ATT&CK mapping exists, leave tactics and techniques empty and state that clearly here."
  },
  "risk_assessment": {
    "overall_risk_score": 0.0,
    "likelihood": "Very Low | Low | Medium | High | Very High",
    "impact": "Low | Medium | High | Critical",
    "priority": "P0 | P1 | P2 | P3",
    "risk_category": "Critical | High | Medium | Low | Info",
    "reasoning": "how exploitability, exposure, asset value and evidence combine into this score"
  },
  "recommendations": [
    {
      "horizon": "immediate | short_term | long_term",
      "category": "patch | configuration | hardening | monitoring | detection | preventive | compensating | architecture",
      "action": "a specific, verifiable step",
      "rationale": "what risk this removes and why it is sequenced here",
      "effort": "Low | Medium | High"
    }
  ],
  "detection_rules": [
    "Concrete detection guidance: log source + signal + condition. Sigma-style pseudo-rules or WAF/SIEM logic are welcome."
  ]
}"""

FINDING_ANALYSIS_TEMPLATE = """\
Analyse a single finding from an authorised Red Team assessment.

## Engagement context
Engagement ID: {engagement_id}
Assessment mode: {mode}
Primary target: {target}
Total findings in this engagement: {total_findings}
Severity distribution: {severity_distribution}

## Finding under analysis ({position} of {total_findings})
{finding_block}

## Required output
Return exactly one JSON object matching this schema:

{schema}

## Constraints
- `overall_risk_score` is a number from 0.0 to 10.0, aligned with CVSS \
qualitative bands (9.0+ Critical, 7.0+ High, 4.0+ Medium, >0 Low).
- Allowed `root_cause.categories` values: {root_cause_categories}.
- Provide at least one recommendation for each of the immediate, short_term \
and long_term horizons, and at least one detection recommendation.
- Prefer real ATT&CK technique IDs. If the scanner already asserted \
techniques, validate them: keep the ones that hold, drop the ones that do not, \
and explain in `notes`.
- If the finding is purely informational, say so plainly and scale the risk \
score and recommendations down accordingly — do not inflate low-signal \
findings.
- Output JSON only.
"""

# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

EXECUTIVE_SUMMARY_SCHEMA = """\
{
  "overall_posture": "3-6 sentences on the security posture this assessment reveals, written for a CISO or board audience. No jargon without a gloss.",
  "top_risks": ["the most consequential risk themes, worst first"],
  "most_dangerous_findings": ["finding titles that most warrant immediate attention, with a clause on why"],
  "security_maturity": "assessment of maturity across patching, configuration management, monitoring and secure development, with the single biggest gap named",
  "recommended_next_steps": ["ordered, owner-assignable next steps for the next 30/60/90 days"],
  "business_narrative": "2-4 sentences translating the technical picture into business consequences and the cost of inaction"
}"""

EXECUTIVE_SUMMARY_TEMPLATE = """\
Write the executive summary for a Blue Team report covering an authorised \
security assessment.

## Engagement
Engagement ID: {engagement_id}
Assessment mode: {mode}
Target: {target}
Findings: {total_findings} (severity distribution: {severity_distribution})
Highest severity observed: {highest_severity}

## Analysed findings (worst first)
{findings_digest}

## Required output
Return exactly one JSON object matching this schema:

{schema}

## Constraints
- The audience is executive: lead with consequence, not mechanism.
- Be honest about a low-risk result. If the assessment surfaced mostly \
informational findings, say the posture is reasonable and focus on what would \
raise the bar — do not manufacture alarm.
- Every item in `recommended_next_steps` must be something a named team could \
start on Monday.
- Output JSON only.
"""

# ---------------------------------------------------------------------------
# Technical summary
# ---------------------------------------------------------------------------

TECHNICAL_SUMMARY_SCHEMA = """\
{
  "developer_guidance": "What engineers should understand about these findings as a class, and the patterns that produced them. 4-8 sentences.",
  "infrastructure_recommendations": ["platform, network, TLS, edge and configuration changes"],
  "secure_coding_guidance": ["code-level practices that prevent this class of defect, with the specific API/control named"],
  "devsecops_improvements": ["pipeline gates, SAST/DAST/SCA placement, dependency and secret scanning, IaC policy"],
  "architecture_improvements": ["structural changes: segmentation, trust boundaries, least privilege, secret management, defence in depth"]
}"""

TECHNICAL_SUMMARY_TEMPLATE = """\
Write the technical summary for a Blue Team report covering an authorised \
security assessment.

## Engagement
Engagement ID: {engagement_id}
Target: {target}
Findings: {total_findings} (severity distribution: {severity_distribution})

## Root causes observed across the analysed findings
{root_cause_digest}

## Analysed findings (worst first)
{findings_digest}

## Required output
Return exactly one JSON object matching this schema:

{schema}

## Constraints
- The audience is engineers and platform owners: be specific about \
technologies, headers, configuration keys, and controls.
- Group advice by the root causes actually observed; do not deliver generic \
checklists that ignore this engagement's evidence.
- Each list should hold 3-7 items, ordered by leverage.
- Output JSON only.
"""


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def build_system_prompt() -> str:
    """Return the shared system prompt."""
    return SYSTEM_PROMPT


def build_finding_analysis_prompt(
    *,
    finding_block: str,
    engagement_id: str,
    mode: str,
    target: str,
    total_findings: int,
    severity_distribution: str,
    position: int,
) -> str:
    """Render the per-finding analysis prompt."""
    return FINDING_ANALYSIS_TEMPLATE.format(
        engagement_id=engagement_id,
        mode=mode,
        target=target,
        total_findings=total_findings,
        severity_distribution=severity_distribution,
        position=position,
        finding_block=finding_block,
        schema=FINDING_ANALYSIS_SCHEMA,
        root_cause_categories=", ".join(ROOT_CAUSE_CATEGORIES),
    )


def build_executive_summary_prompt(
    *,
    engagement_id: str,
    mode: str,
    target: str,
    total_findings: int,
    severity_distribution: str,
    highest_severity: str,
    findings_digest: str,
) -> str:
    """Render the executive-summary prompt."""
    return EXECUTIVE_SUMMARY_TEMPLATE.format(
        engagement_id=engagement_id,
        mode=mode,
        target=target,
        total_findings=total_findings,
        severity_distribution=severity_distribution,
        highest_severity=highest_severity,
        findings_digest=findings_digest,
        schema=EXECUTIVE_SUMMARY_SCHEMA,
    )


def build_technical_summary_prompt(
    *,
    engagement_id: str,
    target: str,
    total_findings: int,
    severity_distribution: str,
    root_cause_digest: str,
    findings_digest: str,
) -> str:
    """Render the technical-summary prompt."""
    return TECHNICAL_SUMMARY_TEMPLATE.format(
        engagement_id=engagement_id,
        target=target,
        total_findings=total_findings,
        severity_distribution=severity_distribution,
        root_cause_digest=root_cause_digest,
        findings_digest=findings_digest,
        schema=TECHNICAL_SUMMARY_SCHEMA,
    )


__all__ = [
    "EXECUTIVE_SUMMARY_SCHEMA",
    "FINDING_ANALYSIS_SCHEMA",
    "PROMPT_VERSION",
    "ROOT_CAUSE_CATEGORIES",
    "SYSTEM_PROMPT",
    "TECHNICAL_SUMMARY_SCHEMA",
    "build_executive_summary_prompt",
    "build_finding_analysis_prompt",
    "build_system_prompt",
    "build_technical_summary_prompt",
]
