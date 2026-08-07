"""Schema-level tests: severity coercion and output-contract stability."""

from __future__ import annotations

import pytest

from models.schemas import (
    BlueAnalysis,
    FindingAnalysis,
    Recommendation,
    RiskAssessment,
    Severity,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Critical", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("informational", Severity.INFO),
        ("sev1", Severity.CRITICAL),
        ("p2", Severity.MEDIUM),
        (9.5, Severity.CRITICAL),
        (7.0, Severity.HIGH),
        (4.0, Severity.MEDIUM),
        (0.1, Severity.LOW),
        (0, Severity.INFO),
        ("8.8", Severity.HIGH),
        (None, Severity.UNKNOWN),
        ("", Severity.UNKNOWN),
        ("banana", Severity.UNKNOWN),
    ],
)
def test_severity_coercion(value, expected):
    assert Severity.coerce(value) is expected


def test_severity_ranking_orders_correctly():
    ladder = [Severity.INFO, Severity.CRITICAL, Severity.LOW, Severity.HIGH]
    assert max(ladder, key=lambda s: s.rank) is Severity.CRITICAL


def test_risk_score_is_clamped():
    assert RiskAssessment(overall_risk_score=42).overall_risk_score == 10.0
    assert RiskAssessment(overall_risk_score=-5).overall_risk_score == 0.0
    assert RiskAssessment(overall_risk_score="not a number").overall_risk_score == 0.0


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Immediate", "immediate"),
        ("short-term", "short_term"),
        ("Long Term", "long_term"),
        ("urgent", "immediate"),
        (None, "short_term"),
    ],
)
def test_recommendation_horizon_normalisation(raw, expected):
    assert Recommendation(horizon=raw, action="x").horizon == expected


def test_unknown_llm_fields_are_preserved_not_rejected():
    """Prompt evolution must not break validation of older/newer replies."""
    analysis = FindingAnalysis.model_validate(
        {"title": "X", "analysis": "text", "confidence": 0.8, "novel_field": ["a"]}
    )
    assert analysis.confidence == 0.8


def test_output_json_matches_the_documented_contract():
    analysis = BlueAnalysis(
        engagement_id="e1",
        overall_risk="high",
        findings=[
            FindingAnalysis(
                title="Finding",
                severity="high",
                analysis="why",
                recommendations=[Recommendation(action="fix it")],
            )
        ],
    )
    payload = analysis.to_dict()

    assert {"summary", "overall_risk", "findings"} <= payload.keys()
    assert payload["overall_risk"] == "high"

    finding = payload["findings"][0]
    for key in (
        "title",
        "severity",
        "analysis",
        "root_cause",
        "business_impact",
        "mitre_attack",
        "risk_assessment",
        "recommendations",
    ):
        assert key in finding
    assert {"tactics", "techniques"} <= finding["mitre_attack"].keys()


def test_recommendations_by_horizon_filters():
    finding = FindingAnalysis(
        recommendations=[
            Recommendation(horizon="immediate", action="a"),
            Recommendation(horizon="long_term", action="b"),
        ]
    )
    assert [r.action for r in finding.recommendations_by_horizon("immediate")] == ["a"]
