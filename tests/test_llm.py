"""LLM service tests, using fake providers — no network access."""

from __future__ import annotations

import json

import pytest

from config import PROVIDER_OFFLINE, Settings
from models.schemas import Severity
from services.llm import (
    LLMError,
    LLMService,
    OfflineProvider,
    OpenAICompatibleProvider,
    build_provider,
    extract_json_object,
)

VALID_FINDING_REPLY = {
    "analysis": "The parameter is concatenated into a SQL statement.",
    "root_cause": {
        "primary": "Unparameterised query construction",
        "categories": ["missing input validation"],
        "explanation": "Legacy JSP code builds SQL by concatenation.",
    },
    "business_impact": {
        "confidentiality": "Customer records readable.",
        "narrative": "A breach here is reportable.",
    },
    "mitre_attack": {
        "tactics": ["Initial Access"],
        "techniques": [{"id": "T1190", "name": "", "tactic": "", "rationale": "Public app."}],
        "notes": "",
    },
    "risk_assessment": {
        "overall_risk_score": 9.6,
        "likelihood": "Very High",
        "impact": "Critical",
        "priority": "P0",
        "risk_category": "Critical",
        "reasoning": "Unauthenticated and remotely reachable.",
    },
    "recommendations": [
        {
            "horizon": "Immediate",
            "category": "patch",
            "action": "Parameterise the query.",
            "rationale": "Removes the defect.",
            "effort": "Low",
        }
    ],
    "detection_rules": ["Alert on SQL syntax errors in application logs."],
}

VALID_EXEC_REPLY = {
    "overall_posture": "Posture is weak at the application tier.",
    "top_risks": ["SQL injection"],
    "most_dangerous_findings": ["SQL injection in login"],
    "security_maturity": "Early.",
    "recommended_next_steps": ["Fix the injection."],
    "business_narrative": "Customer data is at risk.",
}

VALID_TECH_REPLY = {
    "developer_guidance": "Parameterise queries everywhere.",
    "infrastructure_recommendations": ["Deploy a WAF."],
    "secure_coding_guidance": ["Use prepared statements."],
    "devsecops_improvements": ["Add SAST to CI."],
    "architecture_improvements": ["Least-privilege database accounts."],
}


class FakeProvider(OpenAICompatibleProvider):
    """Returns scripted replies and records how often it was called."""

    def __init__(self, replies, *, name="fake"):
        self.replies = list(replies)
        self.calls = 0
        self.last_payload = None
        self.name = name

    @property
    def available(self) -> bool:
        return True

    def complete(self, messages, *, temperature, max_tokens, json_mode=False):
        self.calls += 1
        self.last_payload = list(messages)
        reply = self.replies[min(self.calls - 1, len(self.replies) - 1)]
        if isinstance(reply, Exception):
            raise reply
        return reply if isinstance(reply, str) else json.dumps(reply)


def _settings(tmp_path, **overrides) -> Settings:
    base = {
        "llm_provider": "modal",
        "llm_base_url": "https://example.invalid/v1",
        "output_dir": tmp_path / "output",
        "max_retries": 2,
        "retry_backoff_seconds": 0.0,
        "concurrency": 2,
    }
    base.update(overrides)
    return Settings(**base)


# --- JSON extraction -------------------------------------------------------


def test_extract_plain_json():
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_extract_from_code_fence():
    assert extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}


def test_extract_after_reasoning_trace():
    raw = "<think>Let me consider the finding.</think>\n{\"a\": 1}"
    assert extract_json_object(raw) == {"a": 1}


def test_extract_ignores_surrounding_prose():
    raw = 'Here is the analysis:\n{"a": {"b": [1, 2]}}\nHope that helps.'
    assert extract_json_object(raw) == {"a": {"b": [1, 2]}}


def test_extract_handles_braces_inside_strings():
    raw = '{"action": "set header {x} on }proxy"}'
    assert extract_json_object(raw)["action"] == "set header {x} on }proxy"


@pytest.mark.parametrize("raw", ["", "no json here", "[1, 2, 3]"])
def test_extract_raises_without_an_object(raw):
    with pytest.raises(LLMError):
        extract_json_object(raw)


# --- Provider construction -------------------------------------------------


def test_missing_base_url_degrades_to_offline(tmp_path):
    provider = build_provider(_settings(tmp_path, llm_base_url=None))
    assert isinstance(provider, OfflineProvider)
    assert provider.available is False


def test_offline_provider_selected_explicitly(tmp_path):
    provider = build_provider(_settings(tmp_path, llm_provider=PROVIDER_OFFLINE))
    assert isinstance(provider, OfflineProvider)


def test_base_url_gets_v1_suffix(tmp_path):
    settings = _settings(tmp_path, llm_base_url="https://example.invalid")
    assert settings.llm_base_url == "https://example.invalid/v1"


# --- Service behaviour -----------------------------------------------------


def test_llm_analysis_populates_finding(tmp_path, sample_report):
    provider = FakeProvider([VALID_FINDING_REPLY])
    service = LLMService(_settings(tmp_path), provider=provider)

    finding = sample_report.sorted_findings()[0]
    analysis = service.analyze_finding(finding, sample_report)

    assert analysis.analysis_source == "llm"
    assert analysis.title == finding.title  # identity comes from the report
    assert analysis.severity is Severity.CRITICAL
    assert analysis.risk_assessment.overall_risk_score == 9.6
    assert analysis.recommendations[0].horizon == "immediate"
    # The catalog fills the name/tactic the model left blank.
    technique = analysis.mitre_attack.techniques[0]
    assert technique.id == "T1190"
    assert technique.name == "Exploit Public-Facing Application"
    assert technique.tactic == "Initial Access"


def test_retries_then_succeeds(tmp_path, sample_report):
    provider = FakeProvider([LLMError("cold start"), VALID_FINDING_REPLY])
    service = LLMService(_settings(tmp_path), provider=provider)

    analysis = service.analyze_finding(sample_report.findings[0], sample_report)
    assert provider.calls == 2
    assert analysis.analysis_source == "llm"


def test_falls_back_to_heuristics_after_exhausting_retries(tmp_path, sample_report):
    provider = FakeProvider([LLMError("down"), LLMError("still down")])
    service = LLMService(_settings(tmp_path), provider=provider)

    analysis = service.analyze_finding(sample_report.findings[0], sample_report)
    assert provider.calls == 2
    assert analysis.analysis_source == "heuristic"
    assert analysis.analysis  # the fallback still produces real content


def test_no_fallback_mode_propagates_the_error(tmp_path, sample_report):
    provider = FakeProvider([LLMError("down")])
    service = LLMService(
        _settings(tmp_path, max_retries=1, allow_offline_fallback=False), provider=provider
    )
    with pytest.raises(LLMError):
        service.analyze_finding(sample_report.findings[0], sample_report)


def test_garbage_reply_falls_back(tmp_path, sample_report):
    provider = FakeProvider(["I cannot help with that."])
    service = LLMService(_settings(tmp_path, max_retries=1), provider=provider)

    analysis = service.analyze_finding(sample_report.findings[0], sample_report)
    assert analysis.analysis_source == "heuristic"


def test_scanner_asserted_technique_survives_a_model_that_drops_it(tmp_path, sample_report):
    reply = dict(VALID_FINDING_REPLY)
    reply["mitre_attack"] = {"tactics": [], "techniques": [], "notes": ""}
    provider = FakeProvider([reply])
    service = LLMService(_settings(tmp_path), provider=provider)

    finding = sample_report.sorted_findings()[0]  # asserts T1190
    analysis = service.analyze_finding(finding, sample_report)
    assert [t.id for t in analysis.mitre_attack.techniques] == ["T1190"]


def test_generate_report_end_to_end_with_fake_llm(tmp_path, sample_report):
    provider = FakeProvider(
        [VALID_FINDING_REPLY] * len(sample_report.findings)
        + [VALID_EXEC_REPLY, VALID_TECH_REPLY]
    )
    service = LLMService(_settings(tmp_path, concurrency=1), provider=provider)
    analysis = service.generate_report(sample_report)

    assert len(analysis.findings) == len(sample_report.findings)
    assert analysis.metadata.llm_analysed == len(sample_report.findings)
    assert analysis.metadata.degraded is False
    assert analysis.overall_risk is Severity.CRITICAL
    assert analysis.summary["total_findings"] == len(sample_report.findings)
    assert analysis.summary["immediate_actions"] >= 1
    assert "Initial Access" in analysis.summary["mitre_tactics_observed"]


def test_offline_service_produces_a_complete_report(offline_settings, sample_report):
    service = LLMService(offline_settings)
    assert service.llm_available is False

    analysis = service.generate_report(sample_report)
    assert len(analysis.findings) == len(sample_report.findings)
    assert analysis.metadata.degraded is True
    assert analysis.metadata.llm_analysed == 0
    assert analysis.overall_risk is Severity.CRITICAL

    for finding in analysis.findings:
        assert finding.analysis
        assert finding.root_cause.primary
        assert finding.risk_assessment.reasoning
        assert finding.recommendations
        assert finding.business_impact.narrative


def test_prompt_includes_finding_context(tmp_path, sample_report):
    provider = FakeProvider([VALID_FINDING_REPLY])
    service = LLMService(_settings(tmp_path), provider=provider)
    finding = sample_report.sorted_findings()[0]
    service.analyze_finding(finding, sample_report)

    user_message = provider.last_payload[-1]["content"]
    assert finding.title in user_message
    assert sample_report.target in user_message
    assert "MITRE" in user_message or "mitre_attack" in user_message


def test_analysis_of_an_empty_report(tmp_path):
    from services.parser import parse_report

    service = LLMService(_settings(tmp_path, llm_provider=PROVIDER_OFFLINE, llm_base_url=None))
    analysis = service.generate_report(parse_report({"findings": []}))
    assert analysis.findings == []
    assert analysis.summary["total_findings"] == 0
