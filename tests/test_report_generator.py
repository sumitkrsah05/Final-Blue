"""Report rendering tests: JSON contract and Markdown structure."""

from __future__ import annotations

import json

from models.schemas import BlueAnalysis, FindingAnalysis, MitreAttack, MitreTechnique, Recommendation
from services.llm import LLMService
from services.report_generator import (
    JSON_FILENAME,
    MARKDOWN_FILENAME,
    ReportGenerator,
)


def _analysis(offline_settings, sample_report) -> BlueAnalysis:
    return LLMService(offline_settings).generate_report(sample_report)


def test_generate_writes_both_artefacts(tmp_path, offline_settings, sample_report):
    paths = ReportGenerator(tmp_path).generate(_analysis(offline_settings, sample_report))

    assert paths["json"].name == JSON_FILENAME
    assert paths["markdown"].name == MARKDOWN_FILENAME
    assert paths["json"].exists() and paths["markdown"].exists()


def test_json_round_trips_through_the_schema(tmp_path, offline_settings, sample_report):
    analysis = _analysis(offline_settings, sample_report)
    path = ReportGenerator(tmp_path).write_json(analysis)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert {"summary", "overall_risk", "findings", "executive_summary"} <= payload.keys()
    assert len(payload["findings"]) == len(analysis.findings)

    # The written document must validate back into the model.
    assert BlueAnalysis.model_validate(payload).engagement_id == analysis.engagement_id


def test_markdown_contains_every_required_section(tmp_path, offline_settings, sample_report):
    markdown = ReportGenerator(tmp_path).render_markdown(_analysis(offline_settings, sample_report))

    for heading in (
        "# Blue Team Security Analysis",
        "## Executive Summary",
        "## Risk Register",
        "## MITRE ATT&CK Coverage",
        "## Detailed Findings",
        "#### Vulnerability Analysis",
        "#### Root Cause",
        "#### Business Impact",
        "#### MITRE ATT&CK Mapping",
        "#### Risk Assessment",
        "#### Remediation",
        "## Technical Summary",
        "## Consolidated Remediation Roadmap",
    ):
        assert heading in markdown, f"missing section: {heading}"


def test_degraded_run_is_disclosed_in_the_report(tmp_path, offline_settings, sample_report):
    markdown = ReportGenerator(tmp_path).render_markdown(_analysis(offline_settings, sample_report))
    assert "Degraded run" in markdown
    assert "heuristic engine" in markdown


def test_pipe_characters_do_not_break_tables(tmp_path):
    analysis = BlueAnalysis(
        engagement_id="e1",
        findings=[
            FindingAnalysis(
                title="Command | injection",
                analysis="x",
                mitre_attack=MitreAttack(
                    tactics=["Execution"],
                    techniques=[MitreTechnique(id="T1059", name="Command | Scripting", tactic="Execution")],
                ),
                recommendations=[Recommendation(action="Escape | properly")],
            )
        ],
    )
    markdown = ReportGenerator(tmp_path).render_markdown(analysis)
    for line in markdown.splitlines():
        if line.startswith("|") and "---" not in line:
            # Escaped pipes must not add phantom columns.
            assert "\\|" in line or line.count("|") <= 8


def test_empty_report_still_renders(tmp_path):
    markdown = ReportGenerator(tmp_path).render_markdown(BlueAnalysis(engagement_id="empty"))
    assert "No findings were reported" in markdown


def test_output_directory_is_created_on_demand(tmp_path, offline_settings, sample_report):
    target = tmp_path / "deep" / "nested" / "out"
    paths = ReportGenerator(target).generate(_analysis(offline_settings, sample_report))
    assert paths["json"].parent == target
