"""Parser tests — the parser's whole job is surviving schema drift."""

from __future__ import annotations

import json

import pytest

from models.schemas import Severity
from services.parser import ReportParseError, parse_report


def test_parses_bundled_sample(sample_report):
    assert sample_report.engagement_id == "eng-web-black_box-4f2a91cd"
    assert sample_report.mode == "black_box"
    assert sample_report.target == "demo.testfire.net"
    assert len(sample_report.findings) == 8

    critical = sample_report.findings[0]
    assert critical.severity is Severity.CRITICAL
    assert critical.cvss == 9.8
    assert critical.epss == 0.71
    assert critical.risk_score == 92
    assert critical.tools == ["sqlmap", "manual-validation"]
    assert critical.techniques == ["T1190"]
    assert critical.references


def test_findings_sort_worst_first(sample_report):
    ranks = [f.severity.rank for f in sample_report.sorted_findings()]
    assert ranks == sorted(ranks, reverse=True)


def test_empty_document_yields_empty_report():
    report = parse_report({})
    assert report.findings == []
    assert report.engagement_id == "unknown-engagement"
    assert report.summary["total_findings"] == 0


def test_finding_with_no_recognised_fields_still_parses():
    report = parse_report({"findings": [{"something_new": "value"}]})
    finding = report.findings[0]
    assert finding.title == "Finding 1"
    assert finding.severity is Severity.UNKNOWN
    # Unknown keys survive rather than being dropped.
    assert finding.extra["something_new"] == "value"


def test_alternative_field_names_are_mapped():
    """A future Red Agent schema using different key names must still parse."""
    report = parse_report(
        {
            "scan_id": "scan-77",
            "assessment_mode": "grey_box",
            "host": "example.internal",
            "vulnerabilities": [
                {
                    "name": "Remote code execution in upload handler",
                    "risk_level": "Severe",
                    "detail": "Unrestricted file upload leads to code execution.",
                    "proof": "POST /upload -> shell.jsp accessible",
                    "scanner": "custom-checker",
                    "cvss_score": {"base_score": 9.1},
                    "links": ["https://example.com/advisory"],
                    "ttps": ["T1505.003", "not-a-technique"],
                }
            ],
        }
    )
    assert report.engagement_id == "scan-77"
    assert report.mode == "grey_box"
    assert report.target == "example.internal"

    finding = report.findings[0]
    assert finding.title.startswith("Remote code execution")
    assert finding.severity is Severity.HIGH  # "Severe" maps onto High
    assert finding.cvss == 9.1
    assert finding.description
    assert finding.evidence
    assert finding.tools == ["custom-checker"]
    assert finding.references == ["https://example.com/advisory"]
    assert finding.techniques == ["T1505.003"]  # the junk entry is discarded


def test_severity_inferred_from_cvss_when_label_missing():
    report = parse_report({"findings": [{"title": "Something", "cvss": 9.4}]})
    assert report.findings[0].severity is Severity.CRITICAL


def test_bare_findings_array_is_accepted():
    report = parse_report([{"title": "Open port 23/tcp", "severity": "low"}])
    assert len(report.findings) == 1
    assert report.findings[0].severity is Severity.LOW


def test_nested_report_envelope_is_located():
    report = parse_report({"report": {"findings": [{"title": "Nested finding"}]}})
    assert len(report.findings) == 1


def test_findings_keyed_by_id_are_accepted():
    report = parse_report({"findings": {"f-1": {"title": "Keyed finding", "severity": "high"}}})
    assert report.findings[0].title == "Keyed finding"


def test_target_falls_back_to_most_common_asset():
    report = parse_report(
        {
            "findings": [
                {"title": "a", "asset": "host-a"},
                {"title": "b", "asset": "host-b"},
                {"title": "c", "asset": "host-b"},
            ]
        }
    )
    assert report.target == "host-b"


def test_string_and_path_sources(tmp_path):
    document = {"findings": [{"title": "From disk", "severity": "medium"}]}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    from_path = parse_report(path)
    from_string = parse_report(json.dumps(document))
    assert from_path.findings[0].title == from_string.findings[0].title == "From disk"
    assert from_path.source_path == str(path)


def test_evidence_is_truncated_not_dropped():
    report = parse_report({"findings": [{"title": "Huge", "evidence": "A" * 50_000}]})
    evidence = report.findings[0].evidence
    assert len(evidence) < 50_000
    assert evidence.endswith("[truncated]")


def test_missing_file_raises():
    with pytest.raises(ReportParseError):
        parse_report("/nonexistent/report.json")


def test_malformed_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ReportParseError):
        parse_report(path)


def test_scalar_top_level_raises():
    with pytest.raises(ReportParseError):
        parse_report("42")


def test_severity_counts_and_highest(sample_report):
    counts = sample_report.severity_counts
    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert sample_report.highest_severity is Severity.CRITICAL
