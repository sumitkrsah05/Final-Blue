"""End-to-end CLI tests, run entirely offline."""

from __future__ import annotations

import json

import app
from config import PROVIDER_OFFLINE
from services.report_generator import JSON_FILENAME, MARKDOWN_FILENAME

from tests.conftest import SAMPLE_REPORT_PATH


def test_cli_offline_run_produces_artefacts(tmp_path, capsys):
    output_dir = tmp_path / "out"
    exit_code = app.main(
        ["--input", str(SAMPLE_REPORT_PATH), "--output", str(output_dir), "--offline"]
    )
    assert exit_code == app.EXIT_OK

    payload = json.loads((output_dir / JSON_FILENAME).read_text(encoding="utf-8"))
    assert payload["overall_risk"] == "critical"
    assert len(payload["findings"]) == 8
    assert (output_dir / MARKDOWN_FILENAME).exists()

    printed = capsys.readouterr().out
    assert "OVERALL RISK" in printed


def test_missing_input_returns_usage_error(tmp_path):
    assert app.main(["--input", str(tmp_path / "nope.json"), "--offline"]) == app.EXIT_USAGE


def test_malformed_input_returns_parse_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{oops", encoding="utf-8")
    exit_code = app.main(
        ["--input", str(bad), "--output", str(tmp_path / "out"), "--offline"]
    )
    assert exit_code == app.EXIT_PARSE_ERROR


def test_quiet_mode_suppresses_the_summary(tmp_path, capsys):
    app.main(
        [
            "--input", str(SAMPLE_REPORT_PATH),
            "--output", str(tmp_path / "out"),
            "--offline",
            "--quiet",
        ]
    )
    assert "OVERALL RISK" not in capsys.readouterr().out


def test_cli_flags_override_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("CONCURRENCY", "9")
    args = app.build_arg_parser().parse_args(
        ["--offline", "--concurrency", "2", "--model", "custom-model"]
    )
    settings = app.settings_from_args(args)

    assert settings.concurrency == 2
    assert settings.model_name == "custom-model"
    assert settings.llm_provider == PROVIDER_OFFLINE


def test_run_analysis_is_importable_for_programmatic_use(tmp_path):
    from config import Settings

    settings = Settings(
        llm_provider=PROVIDER_OFFLINE,
        input_path=SAMPLE_REPORT_PATH,
        output_dir=tmp_path / "out",
    )
    analysis, paths = app.run_analysis(settings)

    assert analysis.metadata.findings_analysed == 8
    assert set(paths) == {"json", "markdown"}
