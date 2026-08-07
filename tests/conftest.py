"""Shared fixtures. Keeps every test offline and deterministic."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import PROVIDER_OFFLINE, Settings  # noqa: E402
from services.parser import parse_report  # noqa: E402

SAMPLE_REPORT_PATH = PROJECT_ROOT / "input" / "sample_report.json"


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch, tmp_path):
    """Stop a developer's real .env or exported vars from reaching the tests."""
    for name in (
        "LLM_PROVIDER",
        "MODAL_LLM_BASE_URL",
        "MODAL_API_KEY",
        "LLM_BASE_URL",
        "LLM_API_KEY",
        "SAFEGUARD_LLM_BASE_URL",
        "SAFEGUARD_LLM_API_KEY",
        "SAFEGUARD_LLM_MODEL",
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "MODEL_NAME",
        "TEMPERATURE",
        "MAX_TOKENS",
        "CONCURRENCY",
        "INPUT_PATH",
        "OUTPUT_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    # dotenv would otherwise load the project's real .env during Settings.from_env.
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def offline_settings(tmp_path) -> Settings:
    """Settings that never touch the network."""
    return Settings(
        llm_provider=PROVIDER_OFFLINE,
        input_path=SAMPLE_REPORT_PATH,
        output_dir=tmp_path / "output",
        concurrency=2,
        max_retries=1,
        retry_backoff_seconds=0.0,
    )


@pytest.fixture
def sample_report():
    """The bundled sample report, parsed."""
    return parse_report(SAMPLE_REPORT_PATH)
