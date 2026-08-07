"""Modal deployment for the Blue Team Analysis Agent.

Running locally with ``app.py`` calls the Modal-hosted LLM over HTTP. This
module deploys the *agent itself* onto Modal so the Red Agent can hand a report
straight to a serverless endpoint:

    modal setup                                  # once, stores your tokens
    modal secret create blue-agent-llm \\
        MODAL_LLM_BASE_URL=https://<your-vllm-app>.modal.run/v1 \\
        MODAL_API_KEY=<key> \\
        MODEL_NAME=qwen3-32b
    modal deploy modal_app.py

Two entry points are exposed:

* ``analyze_report`` — a plain Modal function, callable from other Modal apps or
  from Python via ``modal.Function.lookup``.
* ``web`` — an HTTPS POST endpoint that takes the Red Agent report as its JSON
  body and returns the Blue analysis, so the Red Agent can hand off with a
  single request.

The container is CPU-only: this agent does inference over HTTP against the
existing vLLM deployment and needs no GPU of its own.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import modal

APP_NAME = "blue-team-analysis-agent"
REMOTE_ROOT = "/app"

# Mirror the local project into the image. Keeping the source in the image (as
# opposed to a runtime mount) means `modal deploy` produces a self-contained,
# reproducible artefact.
image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        "pydantic>=2.7",
        "python-dotenv>=1.0",
        "orjson>=3.10",
        "rich>=13.7",
        "loguru>=0.7",
        "typing_extensions>=4.11",
        "fastapi[standard]",
    )
    .add_local_dir(
        Path(__file__).parent,
        remote_path=REMOTE_ROOT,
        ignore=["output", ".git", "__pycache__", ".venv", "*.pyc", ".env"],
    )
)

app = modal.App(APP_NAME, image=image)

# Holds MODAL_LLM_BASE_URL / MODAL_API_KEY / MODEL_NAME for the inference
# endpoint the agent calls. Create it with `modal secret create blue-agent-llm`.
llm_secret = modal.Secret.from_name("blue-agent-llm", required_keys=["MODAL_LLM_BASE_URL"])


def _analyze(report: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """Shared implementation for both entry points.

    Imports happen inside the function body because the package only exists on
    the remote filesystem, not in the local deploy-time environment.
    """
    import sys

    if REMOTE_ROOT not in sys.path:
        sys.path.insert(0, REMOTE_ROOT)

    from config import Settings
    from services.llm import LLMService
    from services.parser import parse_report

    settings = Settings.from_env(**{k: v for k, v in overrides.items() if v is not None})
    parsed = parse_report(report)
    analysis = LLMService(settings).generate_report(parsed)
    return analysis.to_dict()


@app.function(secrets=[llm_secret], timeout=1800, max_containers=10)
def analyze_report(report: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """Analyse a Red Agent report and return the Blue analysis as a dict.

    Call it from another Modal app, or locally::

        fn = modal.Function.from_name("blue-team-analysis-agent", "analyze_report")
        analysis = fn.remote(json.load(open("report.json")))

    Args:
        report: The Red Agent report document.
        **overrides: Any :class:`config.Settings` field, e.g.
            ``model_name="qwen3-32b"`` or ``concurrency=8``.
    """
    return _analyze(report, **overrides)


@app.function(secrets=[llm_secret], timeout=1800, max_containers=10)
@modal.fastapi_endpoint(method="POST", docs=True)
def web(report: dict[str, Any]) -> dict[str, Any]:
    """HTTPS endpoint: POST a Red Agent report, receive the Blue analysis.

    ``curl -X POST https://<workspace>--blue-team-analysis-agent-web.modal.run \\
        -H 'Content-Type: application/json' -d @report.json``
    """
    return _analyze(report)


@app.local_entrypoint()
def main(report_path: str = "input/sample_report.json", output_path: str = "output/blue_analysis.json") -> None:
    """Smoke-test the deployment from your laptop: ``modal run modal_app.py``."""
    import json

    document = json.loads(Path(report_path).read_text(encoding="utf-8"))
    result = analyze_report.remote(document)

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")

    metadata = result.get("metadata", {})
    print(f"Overall risk : {result.get('overall_risk')}")
    print(f"Findings     : {metadata.get('findings_analysed')} "
          f"({metadata.get('llm_analysed')} via LLM)")
    print(f"Written to   : {destination}")
