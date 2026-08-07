"""Job registry and execution for the Blue Agent HTTP API.

An analysis takes seconds to minutes — one LLM call per finding, plus two
summary calls, against an endpoint that cold-starts. That is far too long for a
request/response cycle, so the API accepts work, returns a job ID, and lets the
website poll. This module owns that lifecycle; :mod:`api.server` owns only HTTP.

State lives in memory, which is correct for a single-process deployment. To
scale horizontally, replace :class:`JobStore` with a Redis- or database-backed
implementation — the interface is deliberately small.
"""

from __future__ import annotations

import json
import os
import threading
import traceback
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from config import PROVIDER_OFFLINE, PROJECT_ROOT, Settings
from services.llm import LLMService
from services.parser import ReportParseError, parse_report
from services.report_generator import ReportGenerator
from utils.logger import get_logger

log = get_logger(__name__)

# Where per-job artefacts are written. Each job gets its own directory so
# results stay downloadable after the run and never overwrite each other.
ARTIFACT_ROOT = Path(
    os.environ.get("BLUE_API_ARTIFACT_DIR") or PROJECT_ROOT / "output" / "api"
)

# Settings fields a caller may override per request. Everything else — endpoint
# URL, API key, timeouts — stays server-side and is never client-controlled.
ALLOWED_OPTIONS = {
    "concurrency",
    "temperature",
    "max_tokens",
    "model_name",
    "llm_provider",
    "allow_offline_fallback",
}

# Where the Red Agent API lives when a request does not say. Overridable with
# the RED_AGENT_URL environment variable.
DEFAULT_RED_AGENT_URL = "http://127.0.0.1:8000"

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_ERROR = "error"


class RequestError(ValueError):
    """A client-side problem: bad body, unknown option, unreachable source."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


@dataclass
class AnalysisRequest:
    """A validated request to analyse one Red Agent report.

    Exactly one source must be supplied: an inline ``report`` document, a
    ``red_agent_job_id`` to pull from the Red Agent API, or a server-local
    ``report_path``.
    """

    report: Optional[dict[str, Any]] = None
    red_agent_job_id: Optional[str] = None
    red_agent_url: Optional[str] = None
    report_path: Optional[str] = None
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def source(self) -> dict[str, str]:
        """Human-readable provenance, echoed back in the job record."""
        if self.red_agent_job_id:
            return {"kind": "red_agent_job", "ref": self.red_agent_job_id}
        if self.report_path:
            return {"kind": "path", "ref": self.report_path}
        return {"kind": "inline", "ref": "request body"}

    @classmethod
    def from_body(cls, body: Any) -> "AnalysisRequest":
        """Build a request from a parsed JSON body.

        Accepts either an envelope (``{"report": {...}, "options": {...}}``) or
        a bare Red Agent report posted directly. The bare form is detected by
        the presence of report-shaped keys, which keeps the simplest possible
        integration — pipe the Red Agent's output straight in — working.
        """
        if not isinstance(body, dict):
            raise RequestError("request body must be a JSON object")

        envelope_keys = {"report", "red_agent_job_id", "red_agent_url", "report_path", "options"}
        looks_like_raw_report = bool(
            {"findings", "engagement_id", "posture", "vulnerabilities"} & set(body)
        )
        if looks_like_raw_report and not (envelope_keys & set(body)):
            return cls(report=body)

        unknown = set(body) - envelope_keys
        if unknown:
            raise RequestError(
                f"unknown field(s): {sorted(unknown)}; expected any of {sorted(envelope_keys)}",
                status_code=422,
            )

        request = cls(
            report=body.get("report"),
            red_agent_job_id=body.get("red_agent_job_id"),
            red_agent_url=body.get("red_agent_url"),
            report_path=body.get("report_path"),
            options=body.get("options") or {},
        )
        request.validate()
        return request

    def validate(self) -> None:
        """Check that exactly one source and only known options were given."""
        sources = [
            self.report is not None,
            bool(self.red_agent_job_id),
            bool(self.report_path),
        ]
        if sum(sources) == 0:
            raise RequestError(
                "provide one of: report (inline document), red_agent_job_id, or report_path",
                status_code=422,
            )
        if sum(sources) > 1:
            raise RequestError(
                "provide exactly one of: report, red_agent_job_id, report_path",
                status_code=422,
            )
        if self.report is not None and not isinstance(self.report, (dict, list)):
            raise RequestError("report must be a JSON object or array", status_code=422)
        if not isinstance(self.options, dict):
            raise RequestError("options must be a JSON object", status_code=422)

        unknown = set(self.options) - (ALLOWED_OPTIONS | {"offline"})
        if unknown:
            raise RequestError(
                f"unknown option(s): {sorted(unknown)}; "
                f"allowed: {sorted(ALLOWED_OPTIONS | {'offline'})}",
                status_code=422,
            )

    def settings_overrides(self) -> dict[str, Any]:
        """Translate request options into :class:`Settings` overrides."""
        overrides = {k: v for k, v in self.options.items() if k in ALLOWED_OPTIONS}
        if self.options.get("offline"):
            overrides["llm_provider"] = PROVIDER_OFFLINE
        return overrides


# ---------------------------------------------------------------------------
# Source resolution
# ---------------------------------------------------------------------------


def fetch_red_agent_report(
    job_id: str, base_url: Optional[str] = None, *, timeout: float = 30.0
) -> dict[str, Any]:
    """Pull a finished report straight from the Red Agent API.

    This is the one-click path for the website: the Red Agent scan finishes, the
    frontend hands the Blue Agent the same job ID, and no report ever transits
    the browser.

    Args:
        job_id: The Red Agent's job identifier.
        base_url: Red Agent API root. Falls back to the ``RED_AGENT_URL``
            environment variable, then to ``http://127.0.0.1:8000``.
        timeout: Socket timeout in seconds.

    Raises:
        RequestError: The Red Agent was unreachable, or the report was missing
            or not ready.
    """
    root = (base_url or os.environ.get("RED_AGENT_URL") or DEFAULT_RED_AGENT_URL).rstrip("/")
    url = f"{root}/api/v1/scans/{job_id}/report"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        if exc.code == 404:
            raise RequestError(
                f"Red Agent job {job_id!r} not found at {root}", status_code=404
            ) from exc
        if exc.code == 409:
            raise RequestError(
                f"Red Agent job {job_id!r} has no report yet: {detail}", status_code=409
            ) from exc
        raise RequestError(
            f"Red Agent returned HTTP {exc.code} for {url}: {detail}", status_code=502
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RequestError(
            f"cannot reach the Red Agent API at {root}: {exc}. "
            "Is it running (python serve_api.py) and is red_agent_url correct?",
            status_code=502,
        ) from exc
    except json.JSONDecodeError as exc:
        raise RequestError(f"Red Agent returned invalid JSON: {exc}", status_code=502) from exc


def resolve_source(request: AnalysisRequest) -> Any:
    """Return the report document for ``request``, fetching it if necessary."""
    if request.report is not None:
        return request.report
    if request.red_agent_job_id:
        return fetch_red_agent_report(request.red_agent_job_id, request.red_agent_url)
    path = Path(request.report_path or "")
    if not path.is_file():
        raise RequestError(f"report_path not found on the server: {path}", status_code=404)
    return path


# ---------------------------------------------------------------------------
# Job store
# ---------------------------------------------------------------------------


class JobStore:
    """Thread-safe in-memory job registry with a bounded worker pool."""

    def __init__(
        self,
        *,
        max_workers: int = 2,
        history: int = 200,
        artifact_root: Optional[Path] = None,
    ) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="analysis")
        self._history = history
        self._artifact_root = Path(artifact_root) if artifact_root else ARTIFACT_ROOT

    # --- registry ----------------------------------------------------

    def create(self, request: AnalysisRequest) -> dict[str, Any]:
        """Register a queued job and schedule it. Returns the job record."""
        job_id = uuid.uuid4().hex
        record: dict[str, Any] = {
            "job_id": job_id,
            "status": STATUS_QUEUED,
            "created_at": _now(),
            "started_at": None,
            "finished_at": None,
            "source": request.source,
            "progress": {"analysed": 0, "total": None, "percent": 0},
            "links": {
                "self": f"/api/v1/analyses/{job_id}",
                "report": f"/api/v1/analyses/{job_id}/report",
                "markdown": f"/api/v1/analyses/{job_id}/report.md",
            },
            "error": None,
        }
        with self._lock:
            self._jobs[job_id] = record
            self._evict_locked()
        self._pool.submit(self._execute, job_id, request)
        return dict(record)

    def get(self, job_id: str) -> Optional[dict[str, Any]]:
        """Return a copy of the job record, or ``None`` if unknown."""
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        """Most recent jobs first, without their full results."""
        with self._lock:
            jobs = list(self._jobs.values())
        summaries = [{k: v for k, v in job.items() if k != "analysis"} for job in jobs]
        return sorted(summaries, key=lambda j: j["created_at"], reverse=True)[:limit]

    def delete(self, job_id: str) -> bool:
        """Forget a job and remove its artefacts. Returns whether it existed."""
        with self._lock:
            job = self._jobs.pop(job_id, None)
        if job is None:
            return False
        directory = self._artifact_root / job_id
        if directory.is_dir():
            for artefact in directory.glob("*"):
                artefact.unlink(missing_ok=True)
            directory.rmdir()
        return True

    def analysis(self, job_id: str) -> Optional[dict[str, Any]]:
        """Return the full analysis document for a completed job."""
        with self._lock:
            job = self._jobs.get(job_id)
            return job.get("analysis") if job else None

    def _update(self, job_id: str, **changes: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.update(changes)

    def _evict_locked(self) -> None:
        """Drop the oldest finished jobs once the registry exceeds ``history``."""
        if len(self._jobs) <= self._history:
            return
        finished = sorted(
            (j for j in self._jobs.values() if j["status"] in {STATUS_COMPLETED, STATUS_ERROR}),
            key=lambda j: j["created_at"],
        )
        for job in finished[: len(self._jobs) - self._history]:
            self._jobs.pop(job["job_id"], None)

    # --- execution ---------------------------------------------------

    def _execute(self, job_id: str, request: AnalysisRequest) -> None:
        """Run one analysis to completion, recording progress and errors."""
        self._update(job_id, status=STATUS_RUNNING, started_at=_now())
        try:
            source = resolve_source(request)
            report = parse_report(source)

            self._update(
                job_id,
                engagement_id=report.engagement_id,
                target=report.target,
                mode=report.mode,
                progress={"analysed": 0, "total": len(report.findings), "percent": 0},
            )

            def on_progress(done: int, total: int) -> None:
                self._update(
                    job_id,
                    progress={
                        "analysed": done,
                        "total": total,
                        "percent": round(100 * done / total) if total else 100,
                    },
                )

            settings = Settings.from_env(**request.settings_overrides())
            analysis = LLMService(settings).generate_report(report, progress=on_progress)

            paths = ReportGenerator(self._artifact_root / job_id).generate(analysis)
            document = analysis.to_dict()

            self._update(
                job_id,
                status=STATUS_COMPLETED,
                finished_at=_now(),
                overall_risk=analysis.overall_risk.value,
                summary=document["summary"],
                metadata=document["metadata"],
                artifacts={key: str(path) for key, path in paths.items()},
                analysis=document,
            )
            log.info("Job {} completed — overall risk {}", job_id, analysis.overall_risk.value)

        except (RequestError, ReportParseError) as exc:
            log.warning("Job {} rejected: {}", job_id, exc)
            self._update(
                job_id,
                status=STATUS_ERROR,
                finished_at=_now(),
                error={"type": type(exc).__name__, "message": str(exc)},
            )
        except Exception as exc:  # noqa: BLE001 - a worker must never die silently
            log.exception("Job {} failed", job_id)
            self._update(
                job_id,
                status=STATUS_ERROR,
                finished_at=_now(),
                error={
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(limit=5),
                },
            )


__all__ = [
    "ALLOWED_OPTIONS",
    "ARTIFACT_ROOT",
    "AnalysisRequest",
    "JobStore",
    "RequestError",
    "STATUS_COMPLETED",
    "STATUS_ERROR",
    "STATUS_QUEUED",
    "STATUS_RUNNING",
    "fetch_red_agent_report",
    "resolve_source",
]
