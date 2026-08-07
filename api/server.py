"""HTTP API for website integration.

Mirrors the Red Agent's API conventions (Starlette, ``/api/v1`` prefix,
background jobs the site polls) so the frontend treats both agents the same
way. The Blue Agent listens on **8001** by default; the Red Agent owns 8000 and
the website owns 3000.

    GET    /health                              liveness + backend status
    GET    /api/v1/config                       capabilities; drives the UI form
    POST   /api/v1/analyses                     -> 202 {job_id, poll}
    GET    /api/v1/analyses                     recent jobs, newest first
    GET    /api/v1/analyses/{job_id}            status + progress + summary
    GET    /api/v1/analyses/{job_id}/report     full blue_analysis.json
    GET    /api/v1/analyses/{job_id}/report.md  blue_report.md as text/markdown
    DELETE /api/v1/analyses/{job_id}            forget a job and its artefacts

Run it with::

    python serve_api.py                      # 0.0.0.0:8001
    BLUE_API_PORT=9001 python serve_api.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from api.jobs import (
    ALLOWED_OPTIONS,
    AnalysisRequest,
    JobStore,
    RequestError,
    STATUS_COMPLETED,
)
from config import Settings
from services.report_generator import MARKDOWN_FILENAME
from utils.logger import configure_logging, get_logger

SERVICE_NAME = "blueagent-api"
API_VERSION = "1.0.0"

configure_logging(os.environ.get("LOG_LEVEL", "INFO"))
log = get_logger(SERVICE_NAME)

_store = JobStore(
    max_workers=int(os.environ.get("BLUE_API_WORKERS", "2")),
    history=int(os.environ.get("BLUE_API_JOB_HISTORY", "200")),
)


def _error(message: str, status_code: int, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": message, **extra}, status_code=status_code)


async def _json_body(request: Request) -> Any:
    try:
        return await request.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise RequestError(f"request body must be valid JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


async def health(_: Request) -> JSONResponse:
    """Liveness probe. Also reports whether a live LLM is reachable."""
    settings = Settings.from_env()
    return JSONResponse(
        {
            "status": "ok",
            "service": SERVICE_NAME,
            "version": API_VERSION,
            "llm_configured": settings.llm_configured,
            "provider": settings.llm_provider,
            "model": settings.model_name,
        }
    )


async def config(_: Request) -> JSONResponse:
    """Capabilities and the request contract the website renders its form from."""
    settings = Settings.from_env()
    return JSONResponse(
        {
            "service": SERVICE_NAME,
            "version": API_VERSION,
            "llm": {
                "configured": settings.llm_configured,
                "provider": settings.llm_provider,
                "model": settings.model_name,
                "degrades_to_heuristics": settings.allow_offline_fallback,
                "note": (
                    "The LLM endpoint scales to zero, so the first analysis after "
                    "an idle period may take up to a few minutes."
                ),
            },
            "sources": {
                "report": "inline Red Agent report document",
                "red_agent_job_id": "job id from the Red Agent API; the report is fetched server-side",
                "report_path": "path to a report file on the Blue Agent host",
            },
            "options": sorted(ALLOWED_OPTIONS | {"offline"}),
            "severities": ["critical", "high", "medium", "low", "info", "unknown"],
            "statuses": ["queued", "running", "completed", "error"],
        }
    )


async def create_analysis(request: Request) -> JSONResponse:
    """Accept a report and queue an analysis. Returns 202 with a poll URL."""
    try:
        body = await _json_body(request)
        analysis_request = AnalysisRequest.from_body(body)
    except RequestError as exc:
        return _error(str(exc), exc.status_code)

    job = _store.create(analysis_request)
    log.info("Queued analysis {} (source: {})", job["job_id"], job["source"]["kind"])
    return JSONResponse(
        {
            "job_id": job["job_id"],
            "status": job["status"],
            "created_at": job["created_at"],
            "source": job["source"],
            "poll": job["links"]["self"],
            "links": job["links"],
        },
        status_code=202,
    )


async def list_analyses(request: Request) -> JSONResponse:
    """Recent jobs, newest first. ``?limit=`` defaults to 50."""
    try:
        limit = max(1, min(int(request.query_params.get("limit", "50")), 200))
    except ValueError:
        return _error("limit must be an integer", 400)
    jobs = _store.list(limit=limit)
    return JSONResponse({"count": len(jobs), "analyses": jobs})


async def get_analysis(request: Request) -> JSONResponse:
    """Job status, progress and (once finished) the summary block.

    Deliberately omits the full findings array so polling stays cheap; fetch
    ``/report`` once ``status == "completed"``.
    """
    job = _store.get(request.path_params["job_id"])
    if job is None:
        return _error("unknown job_id", 404)
    job.pop("analysis", None)
    return JSONResponse(job)


async def get_report(request: Request) -> JSONResponse:
    """The full ``blue_analysis.json`` document for a completed job."""
    job_id = request.path_params["job_id"]
    job = _store.get(job_id)
    if job is None:
        return _error("unknown job_id", 404)
    if job["status"] != STATUS_COMPLETED:
        return _error(
            f"report not ready (status={job['status']})",
            409,
            status=job["status"],
            progress=job.get("progress"),
        )
    document = _store.analysis(job_id)
    if document is None:
        return _error("analysis missing for a completed job", 500)
    return JSONResponse(document)


async def get_markdown(request: Request) -> Response:
    """The rendered ``blue_report.md``, as ``text/markdown``.

    ``?download=1`` sets a Content-Disposition header so the browser saves it.
    """
    job_id = request.path_params["job_id"]
    job = _store.get(job_id)
    if job is None:
        return _error("unknown job_id", 404)
    if job["status"] != STATUS_COMPLETED:
        return _error(f"report not ready (status={job['status']})", 409)

    path = Path(job.get("artifacts", {}).get("markdown", ""))
    if not path.is_file():
        return _error("markdown artefact missing on disk", 500)

    headers = {}
    if request.query_params.get("download"):
        headers["Content-Disposition"] = f'attachment; filename="{MARKDOWN_FILENAME}"'
    return PlainTextResponse(
        path.read_text(encoding="utf-8"), media_type="text/markdown; charset=utf-8", headers=headers
    )


async def delete_analysis(request: Request) -> Response:
    """Forget a job and delete its artefacts."""
    if not _store.delete(request.path_params["job_id"]):
        return _error("unknown job_id", 404)
    return Response(status_code=204)


routes = [
    Route("/health", health, methods=["GET"]),
    Route("/api/v1/config", config, methods=["GET"]),
    Route("/api/v1/analyses", create_analysis, methods=["POST"]),
    Route("/api/v1/analyses", list_analyses, methods=["GET"]),
    Route("/api/v1/analyses/{job_id}", get_analysis, methods=["GET"]),
    Route("/api/v1/analyses/{job_id}", delete_analysis, methods=["DELETE"]),
    Route("/api/v1/analyses/{job_id}/report", get_report, methods=["GET"]),
    Route("/api/v1/analyses/{job_id}/report.md", get_markdown, methods=["GET"]),
]

# The website runs on its own origin (localhost:3000), and it sends
# application/json — which is not CORS-safelisted — so every request is
# preflighted. Without this middleware the integration fails in the browser
# before a request ever reaches a route.
#
# Pinning exact ports is brittle for local work (a dev server hops 3000 -> 3001
# when the port is busy), so any loopback origin is allowed by default; that
# still refuses arbitrary remote pages. Set BLUE_API_CORS_ORIGINS
# (comma-separated, or "*") to pin real origins for a deployment.
_LOOPBACK_ORIGIN_RE = r"https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?"

_configured_origins = os.environ.get("BLUE_API_CORS_ORIGINS", "").strip()
_cors_kwargs: dict[str, Any] = (
    {"allow_origins": [o.strip() for o in _configured_origins.split(",") if o.strip()]}
    if _configured_origins
    else {"allow_origin_regex": _LOOPBACK_ORIGIN_RE}
)

middleware = [
    Middleware(
        CORSMiddleware,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["content-type"],
        **_cors_kwargs,
    )
]

app = Starlette(routes=routes, middleware=middleware)
