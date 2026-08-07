#!/usr/bin/env python3
"""Launch the Blue Agent HTTP API for website integration.

    python serve_api.py                                  # 0.0.0.0:8001
    BLUE_API_HOST=127.0.0.1 BLUE_API_PORT=9001 python serve_api.py

Port map for the platform:

    3000  website / frontend
    8000  Red Agent API
    8001  Blue Agent API  (this service)

Loads the nearest ``.env`` before importing the app, so the LLM endpoint is
configured regardless of how the process was launched. A bare
``uvicorn api.server:app`` would skip this and silently run every analysis
through the heuristic engine.
"""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from dotenv import load_dotenv


def load_environment() -> None:
    """Load the first ``.env`` found from here upward, without overriding."""
    here = Path(__file__).resolve()
    for base in (here.parent, *here.parents):
        candidate = base / ".env"
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return


def main() -> None:
    """Start uvicorn with the configured host and port."""
    load_environment()

    host = os.environ.get("BLUE_API_HOST", "0.0.0.0")
    port = int(os.environ.get("BLUE_API_PORT", "8001"))
    reload_enabled = os.environ.get("BLUE_API_RELOAD", "").lower() in {"1", "true", "yes"}

    from config import Settings  # imported after .env so settings see it

    settings = Settings.from_env()
    backend = (
        f"{settings.llm_provider} / {settings.model_name}"
        if settings.llm_configured
        else "heuristic engine (no LLM endpoint configured)"
    )
    print(f"BlueAgent API on http://{host}:{port}")
    print(f"  analysis backend : {backend}")
    print("  docs             : see INTEGRATION.md")
    print(f"  health           : http://{host}:{port}/health")

    uvicorn.run(
        "api.server:app",
        host=host,
        port=port,
        reload=reload_enabled,
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()
