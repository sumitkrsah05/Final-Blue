"""Central configuration for the Blue Team Analysis Agent.

Every tunable value lives here and is sourced from the environment (``.env``
via ``python-dotenv``). No other module reads ``os.environ`` directly, so
swapping the LLM backend or retuning generation parameters is a single-file
change.

Environment variables are read through *alias chains* so the agent works
unchanged against an existing Red Agent deployment: ``SAFEGUARD_LLM_BASE_URL``
and friends are accepted alongside the Blue Agent's own ``MODAL_*`` names.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Final, Optional, Sequence

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parent
DEFAULT_INPUT: Final[Path] = PROJECT_ROOT / "input" / "sample_report.json"
DEFAULT_OUTPUT_DIR: Final[Path] = PROJECT_ROOT / "output"

# Provider identifiers understood by :mod:`services.llm`.
PROVIDER_MODAL: Final[str] = "modal"
PROVIDER_OPENAI_COMPATIBLE: Final[str] = "openai"
PROVIDER_OFFLINE: Final[str] = "offline"


def _env(*names: str, default: Optional[str] = None) -> Optional[str]:
    """Return the first non-empty value among ``names`` from the environment."""
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip():
            return value.strip()
    return default


def _env_float(names: Sequence[str], default: float) -> float:
    raw = _env(*names)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(names: Sequence[str], default: int) -> int:
    raw = _env(*names)
    if raw is None:
        return default
    try:
        return int(float(raw))
    except ValueError:
        return default


def _env_bool(names: Sequence[str], default: bool) -> bool:
    raw = _env(*names)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    """Immutable, validated runtime configuration."""

    model_config = {"frozen": True, "extra": "forbid"}

    # --- LLM backend -----------------------------------------------------
    llm_provider: str = Field(
        default=PROVIDER_MODAL,
        description="modal | openai | offline. All HTTP providers speak the "
        "OpenAI chat-completions dialect, so vLLM, Ollama, Azure OpenAI and "
        "Anthropic-compatible gateways work by pointing base_url at them.",
    )
    llm_base_url: Optional[str] = Field(
        default=None,
        description="Endpoint root, including the /v1 suffix.",
    )
    llm_api_key: Optional[str] = Field(default=None, repr=False)
    model_name: str = "qwen3-32b"

    # --- Generation ------------------------------------------------------
    temperature: float = 0.2
    max_tokens: int = 4096
    enable_thinking: bool = Field(
        default=False,
        description="Qwen-style hybrid reasoning toggle, sent as the top-level "
        "chat_template_kwargs field that vLLM understands.",
    )

    # --- Transport -------------------------------------------------------
    request_timeout: float = Field(
        default=180.0,
        description="Generous by default: Modal scales to zero and cold starts "
        "can take tens of seconds.",
    )
    max_retries: int = 3
    retry_backoff_seconds: float = 2.0
    concurrency: int = Field(default=4, description="Findings analysed in parallel.")

    # --- Behaviour -------------------------------------------------------
    allow_offline_fallback: bool = Field(
        default=True,
        description="When the LLM is unreachable, fall back to the deterministic "
        "heuristic analyser instead of aborting the run.",
    )

    # --- Modal SDK (only needed for `modal deploy modal_app.py`) ---------
    modal_token_id: Optional[str] = Field(default=None, repr=False)
    modal_token_secret: Optional[str] = Field(default=None, repr=False)

    # --- I/O -------------------------------------------------------------
    input_path: Path = DEFAULT_INPUT
    output_dir: Path = DEFAULT_OUTPUT_DIR
    log_level: str = "INFO"

    @field_validator("llm_provider")
    @classmethod
    def _known_provider(cls, value: str) -> str:
        normalised = value.strip().lower()
        allowed = {
            PROVIDER_MODAL,
            PROVIDER_OPENAI_COMPATIBLE,
            PROVIDER_OFFLINE,
            "vllm",
            "ollama",
            "azure",
        }
        if normalised not in allowed:
            raise ValueError(
                f"unknown LLM_PROVIDER {value!r}; expected one of {sorted(allowed)}"
            )
        return normalised

    @field_validator("llm_base_url")
    @classmethod
    def _normalise_base_url(cls, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        url = value.rstrip("/")
        # The chat-completions path is appended by the provider; a base URL that
        # forgets /v1 is the single most common misconfiguration.
        if not url.endswith("/v1"):
            url = f"{url}/v1"
        return url

    @field_validator("temperature")
    @classmethod
    def _sane_temperature(cls, value: float) -> float:
        return min(max(value, 0.0), 2.0)

    @field_validator("concurrency", "max_retries")
    @classmethod
    def _at_least_one(cls, value: int) -> int:
        return max(1, value)

    @property
    def llm_configured(self) -> bool:
        """True when a live endpoint is available for this run."""
        return self.llm_provider != PROVIDER_OFFLINE and bool(self.llm_base_url)

    @classmethod
    def from_env(cls, **overrides: Any) -> "Settings":
        """Build settings from ``.env`` + process environment, then overrides.

        ``overrides`` (typically CLI flags) always win, and ``None`` values are
        discarded so callers can pass optional arguments straight through.
        """
        load_dotenv(PROJECT_ROOT / ".env", override=False)
        load_dotenv(override=False)  # also honour a .env in the caller's cwd

        values: dict[str, Any] = {
            "llm_provider": _env(
                "LLM_PROVIDER", "BLUE_LLM_PROVIDER", default=PROVIDER_MODAL
            ),
            "llm_base_url": _env(
                "MODAL_LLM_BASE_URL",
                "MODAL_ENDPOINT_URL",
                "LLM_BASE_URL",
                "SAFEGUARD_LLM_BASE_URL",
                "OPENAI_BASE_URL",
            ),
            "llm_api_key": _env(
                "MODAL_API_KEY",
                "LLM_API_KEY",
                "SAFEGUARD_LLM_API_KEY",
                "OPENAI_API_KEY",
            ),
            "model_name": _env(
                "MODEL_NAME", "LLM_MODEL", "SAFEGUARD_LLM_MODEL", default="qwen3-32b"
            ),
            "temperature": _env_float(["TEMPERATURE", "LLM_TEMPERATURE"], 0.2),
            "max_tokens": _env_int(["MAX_TOKENS", "LLM_MAX_TOKENS"], 4096),
            "enable_thinking": _env_bool(["ENABLE_THINKING"], False),
            "request_timeout": _env_float(["REQUEST_TIMEOUT"], 180.0),
            "max_retries": _env_int(["MAX_RETRIES"], 3),
            "retry_backoff_seconds": _env_float(["RETRY_BACKOFF_SECONDS"], 2.0),
            "concurrency": _env_int(["CONCURRENCY"], 4),
            "allow_offline_fallback": _env_bool(["ALLOW_OFFLINE_FALLBACK"], True),
            "modal_token_id": _env("MODAL_TOKEN_ID"),
            "modal_token_secret": _env("MODAL_TOKEN_SECRET"),
            "log_level": _env("LOG_LEVEL", default="INFO"),
        }

        input_path = _env("INPUT_PATH")
        if input_path:
            values["input_path"] = Path(input_path)
        output_dir = _env("OUTPUT_DIR")
        if output_dir:
            values["output_dir"] = Path(output_dir)

        values.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**values)


def get_settings(**overrides: Any) -> Settings:
    """Convenience wrapper mirroring the usual settings-factory idiom."""
    return Settings.from_env(**overrides)
