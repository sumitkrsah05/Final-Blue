"""Chat over a completed Blue Team analysis.

The website renders the analysis report and offers a chat panel next to it.
This module answers those chat turns: it condenses the ``blue_analysis.json``
document into a context block, wraps it in the chat system prompt, appends the
conversation history, and asks the model for a plain-prose reply.

Design decisions that matter for the integration:

* **Stateless.** The frontend owns the transcript and sends it back on every
  turn (``history`` in the request body). The API keeps no chat sessions, so
  it survives restarts and needs no session GC — the same reasoning that keeps
  :class:`api.jobs.JobStore` in memory does not apply here because a chat turn
  *is* a request/response cycle.
* **No heuristic fallback.** Unlike report generation, a canned answer to a
  free-form question is worse than an honest 503. Offline mode simply does not
  offer chat.
"""

from __future__ import annotations

import time
from typing import Any, Iterable, Optional, Sequence

from config import Settings
from prompts.chat_prompt import build_chat_system_prompt
from services.llm import BaseLLMProvider, LLMError, build_provider
from utils.logger import get_logger

log = get_logger(__name__)

# Bounds on what one chat turn may carry. The context block dominates the
# prompt budget, so history and message caps mostly guard against abuse.
MAX_MESSAGE_CHARS = 8_000
MAX_HISTORY_MESSAGES = 20
MAX_HISTORY_CHARS = 24_000

# Character budget for the condensed report context. Roughly 8k tokens — small
# enough to leave head-room for history and the reply within common context
# windows, large enough to keep every finding's core analysis.
MAX_CONTEXT_CHARS = 32_000
_ANALYSIS_SNIPPET_CHARS = 700

_ALLOWED_ROLES = {"user", "assistant"}


class ChatValidationError(ValueError):
    """The chat request body was malformed. Maps to HTTP 422."""


def validate_chat_turn(message: Any, history: Any) -> tuple[str, list[dict[str, str]]]:
    """Validate and normalise one chat turn from the request body.

    Returns:
        The stripped message and the trimmed history (most recent
        :data:`MAX_HISTORY_MESSAGES` entries, bounded by
        :data:`MAX_HISTORY_CHARS`).

    Raises:
        ChatValidationError: The message or history is unusable.
    """
    if not isinstance(message, str) or not message.strip():
        raise ChatValidationError("message must be a non-empty string")
    if len(message) > MAX_MESSAGE_CHARS:
        raise ChatValidationError(f"message exceeds {MAX_MESSAGE_CHARS} characters")

    if history is None:
        history = []
    if not isinstance(history, list):
        raise ChatValidationError("history must be an array of {role, content} objects")

    cleaned: list[dict[str, str]] = []
    for index, entry in enumerate(history):
        if not isinstance(entry, dict):
            raise ChatValidationError(f"history[{index}] must be an object")
        role = entry.get("role")
        content = entry.get("content")
        if role not in _ALLOWED_ROLES:
            raise ChatValidationError(
                f"history[{index}].role must be one of {sorted(_ALLOWED_ROLES)}"
            )
        if not isinstance(content, str) or not content.strip():
            raise ChatValidationError(f"history[{index}].content must be a non-empty string")
        cleaned.append({"role": role, "content": content})

    # Keep the most recent turns; the oldest context matters least.
    cleaned = cleaned[-MAX_HISTORY_MESSAGES:]
    total = sum(len(entry["content"]) for entry in cleaned)
    while cleaned and total > MAX_HISTORY_CHARS:
        total -= len(cleaned.pop(0)["content"])

    return message.strip(), cleaned


# ---------------------------------------------------------------------------
# Report context
# ---------------------------------------------------------------------------


def build_report_context(document: dict[str, Any], *, max_chars: int = MAX_CONTEXT_CHARS) -> str:
    """Condense a ``blue_analysis.json`` document into a prompt context block.

    Keeps the pieces a question is most likely to touch — the summary numbers,
    both narrative summaries, and per-finding essentials worst-first — and
    truncates the long analysis bodies so even large engagements fit the
    budget. When findings must be dropped, the block says so, so the model can
    tell the user instead of hallucinating.
    """
    summary = document.get("summary") or {}
    sections: list[str] = [
        _section(
            "Engagement overview",
            [
                f"Engagement ID: {document.get('engagement_id', 'n/a')}",
                f"Target: {document.get('target', 'n/a')}",
                f"Assessment mode: {document.get('mode', 'n/a')}",
                f"Overall risk: {document.get('overall_risk', 'n/a')}",
                f"Total findings: {summary.get('total_findings', 'n/a')}",
                f"Severity counts: {summary.get('severity_counts', {})}",
                f"Priority counts: {summary.get('priority_counts', {})}",
                f"Max risk score: {summary.get('max_risk_score', 'n/a')}/10 "
                f"(mean {summary.get('mean_risk_score', 'n/a')})",
                f"MITRE tactics observed: "
                f"{', '.join(summary.get('mitre_tactics_observed') or []) or 'none'}",
            ],
        ),
        _summary_section("Executive summary", document.get("executive_summary")),
        _summary_section("Technical summary", document.get("technical_summary")),
    ]

    header = "\n\n".join(part for part in sections if part)
    remaining = max_chars - len(header)

    findings = document.get("findings") or []
    blocks: list[str] = []
    for index, finding in enumerate(findings, start=1):
        block = _finding_block(index, finding)
        if len(block) + 2 > remaining:
            blocks.append(
                f"(Findings {index}-{len(findings)} omitted from this context for "
                "length; tell the user to consult the full report for them.)"
            )
            break
        blocks.append(block)
        remaining -= len(block) + 2

    return header + "\n\n### Findings (worst first)\n\n" + "\n\n".join(blocks or ["No findings."])


def _section(title: str, lines: Iterable[str]) -> str:
    return f"### {title}\n" + "\n".join(lines)


def _summary_section(title: str, payload: Optional[dict[str, Any]]) -> str:
    if not payload:
        return ""
    lines = []
    for key, value in payload.items():
        if isinstance(value, list):
            rendered = "\n".join(f"  - {item}" for item in value)
            lines.append(f"{key}:\n{rendered}" if rendered else f"{key}: none")
        else:
            lines.append(f"{key}: {value}")
    return _section(title, lines)


def _finding_block(index: int, finding: dict[str, Any]) -> str:
    risk = finding.get("risk_assessment") or {}
    root = finding.get("root_cause") or {}
    impact = finding.get("business_impact") or {}
    mitre = finding.get("mitre_attack") or {}
    techniques = ", ".join(
        f"{t.get('id')} {t.get('name', '')}".strip() for t in mitre.get("techniques") or []
    )
    recommendations = "\n".join(
        f"  - [{rec.get('horizon')}] {rec.get('action')}"
        for rec in (finding.get("recommendations") or [])[:5]
    )
    detections = "\n".join(f"  - {rule}" for rule in (finding.get("detection_rules") or [])[:3])

    lines = [
        f"#### {index}. [{finding.get('severity', 'unknown')}] "
        f"{finding.get('title', 'Untitled finding')} ({finding.get('id', 'n/a')})",
        f"Asset: {finding.get('asset', 'n/a')}",
        f"Risk: {risk.get('overall_risk_score', 'n/a')}/10, priority "
        f"{risk.get('priority', 'n/a')}, likelihood {risk.get('likelihood', 'n/a')}, "
        f"impact {risk.get('impact', 'n/a')}",
        f"Analysis: {_truncate(finding.get('analysis', ''), _ANALYSIS_SNIPPET_CHARS)}",
        f"Root cause: {root.get('primary', 'n/a')} "
        f"(categories: {', '.join(root.get('categories') or []) or 'n/a'})",
        f"Business impact: {_truncate(impact.get('narrative', 'n/a'), 400)}",
        f"MITRE ATT&CK: {techniques or mitre.get('notes') or 'no mapping'}",
    ]
    if recommendations:
        lines.append(f"Key recommendations:\n{recommendations}")
    if detections:
        lines.append(f"Detection guidance:\n{detections}")
    return "\n".join(lines)


def _truncate(text: str, limit: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ChatService:
    """Answers questions about one completed analysis document.

    Cheap to construct — build one per request. The provider is the same
    transport used for report generation, so chat needs no extra configuration.
    """

    def __init__(self, settings: Settings, *, provider: Optional[BaseLLMProvider] = None) -> None:
        self.settings = settings
        self.provider = provider or build_provider(settings)

    @property
    def available(self) -> bool:
        """Whether a live model backs chat. There is no offline fallback."""
        return self.provider.available

    def reply(
        self,
        document: dict[str, Any],
        message: str,
        history: Sequence[dict[str, str]] = (),
    ) -> str:
        """Return the assistant's reply to ``message`` about ``document``.

        Raises:
            LLMError: No provider is available or every attempt failed.
        """
        if not self.provider.available:
            raise LLMError("chat requires a live LLM provider; none is configured")

        messages: list[dict[str, str]] = [
            {"role": "system", "content": build_chat_system_prompt(build_report_context(document))},
            *history,
            {"role": "user", "content": message},
        ]

        last_error: Optional[Exception] = None
        for attempt in range(1, self.settings.max_retries + 1):
            try:
                reply = self.provider.complete(
                    messages,
                    temperature=self.settings.temperature,
                    max_tokens=self.settings.max_tokens,
                    json_mode=False,
                )
                return _strip_thinking(reply).strip()
            except LLMError as exc:
                last_error = exc
                if attempt < self.settings.max_retries:
                    delay = self.settings.retry_backoff_seconds * (2 ** (attempt - 1))
                    log.warning(
                        "Chat attempt {}/{} failed ({}); retrying in {:.1f}s",
                        attempt,
                        self.settings.max_retries,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
        raise LLMError(f"all {self.settings.max_retries} chat attempts failed: {last_error}")


def _strip_thinking(text: str) -> str:
    """Drop a reasoning model's ``<think>`` trace; only the answer is shown."""
    if "</think>" in text:
        return text.rsplit("</think>", 1)[1]
    return text


__all__ = [
    "ChatService",
    "ChatValidationError",
    "MAX_HISTORY_MESSAGES",
    "MAX_MESSAGE_CHARS",
    "build_report_context",
    "validate_chat_turn",
]
