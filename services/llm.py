"""LLM access layer.

This is the **only** module in the agent that talks to a model. Everything else
depends on :class:`LLMService`, so replacing Modal with OpenAI, Anthropic, Azure
OpenAI, Ollama or a local vLLM is a provider swap plus two environment
variables — no business logic changes.

Layering:

``LLMService``            orchestration, prompt selection, validation, fallback
``BaseLLMProvider``       transport contract (``complete``)
``OpenAICompatibleProvider``  HTTP transport for any OpenAI-dialect endpoint
``OfflineProvider``       explicit no-LLM mode

Reliability behaviour that matters for the Modal deployment: the endpoint scales
to zero, so the first request after idle can take tens of seconds. The timeout
defaults to 180 s and failures are retried with exponential backoff before the
deterministic heuristic analyser takes over, which keeps a demo alive through a
cold start.
"""

from __future__ import annotations

import abc
import json
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable, Optional, Sequence

ProgressCallback = Callable[[int, int], None]
"""Called as ``(completed, total)`` after each finding is analysed."""

from pydantic import ValidationError

from config import PROVIDER_OFFLINE, Settings
from models.schemas import (
    AnalysisMetadata,
    BlueAnalysis,
    ExecutiveSummary,
    FindingAnalysis,
    MitreAttack,
    MitreTechnique,
    RedFinding,
    RedTeamReport,
    Severity,
    TechnicalSummary,
)
from prompts.blue_analysis_prompt import (
    PROMPT_VERSION,
    build_executive_summary_prompt,
    build_finding_analysis_prompt,
    build_system_prompt,
    build_technical_summary_prompt,
)
from services import mitre
from services.heuristics import HeuristicAnalyzer
from utils.logger import get_logger

log = get_logger(__name__)


class LLMError(RuntimeError):
    """Raised when the model could not be reached or returned nothing usable."""


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


class BaseLLMProvider(abc.ABC):
    """Transport contract every backend must satisfy.

    Implement :meth:`complete` and register the class in :data:`PROVIDERS` to
    add a backend. Providers are transport-only: they know nothing about
    prompts, findings, or reports.
    """

    name: str = "base"

    @abc.abstractmethod
    def complete(
        self,
        messages: Sequence[dict[str, str]],
        *,
        temperature: float,
        max_tokens: int,
        json_mode: bool = False,
    ) -> str:
        """Return the assistant message content for ``messages``.

        Raises:
            LLMError: On transport failure or an unusable response.
        """

    @property
    def available(self) -> bool:
        """Whether this provider can currently serve requests."""
        return True


class OpenAICompatibleProvider(BaseLLMProvider):
    """HTTP client for any endpoint speaking the OpenAI chat-completions API.

    Covers the Modal-hosted vLLM deployment as well as OpenAI, Azure OpenAI,
    Ollama, and self-hosted vLLM/TGI gateways. Uses :mod:`urllib` from the
    standard library rather than an SDK, so the container stays small and the
    dependency surface minimal.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: Optional[str],
        model: str,
        timeout: float = 180.0,
        enable_thinking: bool = False,
        name: str = "openai-compatible",
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required for an HTTP LLM provider")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.enable_thinking = enable_thinking
        self.name = name

    def complete(
        self,
        messages: Sequence[dict[str, str]],
        *,
        temperature: float,
        max_tokens: int,
        json_mode: bool = False,
    ) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": list(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        # Qwen-style hybrid reasoning toggle. vLLM reads it from the top-level
        # `chat_template_kwargs`; the `extra_body` form is silently ignored.
        payload["chat_template_kwargs"] = {"enable_thinking": self.enable_thinking}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise LLMError(f"HTTP {exc.code} from {self.base_url}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMError(f"request to {self.base_url} failed: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise LLMError(f"non-JSON response envelope from {self.base_url}: {exc}") from exc

        try:
            choice = body["choices"][0]
            content = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected response shape: {exc}") from exc

        if not content:
            # Reasoning models can spend the whole budget on the thinking trace
            # and return empty content with finish_reason="length".
            raise LLMError(
                f"empty completion (finish_reason={choice.get('finish_reason')!r}); "
                "raise MAX_TOKENS or set ENABLE_THINKING=false"
            )
        return content


class OfflineProvider(BaseLLMProvider):
    """Explicit no-LLM provider; every call routes to the heuristic analyser."""

    name = "offline"

    @property
    def available(self) -> bool:
        return False

    def complete(self, messages, *, temperature, max_tokens, json_mode=False) -> str:
        raise LLMError("offline provider: no LLM configured for this run")


PROVIDERS: dict[str, type[BaseLLMProvider]] = {
    "modal": OpenAICompatibleProvider,
    "openai": OpenAICompatibleProvider,
    "vllm": OpenAICompatibleProvider,
    "ollama": OpenAICompatibleProvider,
    "azure": OpenAICompatibleProvider,
    PROVIDER_OFFLINE: OfflineProvider,
}


def build_provider(settings: Settings) -> BaseLLMProvider:
    """Construct the provider named by ``settings``.

    Falls back to :class:`OfflineProvider` when no endpoint is configured, so a
    missing ``.env`` degrades instead of crashing.
    """
    if settings.llm_provider == PROVIDER_OFFLINE or not settings.llm_base_url:
        if settings.llm_provider != PROVIDER_OFFLINE:
            log.warning(
                "No LLM base URL configured (set MODAL_LLM_BASE_URL or "
                "SAFEGUARD_LLM_BASE_URL) — using the heuristic analyser"
            )
        return OfflineProvider()

    provider_cls = PROVIDERS.get(settings.llm_provider, OpenAICompatibleProvider)
    if provider_cls is OfflineProvider:
        return OfflineProvider()
    return provider_cls(  # type: ignore[call-arg]
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        model=settings.model_name,
        timeout=settings.request_timeout,
        enable_thinking=settings.enable_thinking,
        name=settings.llm_provider,
    )


# ---------------------------------------------------------------------------
# JSON repair
# ---------------------------------------------------------------------------


def extract_json_object(text: str) -> dict[str, Any]:
    """Pull the first JSON object out of a model reply.

    Models wrap JSON in prose or ``` fences even when told not to, and
    reasoning models sometimes emit a ``<think>`` block first. This scans for
    the first balanced ``{...}`` span (string- and escape-aware) and parses it.

    Raises:
        LLMError: No parseable JSON object was present.
    """
    if not text:
        raise LLMError("empty model reply")

    cleaned = text.strip()
    if "</think>" in cleaned:
        cleaned = cleaned.rsplit("</think>", 1)[1].strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```", 2)[1] if cleaned.count("```") >= 2 else cleaned[3:]
        if cleaned.lstrip().startswith("json"):
            cleaned = cleaned.lstrip()[4:]
        cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(cleaned)):
            char = cleaned[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = cleaned[start : index + 1]
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            return parsed
                    except json.JSONDecodeError:
                        break  # try the next '{'
        start = cleaned.find("{", start + 1)

    raise LLMError(f"no JSON object found in model reply: {cleaned[:200]!r}")


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class LLMService:
    """High-level AI operations for the Blue Agent.

    Public surface used by the rest of the application:

    * :meth:`analyze_finding` / :meth:`analyze_findings` — per-finding analysis
    * :meth:`generate_summary` — executive + technical summaries
    * :meth:`generate_report` — the whole :class:`BlueAnalysis`

    Every method degrades to :class:`~services.heuristics.HeuristicAnalyzer`
    rather than raising, unless ``settings.allow_offline_fallback`` is off.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        provider: Optional[BaseLLMProvider] = None,
        heuristics: Optional[HeuristicAnalyzer] = None,
    ) -> None:
        self.settings = settings
        self.provider = provider or build_provider(settings)
        self.heuristics = heuristics or HeuristicAnalyzer()
        self._llm_calls = 0
        self._llm_failures = 0

    # --- transport -------------------------------------------------------

    @property
    def llm_available(self) -> bool:
        """Whether a live model backs this service."""
        return self.provider.available

    def _chat(self, prompt: str, *, json_mode: bool = True) -> dict[str, Any]:
        """Send one prompt with retries and return the parsed JSON object.

        Raises:
            LLMError: Every attempt failed.
        """
        if not self.provider.available:
            raise LLMError("no LLM provider available")

        messages = [
            {"role": "system", "content": build_system_prompt()},
            {"role": "user", "content": prompt},
        ]
        last_error: Optional[Exception] = None

        for attempt in range(1, self.settings.max_retries + 1):
            try:
                self._llm_calls += 1
                raw = self.provider.complete(
                    messages,
                    temperature=self.settings.temperature,
                    max_tokens=self.settings.max_tokens,
                    json_mode=json_mode,
                )
                return extract_json_object(raw) if json_mode else {"content": raw}
            except LLMError as exc:
                last_error = exc
                self._llm_failures += 1
                if attempt < self.settings.max_retries:
                    delay = self.settings.retry_backoff_seconds * (2 ** (attempt - 1))
                    log.warning(
                        "LLM attempt {}/{} failed ({}); retrying in {:.1f}s",
                        attempt,
                        self.settings.max_retries,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
                else:
                    log.error(
                        "LLM attempt {}/{} failed ({}); giving up",
                        attempt,
                        self.settings.max_retries,
                        exc,
                    )
        raise LLMError(f"all {self.settings.max_retries} attempts failed: {last_error}")

    # --- per-finding analysis -------------------------------------------

    def analyze_finding(self, finding: RedFinding, report: RedTeamReport, position: int = 1) -> FindingAnalysis:
        """Analyse one finding, falling back to heuristics on any failure."""
        if not self.provider.available:
            return self.heuristics.analyze_finding(finding, report)

        prompt = build_finding_analysis_prompt(
            finding_block=finding.context_block(),
            engagement_id=report.engagement_id,
            mode=report.mode,
            target=report.target,
            total_findings=len(report.findings),
            severity_distribution=_format_counts(report.severity_counts),
            position=position,
        )
        try:
            payload = self._chat(prompt)
            return self._finding_from_payload(payload, finding, report)
        except (LLMError, ValidationError) as exc:
            if not self.settings.allow_offline_fallback:
                raise
            log.warning(
                "Falling back to heuristics for finding {}: {}", finding.display_id, exc
            )
            return self.heuristics.analyze_finding(finding, report)

    def analyze_findings(
        self, report: RedTeamReport, progress: Optional[ProgressCallback] = None
    ) -> list[FindingAnalysis]:
        """Analyse every finding, worst first, with bounded concurrency.

        Args:
            report: The parsed Red Agent report.
            progress: Optional ``(completed, total)`` callback, invoked once per
                finished finding. Called from worker threads, so it must be
                cheap and thread-safe — the HTTP API uses it to drive a
                progress bar.

        Returns:
            Analyses ordered as :meth:`RedTeamReport.sorted_findings`.
        """
        findings = report.sorted_findings()
        total = len(findings)
        if not findings:
            if progress is not None:
                progress(0, 0)
            return []

        counter = _ProgressCounter(total, progress)
        workers = min(self.settings.concurrency, total)
        log.info("Analysing {} finding(s) with {} worker(s)", total, workers)

        def run(finding: RedFinding, position: int) -> FindingAnalysis:
            try:
                return self.analyze_finding(finding, report, position)
            finally:
                counter.tick()

        if workers == 1:
            return [run(finding, position) for position, finding in enumerate(findings, start=1)]

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(run, finding, position)
                for position, finding in enumerate(findings, start=1)
            ]
            return [future.result() for future in futures]

    def _finding_from_payload(
        self, payload: dict[str, Any], finding: RedFinding, report: RedTeamReport
    ) -> FindingAnalysis:
        """Validate an LLM payload into :class:`FindingAnalysis`.

        Identity fields come from the report, never from the model, so the
        analysis can always be traced back to its source finding.
        """
        payload = dict(payload)
        payload.update(
            {
                "id": finding.display_id,
                "title": finding.title,
                "severity": finding.severity,
                "asset": finding.asset or report.target,
                "analysis_source": "llm",
            }
        )
        analysis = FindingAnalysis.model_validate(payload)
        analysis.mitre_attack = self._enrich_mitre(analysis.mitre_attack, finding)
        if not analysis.analysis.strip():
            raise LLMError("model returned an empty analysis body")
        return analysis

    @staticmethod
    def _enrich_mitre(mapping: MitreAttack, finding: RedFinding) -> MitreAttack:
        """Fill in technique names/tactics from the catalog and dedupe.

        Also merges in any technique the scanner asserted that the model
        dropped without comment, so scanner evidence is never lost silently.
        """
        enriched: list[MitreTechnique] = []
        seen: set[str] = set()

        for technique in mapping.techniques:
            info = mitre.lookup(technique.id)
            identifier = info.id if info else (technique.id or "").strip().upper()
            if not identifier or identifier in seen:
                continue
            seen.add(identifier)
            enriched.append(
                MitreTechnique(
                    id=identifier,
                    name=technique.name or (info.name if info else "Unmapped technique"),
                    tactic=technique.tactic or (info.tactic if info else "Unknown"),
                    rationale=technique.rationale,
                )
            )

        for asserted in finding.techniques:
            info = mitre.lookup(asserted)
            if info and info.id not in seen:
                seen.add(info.id)
                enriched.append(
                    MitreTechnique(
                        id=info.id,
                        name=info.name,
                        tactic=info.tactic,
                        rationale="Asserted by the scanning tool and retained during enrichment.",
                    )
                )

        tactics = list(mapping.tactics)
        for technique in enriched:
            if technique.tactic and technique.tactic not in tactics:
                tactics.append(technique.tactic)

        notes = mapping.notes
        if not enriched and not notes:
            notes = (
                "No reasonable ATT&CK mapping applies to this finding; it describes a "
                "condition rather than adversary behaviour."
            )
        return MitreAttack(tactics=tactics, techniques=enriched, notes=notes)

    # --- summaries -------------------------------------------------------

    def generate_summary(
        self, report: RedTeamReport, analyses: Sequence[FindingAnalysis]
    ) -> tuple[ExecutiveSummary, TechnicalSummary]:
        """Produce the executive and technical summaries."""
        return (
            self.generate_executive_summary(report, analyses),
            self.generate_technical_summary(report, analyses),
        )

    def generate_executive_summary(
        self, report: RedTeamReport, analyses: Sequence[FindingAnalysis]
    ) -> ExecutiveSummary:
        """Management-facing summary, with heuristic fallback."""
        if not self.provider.available:
            return self.heuristics.executive_summary(report, analyses)

        prompt = build_executive_summary_prompt(
            engagement_id=report.engagement_id,
            mode=report.mode,
            target=report.target,
            total_findings=len(report.findings),
            severity_distribution=_format_counts(report.severity_counts),
            highest_severity=report.highest_severity.label,
            findings_digest=_findings_digest(analyses),
        )
        try:
            return ExecutiveSummary.model_validate(self._chat(prompt))
        except (LLMError, ValidationError) as exc:
            if not self.settings.allow_offline_fallback:
                raise
            log.warning("Falling back to heuristics for the executive summary: {}", exc)
            return self.heuristics.executive_summary(report, analyses)

    def generate_technical_summary(
        self, report: RedTeamReport, analyses: Sequence[FindingAnalysis]
    ) -> TechnicalSummary:
        """Engineer-facing summary, with heuristic fallback."""
        if not self.provider.available:
            return self.heuristics.technical_summary(report, analyses)

        prompt = build_technical_summary_prompt(
            engagement_id=report.engagement_id,
            target=report.target,
            total_findings=len(report.findings),
            severity_distribution=_format_counts(report.severity_counts),
            root_cause_digest=_root_cause_digest(analyses),
            findings_digest=_findings_digest(analyses),
        )
        try:
            return TechnicalSummary.model_validate(self._chat(prompt))
        except (LLMError, ValidationError) as exc:
            if not self.settings.allow_offline_fallback:
                raise
            log.warning("Falling back to heuristics for the technical summary: {}", exc)
            return self.heuristics.technical_summary(report, analyses)

    # --- orchestration ---------------------------------------------------

    def generate_report(
        self, report: RedTeamReport, progress: Optional[ProgressCallback] = None
    ) -> BlueAnalysis:
        """Run the full pipeline and return the complete Blue Team analysis.

        Args:
            report: The parsed Red Agent report.
            progress: Optional per-finding ``(completed, total)`` callback.
        """
        analyses = self.analyze_findings(report, progress=progress)
        executive, technical = self.generate_summary(report, analyses)

        llm_count = sum(1 for a in analyses if a.analysis_source == "llm")
        heuristic_count = len(analyses) - llm_count

        analysis = BlueAnalysis(
            engagement_id=report.engagement_id,
            target=report.target,
            mode=report.mode,
            summary=self._build_summary_block(report, analyses),
            overall_risk=_overall_risk(report, analyses),
            executive_summary=executive,
            technical_summary=technical,
            findings=analyses,
            metadata=AnalysisMetadata(
                llm_provider=self.provider.name,
                model_name=self.settings.model_name if self.provider.available else "n/a",
                source_report=report.source_path or "<in-memory>",
                findings_analysed=len(analyses),
                llm_analysed=llm_count,
                heuristic_analysed=heuristic_count,
                degraded=heuristic_count > 0,
                prompt_version=PROMPT_VERSION,
            ),
        )
        log.info(
            "Analysis complete — {} finding(s): {} via LLM, {} via heuristics",
            len(analyses),
            llm_count,
            heuristic_count,
        )
        return analysis

    def _build_summary_block(
        self, report: RedTeamReport, analyses: Sequence[FindingAnalysis]
    ) -> dict[str, Any]:
        """Assemble the machine-readable ``summary`` block of the output JSON."""
        scores = [a.risk_assessment.overall_risk_score for a in analyses]
        by_priority: dict[str, int] = {}
        for analysis in analyses:
            key = analysis.risk_assessment.priority
            by_priority[key] = by_priority.get(key, 0) + 1

        tactics: list[str] = []
        for analysis in analyses:
            for tactic in analysis.mitre_attack.tactics:
                if tactic not in tactics:
                    tactics.append(tactic)

        return {
            "engagement_id": report.engagement_id,
            "target": report.target,
            "mode": report.mode,
            "total_findings": len(report.findings),
            "severity_counts": report.severity_counts,
            "priority_counts": by_priority,
            "highest_severity": report.highest_severity.value,
            "max_risk_score": max(scores, default=0.0),
            "mean_risk_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
            "immediate_actions": sum(
                len(a.recommendations_by_horizon("immediate")) for a in analyses
            ),
            "mitre_tactics_observed": tactics,
            "red_agent_summary": report.summary,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _ProgressCounter:
    """Thread-safe completion counter driving an optional progress callback.

    A failing callback must never take down an analysis, so exceptions raised
    by the consumer are logged and swallowed.
    """

    def __init__(self, total: int, callback: Optional[ProgressCallback]) -> None:
        self._total = total
        self._callback = callback
        self._done = 0
        self._lock = threading.Lock()

    def tick(self) -> None:
        if self._callback is None:
            return
        with self._lock:
            self._done += 1
            done = self._done
        try:
            self._callback(done, self._total)
        except Exception as exc:  # noqa: BLE001 - never fail the run on telemetry
            log.warning("Progress callback raised {}; continuing", exc)


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "no findings"
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    ordered = sorted(counts.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 99)
    return ", ".join(f"{count} {name}" for name, count in ordered)


def _findings_digest(analyses: Iterable[FindingAnalysis], *, limit: int = 25) -> str:
    """Compact bullet list of analysed findings for the summary prompts."""
    lines: list[str] = []
    for index, analysis in enumerate(analyses, start=1):
        if index > limit:
            lines.append("... and further findings omitted for brevity")
            break
        risk = analysis.risk_assessment
        lines.append(
            f"{index}. [{analysis.severity.label}] {analysis.title} "
            f"(asset: {analysis.asset or 'n/a'}, risk {risk.overall_risk_score}/10, "
            f"priority {risk.priority}) — root cause: "
            f"{analysis.root_cause.primary or 'undetermined'}"
        )
    return "\n".join(lines) or "No findings were reported."


def _root_cause_digest(analyses: Iterable[FindingAnalysis]) -> str:
    """Frequency table of root-cause categories across the engagement."""
    counts: dict[str, int] = {}
    for analysis in analyses:
        for category in analysis.root_cause.categories:
            counts[category] = counts.get(category, 0) + 1
    if not counts:
        return "No root causes were classified."
    return "\n".join(
        f"- {category}: {count} finding(s)"
        for category, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    )


def _overall_risk(report: RedTeamReport, analyses: Sequence[FindingAnalysis]) -> Severity:
    """Engagement-level risk: the worse of peak analysed risk and peak severity."""
    if not analyses:
        return report.highest_severity
    peak_score = max(a.risk_assessment.overall_risk_score for a in analyses)
    from_score = Severity.from_cvss(peak_score)
    from_severity = max((a.severity for a in analyses), key=lambda s: s.rank)
    return from_score if from_score.rank >= from_severity.rank else from_severity


__all__ = [
    "BaseLLMProvider",
    "LLMError",
    "LLMService",
    "OfflineProvider",
    "OpenAICompatibleProvider",
    "PROVIDERS",
    "build_provider",
    "extract_json_object",
]
