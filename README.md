# Blue Team Analysis Agent

AI-driven defensive analysis of Red Team findings. The agent consumes the JSON
report produced by the Red Agent, reasons over every finding with an LLM hosted
on Modal, and emits an executive-grade Blue Team report.

> **Scope.** This agent performs **no scanning and no attacks**. It never
> contacts a target system. Its only input is a JSON document; its only outputs
> are analysis files. It is part of an authorised security assessment platform
> and is designed for use on engagements you are permitted to run.

---

## What it produces

For every finding in the Red Agent report:

| Section | Content |
| --- | --- |
| **Vulnerability analysis** | What the weakness is, why it exists here, how it is abused, and the security implications |
| **Root cause** | Primary cause plus classification (misconfiguration, missing patch, weak authentication, exposed secret, missing input validation, weak TLS, insecure dependency, …) |
| **Business impact** | Confidentiality, integrity, availability, financial, compliance, operational, reputation, customer trust, data exposure, privilege escalation, lateral movement, remote compromise |
| **MITRE ATT&CK** | Tactics and techniques with IDs and per-technique rationale — or an explicit statement that no mapping applies |
| **Risk assessment** | 0–10 risk score, likelihood, impact, priority (P0–P3), risk category, and the reasoning behind them |
| **Remediation** | Immediate / short-term / long-term actions, each tagged patch, configuration, hardening, monitoring, detection, preventive, compensating or architecture — with rationale |
| **Detection** | Concrete detection guidance: log source, signal, condition |

Plus engagement-level output: an **executive summary** (posture, top risks, most
dangerous findings, maturity, next steps), a **technical summary** (developer
guidance, infrastructure, secure coding, DevSecOps, architecture), an ATT&CK
coverage roll-up, and a consolidated remediation roadmap.

Artefacts land in `output/`:

- `blue_analysis.json` — structured record for dashboards, ticketing and diffing
- `blue_report.md` — the human-readable report

---

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env         # then fill in MODAL_LLM_BASE_URL and MODAL_API_KEY
python app.py --input input/sample_report.json
```

No credentials to hand? The agent still produces a complete report using its
deterministic heuristic engine:

```bash
python app.py --offline
```

Every heuristic section is labelled as such in both artefacts, so AI analysis is
never confused with rule-based analysis.

### CLI

```
python app.py [-i REPORT] [-o DIR] [--provider NAME] [--model NAME]
              [--base-url URL] [--temperature N] [--max-tokens N]
              [--concurrency N] [--offline] [--no-fallback]
              [--log-level LEVEL] [--quiet]
```

| Flag | Purpose |
| --- | --- |
| `--offline` | Skip the LLM entirely; use the heuristic analyser |
| `--no-fallback` | Fail the run rather than degrade to heuristics on LLM error |
| `--concurrency` | Findings analysed in parallel (default 4) |
| `--provider` | `modal`, `openai`, `vllm`, `ollama`, `azure`, `offline` |

Exit codes: `0` success, `2` bad usage or missing input, `3` unparseable
report, `4` runtime failure.

---

## HTTP API (website integration)

```bash
python serve_api.py        # 0.0.0.0:8001
```

Port map: **3000** frontend · **8000** Red Agent · **8001** Blue Agent.

The API mirrors the Red Agent's conventions — Starlette, `/api/v1`, background
jobs the site polls:

```
GET    /health                              liveness + backend status
GET    /api/v1/config                       capabilities; drives the UI form
POST   /api/v1/analyses                     -> 202 {job_id, poll}
GET    /api/v1/analyses                     recent jobs, newest first
GET    /api/v1/analyses/{job_id}            status + live progress + summary
GET    /api/v1/analyses/{job_id}/report     full blue_analysis.json
GET    /api/v1/analyses/{job_id}/report.md  blue_report.md as text/markdown
DELETE /api/v1/analyses/{job_id}            forget a job and its artefacts
```

A report can be posted inline, referenced by path, or — the one-click path —
pulled straight from the Red Agent by job ID, so it never transits the browser:

```bash
curl -X POST http://localhost:8001/api/v1/analyses \
     -H 'Content-Type: application/json' \
     -d '{"red_agent_job_id": "<red-agent-job>", "red_agent_url": "http://localhost:8000"}'
```

CORS allows any loopback origin by default, so `localhost:3000` works out of the
box. **[INTEGRATION.md](INTEGRATION.md) has the full contract**: request and
response shapes, options, error codes, a complete JavaScript client, and
deployment notes.

---

## Configuration

All settings come from the environment (`.env` via `python-dotenv`) and can be
overridden per-run by CLI flags. See `.env.example` for the full list.

```bash
LLM_PROVIDER=modal
MODAL_LLM_BASE_URL=https://your-workspace--your-vllm-app.modal.run/v1
MODAL_API_KEY=...
MODEL_NAME=qwen3-32b
TEMPERATURE=0.2
MAX_TOKENS=4096
REQUEST_TIMEOUT=180      # Modal scales to zero; cold starts are slow
MAX_RETRIES=3
CONCURRENCY=4
```

Two details worth knowing about the Modal deployment:

- **The base URL must end in `/v1`.** If you forget, the agent appends it.
- **Cold starts take tens of seconds.** The 180 s timeout and exponential-backoff
  retries exist for exactly this reason. If every retry still fails, the run
  degrades to heuristics rather than dying — which is what keeps a live demo
  alive.

If you already run the Red Agent, its `SAFEGUARD_LLM_BASE_URL`,
`SAFEGUARD_LLM_API_KEY` and `SAFEGUARD_LLM_MODEL` are read as fallbacks, so both
agents can share one environment file with no changes.

`.env` is git-ignored and is never generated by this project.

---

## Deploying on Modal

`app.py` calls a Modal-hosted LLM over HTTP. `modal_app.py` deploys the *agent
itself* onto Modal, so the Red Agent can hand off a report with one request:

```bash
modal setup
modal secret create blue-agent-llm \
    MODAL_LLM_BASE_URL=https://<your-vllm-app>.modal.run/v1 \
    MODAL_API_KEY=<key> \
    MODEL_NAME=qwen3-32b

modal run    modal_app.py     # smoke test against the sample report
modal deploy modal_app.py     # publish
```

That exposes two entry points:

```python
# From Python or another Modal app
fn = modal.Function.from_name("blue-team-analysis-agent", "analyze_report")
analysis = fn.remote(json.load(open("redagent-report.json")))
```

```bash
# Or over HTTPS
curl -X POST https://<workspace>--blue-team-analysis-agent-web.modal.run \
     -H 'Content-Type: application/json' -d @redagent-report.json
```

The container is CPU-only — inference happens over HTTP against the existing
vLLM deployment, so the Blue Agent needs no GPU of its own.

---

## Wiring it to the Red Agent

The Blue Agent's only contract is "a JSON document with findings in it", so the
handoff is a file path:

```bash
python run_agent.py demo.testfire.net          # Red Agent
python app.py -i runs-agent/<engagement>/report/report.json   # Blue Agent
```

Or in-process:

```python
from config import Settings
from services.llm import LLMService
from services.parser import parse_report
from services.report_generator import ReportGenerator

report   = parse_report(red_agent_output)      # path, JSON string, or dict
analysis = LLMService(Settings.from_env()).generate_report(report)
ReportGenerator(Path("output")).generate(analysis)
```

### The parser tolerates schema drift

The Red Agent's schema changes between versions, so the parser resolves fields
through alias chains and never rejects a document for being unfamiliar:

- `description` also matches `desc`, `details`, `detail`, `summary`, `explanation`
- `tool` also matches `tools`, `sources`, `scanner`, `engine`, `plugin`
- `cvss` accepts `8.8`, `"8.8"`, or `{"base_score": 8.8}`
- Severity accepts `Critical`, `sev1`, `moderate`, `informational`, `P2`, or a
  bare CVSS number — and is inferred from CVSS when the label is missing
- Findings may be a list, a dict keyed by ID, or nested inside an envelope
- Unrecognised keys are preserved in `extra` rather than dropped

Only genuinely unusable input (unreadable file, malformed JSON) raises
`ReportParseError`. A finding with no recognised fields at all still becomes a
finding.

---

## Architecture

```
blue_agent/
├── app.py                    CLI entry point and pipeline orchestration
├── serve_api.py              HTTP API launcher (port 8001)
├── config.py                 Settings — the only module that reads the environment
├── modal_app.py              Modal deployment (function + HTTPS endpoint)
│
├── api/
│   ├── server.py             Starlette routes, CORS — HTTP concerns only
│   └── jobs.py               Job registry, execution, Red Agent handoff
│
├── services/
│   ├── parser.py             Red Agent JSON → normalised models (schema-drift tolerant)
│   ├── llm.py                LLMService + pluggable providers — the ONLY caller of an LLM
│   ├── heuristics.py         Deterministic fallback analyser
│   ├── mitre.py              Offline ATT&CK catalog and keyword mapping
│   └── report_generator.py   BlueAnalysis → JSON + Markdown (pure, no I/O beyond writing)
│
├── prompts/
│   └── blue_analysis_prompt.py   Every prompt string in the project
│
├── models/schemas.py         Pydantic contracts, inbound and outbound
├── utils/logger.py           loguru + rich console
├── input/sample_report.json  Runnable sample
├── output/                   Generated artefacts (git-ignored)
├── INTEGRATION.md            API contract for the frontend
└── tests/                    98 tests, all offline
```

Design rules the code holds to:

1. **One LLM boundary.** Only `services/llm.py` performs inference. Everything
   else depends on `LLMService`.
2. **Prompts are data.** They live in `prompts/`, never inline in logic.
3. **Configuration is centralised.** Only `config.py` reads `os.environ`.
4. **Degrade, don't die.** Every LLM path has a deterministic fallback, and the
   report discloses when one was used.
5. **Never lose input.** Unrecognised report fields are preserved, not dropped.

### Swapping the LLM backend

Providers implement one method:

```python
class BaseLLMProvider(abc.ABC):
    @abc.abstractmethod
    def complete(self, messages, *, temperature, max_tokens, json_mode=False) -> str: ...
```

`OpenAICompatibleProvider` already covers Modal, OpenAI, Azure OpenAI, vLLM and
Ollama — those need only a different `base_url` and `MODEL_NAME`. For a
non-OpenAI dialect (Anthropic's Messages API, Bedrock, a bespoke gateway),
implement `complete` and register the class:

```python
from services.llm import PROVIDERS

class AnthropicProvider(BaseLLMProvider):
    name = "anthropic"
    def complete(self, messages, *, temperature, max_tokens, json_mode=False) -> str:
        ...

PROVIDERS["anthropic"] = AnthropicProvider
```

No other module changes.

### Extending the analysis

- **New root-cause class or remediation playbook** → add a `Playbook` to
  `services/heuristics.py`
- **New ATT&CK techniques** → add to `TECHNIQUES` in `services/mitre.py`
- **Different analysis depth or tone** → edit `prompts/blue_analysis_prompt.py`
- **New report format (HTML, PDF, SARIF)** → add a renderer alongside
  `ReportGenerator`; it reads only the analysis object

---

## Output format

`blue_analysis.json`:

```jsonc
{
  "summary": {
    "engagement_id": "...", "target": "...", "total_findings": 8,
    "severity_counts": {...}, "priority_counts": {...},
    "max_risk_score": 10.0, "immediate_actions": 12,
    "mitre_tactics_observed": [...], "red_agent_summary": {...}
  },
  "overall_risk": "critical",
  "executive_summary": { "overall_posture": "...", "top_risks": [...], ... },
  "technical_summary": { "developer_guidance": "...", ... },
  "findings": [
    {
      "title": "...", "severity": "critical", "asset": "...",
      "analysis": "...",
      "root_cause":      { "primary": "...", "categories": [...], "explanation": "..." },
      "business_impact": { "confidentiality": "...", "...": "...", "narrative": "..." },
      "mitre_attack":    { "tactics": [...], "techniques": [{"id": "T1190", ...}], "notes": "" },
      "risk_assessment": { "overall_risk_score": 9.8, "likelihood": "...", "priority": "P0", ... },
      "recommendations": [{ "horizon": "immediate", "category": "patch", "action": "...", "rationale": "..." }],
      "detection_rules": ["..."],
      "analysis_source": "llm"
    }
  ],
  "metadata": { "generated_at": "...", "model_name": "...", "llm_analysed": 8, "degraded": false }
}
```

`analysis_source` and `metadata.degraded` let a consumer tell AI analysis from
heuristic fallback at both the finding and run level.

---

## Tests

```bash
pytest
```

98 tests, all offline — LLM behaviour is exercised through fake providers and
the Red Agent through a stub, so the suite needs no credentials and makes no
network calls. Coverage includes schema-drift parsing, severity coercion, JSON
repair of messy model replies, retry-then-succeed and retry-then-fall-back
paths, Markdown structure, the CLI end to end, and every API route including
CORS preflight and the Red Agent handoff.

---

## Requirements

Python 3.12+ · `modal` · `python-dotenv` · `pydantic` · `orjson` · `rich` ·
`loguru` · `typing_extensions` · `starlette` + `uvicorn` (HTTP API)
