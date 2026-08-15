# Blue Agent API — Integration Guide

HTTP API for the Blue Team Analysis Agent, written for whoever is wiring up the
website.

| Service | Port | Base URL |
| --- | --- | --- |
| Frontend | 3000 | `http://localhost:3000` |
| Red Agent API | 8000 | `http://localhost:8000` |
| **Blue Agent API** | **8001** | **`http://localhost:8001`** |

The Blue Agent deliberately mirrors the Red Agent's API conventions — Starlette,
an `/api/v1` prefix, background jobs the site polls — so both integrate the same
way.

---

## Starting the service

```bash
cd /home/sumit/Desktop/BlueAgent
source .venv/bin/activate
python serve_api.py
```

```
BlueAgent API on http://0.0.0.0:8001
  analysis backend : modal / qwen3-32b
  health           : http://0.0.0.0:8001/health
```

Change the port with `BLUE_API_PORT=9001 python serve_api.py`. Add
`BLUE_API_RELOAD=true` during frontend development for auto-reload.

If `analysis backend` says *heuristic engine*, no LLM endpoint is configured —
analyses will still succeed, using deterministic rules. See
[Degraded mode](#degraded-mode).

---

## The shape of the integration

An analysis takes seconds to minutes — one LLM call per finding against an
endpoint that cold-starts — so it does **not** fit in a request/response cycle.
The flow is submit → poll → fetch:

```
POST /api/v1/analyses          -> 202 { job_id, poll }
GET  /api/v1/analyses/{job_id} -> { status, progress }   ← poll every ~2s
GET  /api/v1/analyses/{job_id}/report                     ← once completed
```

Poll `/{job_id}` rather than `/report`: the status response omits the findings
array, so polling stays cheap. Fetch the full document once.

---

## Endpoints

### `GET /health`

Liveness plus which backend is live. Use it for a status dot in the UI.

```json
{
  "status": "ok",
  "service": "blueagent-api",
  "version": "1.0.0",
  "llm_configured": true,
  "provider": "modal",
  "model": "qwen3-32b"
}
```

### `GET /api/v1/config`

Capabilities and the request contract — render your form from this rather than
hardcoding option names.

```json
{
  "llm": { "configured": true, "provider": "modal", "model": "qwen3-32b",
           "degrades_to_heuristics": true, "note": "..." },
  "sources": { "report": "...", "red_agent_job_id": "...", "report_path": "..." },
  "options": ["allow_offline_fallback", "concurrency", "llm_provider",
              "max_tokens", "model_name", "offline", "temperature"],
  "severities": ["critical", "high", "medium", "low", "info", "unknown"],
  "statuses": ["queued", "running", "completed", "error"]
}
```

### `POST /api/v1/analyses`

Queue an analysis. Returns **202** immediately.

Supply **exactly one** source:

| Field | Meaning |
| --- | --- |
| `report` | The Red Agent report document, inline |
| `red_agent_job_id` | A Red Agent job ID — the Blue Agent fetches the report itself |
| `report_path` | Path to a report file **on the Blue Agent host** |

```jsonc
{
  "report": { "engagement_id": "...", "findings": [ ... ] },
  "options": { "offline": false, "concurrency": 4 }
}
```

You can also POST a bare Red Agent report with no envelope — if the body looks
like a report, it is treated as one. That makes the simplest possible
integration work:

```bash
curl -X POST http://localhost:8001/api/v1/analyses \
     -H 'Content-Type: application/json' \
     -d @redagent-report.json
```

Response:

```json
{
  "job_id": "a27f2e26f8cb4c4dae35484d98bb6d05",
  "status": "queued",
  "created_at": "2026-08-06T16:37:59+00:00",
  "source": { "kind": "inline", "ref": "request body" },
  "poll": "/api/v1/analyses/a27f2e26f8cb4c4dae35484d98bb6d05",
  "links": { "self": "...", "report": "...", "markdown": "..." }
}
```

**Options** (all optional):

| Option | Type | Default | Effect |
| --- | --- | --- | --- |
| `offline` | bool | `false` | Skip the LLM; use the heuristic engine. Fast and free — good for a demo fallback |
| `concurrency` | int | `4` | Findings analysed in parallel |
| `temperature` | float | `0.2` | Sampling temperature |
| `max_tokens` | int | `4096` | Completion budget per call |
| `model_name` | string | env | Request a different model |
| `llm_provider` | string | env | `modal`, `openai`, `vllm`, `ollama`, `azure`, `offline` |
| `allow_offline_fallback` | bool | `true` | When false, LLM failure fails the job instead of degrading |

The endpoint URL and API key are **not** settable per request. A browser client
can never redirect the agent at another inference endpoint or exfiltrate the
key.

### `GET /api/v1/analyses/{job_id}`

Status, progress and — once finished — the summary block. This is your polling
endpoint.

```jsonc
{
  "job_id": "a27f2e26...",
  "status": "running",                  // queued | running | completed | error
  "created_at": "...", "started_at": "...", "finished_at": null,
  "source": { "kind": "inline", "ref": "request body" },
  "progress": { "analysed": 3, "total": 8, "percent": 38 },
  "engagement_id": "eng-web-black_box-4f2a91cd",
  "target": "demo.testfire.net",
  "mode": "black_box",
  "overall_risk": "critical",           // present once completed
  "summary": { ... },                   // present once completed
  "metadata": { ... },
  "artifacts": { "json": "...", "markdown": "..." },
  "links": { ... },
  "error": null
}
```

`progress` is live — drive a progress bar from `percent`. `total` is `null`
until the report has been parsed and the finding count is known.

### `GET /api/v1/analyses/{job_id}/report`

The full `blue_analysis.json`. **409** if the job has not completed, with the
current status and progress in the body.

### `GET /api/v1/analyses/{job_id}/report.md`

The rendered Markdown report as `text/markdown`. Add `?download=1` for a
`Content-Disposition: attachment` header, which gives you a one-line download
button.

### `POST /api/v1/analyses/{job_id}/chat`

Ask a question about a **completed** analysis — this powers the chat panel next
to the rendered report. The reply is grounded in that job's
`blue_analysis.json`: the model is handed the summaries and every finding as
context, answers in Markdown, and is instructed to say so rather than invent
when a question falls outside the report.

The endpoint is **stateless**: your frontend keeps the transcript and sends it
back as `history` on every turn. The response returns the updated `history`
(including this turn), ready to store verbatim for the next request.

Request:

```json
{
  "message": "Which finding should we fix first, and why?",
  "history": [
    { "role": "user", "content": "summarise the report" },
    { "role": "assistant", "content": "The assessment found 8 issues..." }
  ]
}
```

`history` is optional (omit it on the first turn). Only `user` and `assistant`
roles are accepted; the last 20 turns are kept. `message` is capped at 8,000
characters.

Response `200`:

```json
{
  "job_id": "9a1167392be64797912abf6e13c2b1c7",
  "reply": "Start with **SQL Injection in login form** (find-a41c9e2b7d10)...",
  "model": "qwen3-32b",
  "history": [
    { "role": "user", "content": "summarise the report" },
    { "role": "assistant", "content": "The assessment found 8 issues..." },
    { "role": "user", "content": "Which finding should we fix first, and why?" },
    { "role": "assistant", "content": "Start with **SQL Injection in login form**..." }
  ]
}
```

Render `reply` as Markdown. Errors:

| Status | Meaning |
| --- | --- |
| `404` | unknown `job_id` |
| `409` | analysis not completed yet (body carries `status` + `progress`) |
| `422` | bad body: empty message, bad `history` shape, unknown fields |
| `502` | the LLM could not be reached after retries |
| `503` | no LLM configured — chat has **no heuristic fallback**, unlike analysis |

Minimal frontend wiring:

```js
const BLUE_API = "http://localhost:8001";
let history = [];

export async function askReport(jobId, message) {
  const res = await fetch(`${BLUE_API}/api/v1/analyses/${jobId}/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, history }),
  });
  if (!res.ok) throw new Error((await res.json()).error);
  const body = await res.json();
  history = body.history;         // send back verbatim on the next turn
  return body.reply;              // Markdown — render with your MD component
}
```

Like analysis, the first turn after an idle period can be slow (the Modal
endpoint scales to zero), so show a typing indicator and keep the request
timeout generous. Whether chat is available is advertised in
`GET /api/v1/config` under `chat.available`, and each job links its own chat
endpoint at `links.chat`.

### `GET /api/v1/analyses?limit=50`

Recent jobs, newest first, without their findings arrays — for a history table.

### `DELETE /api/v1/analyses/{job_id}`

Forget a job and delete its artefacts. **204** on success.

---

## The one-click Red Agent handoff

The best flow for the website: the Red Agent scan finishes, and you hand the
Blue Agent the same job ID. The report never transits the browser.

```js
// 1. Red Agent scan (port 8000)
const scan = await fetch("http://localhost:8000/api/v1/scans", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ mode: "black_box", target: "demo.testfire.net" }),
}).then(r => r.json());

// 2. ...poll until the Red Agent scan completes...

// 3. Blue Agent analysis (port 8001) — pass the Red job id straight through
const analysis = await fetch("http://localhost:8001/api/v1/analyses", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    red_agent_job_id: scan.job_id,
    red_agent_url: "http://localhost:8000",
  }),
}).then(r => r.json());
```

`red_agent_url` is optional; it defaults to the `RED_AGENT_URL` environment
variable, then `http://127.0.0.1:8000`. Server-to-server, so it must be an
address the *Blue Agent host* can reach — not a browser-visible one.

If the Red Agent is unreachable or the report is not ready, the job lands in
`status: "error"` with a diagnostic message rather than hanging.

---

## Frontend example

A complete submit-poll-render client:

```js
const BLUE_API = "http://localhost:8001";

export async function analyzeReport(report, { onProgress } = {}) {
  const { job_id } = await fetch(`${BLUE_API}/api/v1/analyses`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ report }),
  }).then(handle);

  while (true) {
    const job = await fetch(`${BLUE_API}/api/v1/analyses/${job_id}`).then(handle);
    onProgress?.(job.progress);

    if (job.status === "completed") {
      const analysis = await fetch(
        `${BLUE_API}/api/v1/analyses/${job_id}/report`
      ).then(handle);
      return { job, analysis };
    }
    if (job.status === "error") {
      throw new Error(job.error?.message ?? "analysis failed");
    }
    await new Promise(r => setTimeout(r, 2000));
  }
}

async function handle(response) {
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error ?? `HTTP ${response.status}`);
  }
  return response.json();
}
```

Use it like:

```js
const { analysis } = await analyzeReport(redAgentReport, {
  onProgress: p => setProgress(p.percent),
});

console.log(analysis.overall_risk);                  // "critical"
console.log(analysis.executive_summary.top_risks);   // string[]
console.log(analysis.findings[0].mitre_attack);      // { tactics, techniques }
```

Poll every 2 seconds or so. A cold Modal container can take a couple of minutes
on the first request, so don't set a client timeout below ~5 minutes — or show
the progress bar and let the user wait.

---

## Response shapes worth rendering

`GET /report` returns the full document. The parts most worth building UI around:

```jsonc
{
  "overall_risk": "critical",              // badge colour
  "summary": {
    "total_findings": 8,
    "severity_counts": { "critical": 1, "high": 2, "medium": 2, "low": 2, "info": 1 },
    "priority_counts": { "P0": 1, "P1": 2, "P2": 2, "P3": 3 },
    "max_risk_score": 10.0,
    "mean_risk_score": 5.6,
    "immediate_actions": 12,               // headline number
    "mitre_tactics_observed": ["Initial Access", "Credential Access"]
  },
  "executive_summary": {
    "overall_posture": "...",              // paragraph
    "top_risks": ["..."],
    "most_dangerous_findings": ["..."],
    "security_maturity": "...",
    "recommended_next_steps": ["..."],
    "business_narrative": "..."
  },
  "technical_summary": {
    "developer_guidance": "...",
    "infrastructure_recommendations": ["..."],
    "secure_coding_guidance": ["..."],
    "devsecops_improvements": ["..."],
    "architecture_improvements": ["..."]
  },
  "findings": [
    {
      "id": "find-a41c9e2b7d10",
      "title": "SQL Injection in login form (uid parameter)",
      "severity": "critical",              // critical|high|medium|low|info|unknown
      "asset": "https://demo.testfire.net/bank/login.jsp",
      "analysis": "...",                   // multi-paragraph prose
      "root_cause":      { "primary": "...", "categories": ["..."], "explanation": "..." },
      "business_impact": { "confidentiality": "...", "integrity": "...", "...": "...",
                           "narrative": "..." },
      "mitre_attack":    { "tactics": ["Initial Access"],
                           "techniques": [{ "id": "T1190", "name": "...", "tactic": "...",
                                            "rationale": "..." }],
                           "notes": "" },
      "risk_assessment": { "overall_risk_score": 9.8, "likelihood": "Very High",
                           "impact": "Critical", "priority": "P0",
                           "risk_category": "critical", "reasoning": "..." },
      "recommendations": [{ "horizon": "immediate",   // immediate|short_term|long_term
                            "category": "patch",
                            "action": "...", "rationale": "...", "effort": "Low" }],
      "detection_rules": ["..."],
      "analysis_source": "llm"             // "llm" or "heuristic" — see below
    }
  ],
  "metadata": {
    "generated_at": "...", "model_name": "qwen3-32b",
    "findings_analysed": 8, "llm_analysed": 8, "heuristic_analysed": 0,
    "degraded": false
  }
}
```

Findings arrive **sorted worst-first**, so render them in order.

`mitre_attack.techniques` may be empty with an explanatory `notes` string — that
is a valid answer, not a failure. Render the note.

---

## Degraded mode

If the Modal endpoint is unreachable or every retry times out, the run falls
back to a deterministic heuristic engine rather than failing. The job still
completes; the response says so:

- `metadata.degraded: true` at the run level
- `metadata.heuristic_analysed: N` — how many findings fell back
- `finding.analysis_source: "heuristic"` per finding

Surface this in the UI. A badge like *"Rule-based analysis — AI unavailable"* is
honest and keeps a demo alive; silently presenting heuristic output as AI
analysis is not.

To force it (fast, free, deterministic — useful for demos and CI):

```json
{ "report": { ... }, "options": { "offline": true } }
```

To opt out entirely and have LLM failure fail the job:

```json
{ "report": { ... }, "options": { "allow_offline_fallback": false } }
```

---

## Errors

| Status | Meaning |
| --- | --- |
| 202 | Accepted; poll the `poll` URL |
| 400 | Malformed JSON body, or a bad query parameter |
| 404 | Unknown `job_id`, or `report_path` not found on the server |
| 409 | Report requested before the job completed |
| 422 | Valid JSON, invalid request: no source, two sources, unknown field or option |
| 500 | Server fault |
| 502 | The Red Agent API was unreachable |

All errors share one shape:

```json
{ "error": "human-readable message" }
```

Failures *during* analysis are not HTTP errors — the job was accepted, so they
appear on the job record:

```json
{
  "status": "error",
  "error": { "type": "RequestError",
             "message": "cannot reach the Red Agent API at http://127.0.0.1:8000: ..." }
}
```

Always check `status` when polling, not just the HTTP code.

---

## CORS

Any loopback origin is allowed by default, so `http://localhost:3000` works out
of the box — and keeps working if your dev server hops to 3001. Arbitrary remote
pages are still refused.

For a real deployment, pin the origins:

```bash
BLUE_API_CORS_ORIGINS=https://app.example.com,https://admin.example.com
```

Allowed methods are `GET, POST, DELETE, OPTIONS`; the only allowed custom
request header is `content-type`. If you add authentication in front of this,
extend `allow_headers` in `api/server.py` to match.

---

## Deployment notes

**No authentication is built in.** The API assumes it sits on a trusted network
or behind a gateway that handles authn/authz. Do not expose it to the internet
as-is.

**State is in memory.** Jobs and their results live in the process; a restart
loses history, though the artefact files under `output/api/<job_id>/` survive.
The oldest finished jobs are evicted past `BLUE_API_JOB_HISTORY` (default 200).
For multi-process or multi-host deployment, replace `JobStore` in `api/jobs.py`
with a Redis- or database-backed implementation — the interface is five methods.

**Concurrency.** `BLUE_API_WORKERS` (default 2) analyses run at once, each
fanning out internally to `concurrency` findings in parallel. So the default
worst case is 8 simultaneous requests at the LLM endpoint. Raise both together,
and watch what your Modal deployment can absorb.

**`report_path` reads the Blue Agent's filesystem.** It exists for the
server-to-server case. If untrusted users can reach this API, drop that branch
from `resolve_source` in `api/jobs.py`.

---

## Verifying the wiring

```bash
# 1. Is it up, and is the LLM configured?
curl -s http://localhost:8001/health | python -m json.tool

# 2. Submit the bundled sample, offline so it returns in a second
JOB=$(curl -s -X POST http://localhost:8001/api/v1/analyses \
        -H 'Content-Type: application/json' \
        -d '{"report_path":"input/sample_report.json","options":{"offline":true}}' \
      | python -c 'import sys,json; print(json.load(sys.stdin)["job_id"])')

# 3. Poll
curl -s http://localhost:8001/api/v1/analyses/$JOB | python -m json.tool

# 4. Fetch the analysis
curl -s http://localhost:8001/api/v1/analyses/$JOB/report | python -m json.tool

# 5. And the readable report
curl -s http://localhost:8001/api/v1/analyses/$JOB/report.md | head -40
```

The API test suite covers all of this without a running server:

```bash
pytest tests/test_api.py -v
```
