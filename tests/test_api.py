"""HTTP API tests.

Every test runs offline: analyses use the heuristic engine and the Red Agent is
replaced by a stub, so the suite needs no credentials and makes no outbound
calls. Jobs execute on a worker thread, so helpers poll for terminal state.
"""

from __future__ import annotations

import json
import time

import pytest
from starlette.testclient import TestClient

from api.jobs import AnalysisRequest, JobStore, RequestError

from tests.conftest import SAMPLE_REPORT_PATH

OFFLINE = {"offline": True}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient whose job store writes artefacts into ``tmp_path``."""
    import api.server as server

    store = JobStore(max_workers=2, artifact_root=tmp_path / "artifacts")
    monkeypatch.setattr(server, "_store", store)
    with TestClient(server.app) as test_client:
        yield test_client


@pytest.fixture
def sample_document():
    return json.loads(SAMPLE_REPORT_PATH.read_text(encoding="utf-8"))


def wait_for(client, job_id, *, timeout=60.0):
    """Poll a job until it reaches a terminal state, then return the record."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/v1/analyses/{job_id}").json()
        if job["status"] in {"completed", "error"}:
            return job
        time.sleep(0.05)
    pytest.fail(f"job {job_id} did not finish within {timeout}s")


def submit(client, body) -> str:
    response = client.post("/api/v1/analyses", json=body)
    assert response.status_code == 202, response.text
    return response.json()["job_id"]


# --- discovery endpoints ---------------------------------------------------


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["service"] == "blueagent-api"
    assert "llm_configured" in body


def test_config_describes_the_request_contract(client):
    body = client.get("/api/v1/config").json()
    assert "report" in body["sources"]
    assert "red_agent_job_id" in body["sources"]
    assert "offline" in body["options"]
    assert "critical" in body["severities"]


# --- happy paths -----------------------------------------------------------


def test_inline_envelope_analysis(client, sample_document):
    job_id = submit(client, {"report": sample_document, "options": OFFLINE})
    job = wait_for(client, job_id)

    assert job["status"] == "completed"
    assert job["overall_risk"] == "critical"
    assert job["target"] == "demo.testfire.net"
    assert job["progress"] == {"analysed": 8, "total": 8, "percent": 100}
    assert job["summary"]["total_findings"] == 8
    # Polling must stay cheap: the full findings array is not in the status body.
    assert "analysis" not in job


def test_bare_report_body_is_accepted(client, sample_document):
    """Posting the Red Agent report directly, with no envelope, must work."""
    job_id = submit(client, sample_document)
    job = wait_for(client, job_id)
    assert job["status"] == "completed"
    assert job["source"]["kind"] == "inline"


def test_report_endpoint_returns_the_full_document(client, sample_document):
    job_id = submit(client, {"report": sample_document, "options": OFFLINE})
    wait_for(client, job_id)

    document = client.get(f"/api/v1/analyses/{job_id}/report").json()
    assert {"summary", "overall_risk", "findings", "executive_summary"} <= document.keys()
    assert len(document["findings"]) == 8
    assert document["findings"][0]["mitre_attack"]["techniques"]


def test_markdown_endpoint_serves_text_markdown(client, sample_document):
    job_id = submit(client, {"report": sample_document, "options": OFFLINE})
    wait_for(client, job_id)

    response = client.get(f"/api/v1/analyses/{job_id}/report.md")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.text.startswith("# Blue Team Security Analysis")
    assert "content-disposition" not in response.headers

    download = client.get(f"/api/v1/analyses/{job_id}/report.md?download=1")
    assert "attachment" in download.headers["content-disposition"]


def test_report_path_source(client, tmp_path, sample_document):
    path = tmp_path / "red.json"
    path.write_text(json.dumps(sample_document), encoding="utf-8")

    job_id = submit(client, {"report_path": str(path), "options": OFFLINE})
    job = wait_for(client, job_id)
    assert job["status"] == "completed"
    assert job["source"] == {"kind": "path", "ref": str(path)}


def test_listing_and_deletion(client, sample_document):
    job_id = submit(client, {"report": sample_document, "options": OFFLINE})
    wait_for(client, job_id)

    listing = client.get("/api/v1/analyses?limit=10").json()
    assert listing["count"] >= 1
    assert any(job["job_id"] == job_id for job in listing["analyses"])

    assert client.delete(f"/api/v1/analyses/{job_id}").status_code == 204
    assert client.get(f"/api/v1/analyses/{job_id}").status_code == 404
    assert client.delete(f"/api/v1/analyses/{job_id}").status_code == 404


def test_empty_report_completes_rather_than_erroring(client):
    job_id = submit(client, {"report": {"findings": []}, "options": OFFLINE})
    job = wait_for(client, job_id)
    assert job["status"] == "completed"
    assert job["progress"]["total"] == 0


# --- Red Agent handoff -----------------------------------------------------


def test_red_agent_handoff(client, sample_document, monkeypatch):
    """The one-click path: Blue fetches the report from Red by job id."""
    import api.jobs as jobs

    captured = {}

    def fake_fetch(job_id, base_url=None, *, timeout=30.0):
        captured["job_id"] = job_id
        captured["base_url"] = base_url
        return sample_document

    monkeypatch.setattr(jobs, "fetch_red_agent_report", fake_fetch)

    job_id = submit(
        client,
        {
            "red_agent_job_id": "red-123",
            "red_agent_url": "http://127.0.0.1:8000",
            "options": OFFLINE,
        },
    )
    job = wait_for(client, job_id)

    assert captured == {"job_id": "red-123", "base_url": "http://127.0.0.1:8000"}
    assert job["status"] == "completed"
    assert job["source"] == {"kind": "red_agent_job", "ref": "red-123"}


def test_unreachable_red_agent_is_reported_on_the_job(client):
    """Port 9 is the discard service — a connection there always fails fast."""
    job_id = submit(
        client,
        {"red_agent_job_id": "red-123", "red_agent_url": "http://127.0.0.1:9", "options": OFFLINE},
    )
    job = wait_for(client, job_id)

    assert job["status"] == "error"
    assert job["error"]["type"] == "RequestError"
    assert "cannot reach the Red Agent API" in job["error"]["message"]


# --- validation ------------------------------------------------------------


def test_malformed_json_is_rejected(client):
    response = client.post(
        "/api/v1/analyses", content=b"{oops", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert "valid JSON" in response.json()["error"]


@pytest.mark.parametrize(
    "body",
    [
        {"reportt": {}},
        {"options": {"offline": True}},
        {"report": {"findings": []}, "options": {"api_key": "leak"}},
        {"report": {"findings": []}, "report_path": "/tmp/x"},
        {"report": "not an object"},
    ],
)
def test_invalid_bodies_are_rejected_with_422(client, body):
    assert client.post("/api/v1/analyses", json=body).status_code == 422


def test_secrets_cannot_be_overridden_per_request():
    """A caller must never be able to redirect the agent at another endpoint."""
    request = AnalysisRequest(
        report={"findings": []}, options={"concurrency": 2, "offline": True}
    )
    overrides = request.settings_overrides()
    assert "llm_base_url" not in overrides
    assert "llm_api_key" not in overrides
    assert overrides["concurrency"] == 2

    with pytest.raises(RequestError):
        AnalysisRequest.from_body({"report": {}, "options": {"llm_base_url": "http://evil"}})


def test_unknown_job_returns_404(client):
    assert client.get("/api/v1/analyses/nope").status_code == 404
    assert client.get("/api/v1/analyses/nope/report").status_code == 404
    assert client.get("/api/v1/analyses/nope/report.md").status_code == 404


def test_report_before_completion_returns_409(client, sample_document, monkeypatch):
    import api.server as server

    job = server._store.create(AnalysisRequest(report=sample_document, options=OFFLINE))
    server._store._update(job["job_id"], status="running")

    response = client.get(f"/api/v1/analyses/{job['job_id']}/report")
    assert response.status_code == 409
    assert "not ready" in response.json()["error"]


def test_bad_limit_is_rejected(client):
    assert client.get("/api/v1/analyses?limit=abc").status_code == 400


# --- chat ------------------------------------------------------------------


class FakeChatService:
    """Stands in for ChatService so chat tests never need a live LLM."""

    last_call = None

    def __init__(self, settings, provider=None):
        self.settings = settings

    @property
    def available(self):
        return True

    def reply(self, document, message, history=()):
        FakeChatService.last_call = {
            "document": document,
            "message": message,
            "history": list(history),
        }
        return "The SQL injection finding is the top priority."


@pytest.fixture
def completed_job(client, sample_document):
    job_id = submit(client, {"report": sample_document, "options": OFFLINE})
    wait_for(client, job_id)
    return job_id


def test_chat_returns_a_grounded_reply(client, completed_job, monkeypatch):
    import api.server as server

    monkeypatch.setattr(server, "ChatService", FakeChatService)
    history = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]

    response = client.post(
        f"/api/v1/analyses/{completed_job}/chat",
        json={"message": "What should we fix first?", "history": history},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["reply"] == "The SQL injection finding is the top priority."
    # The returned history is ready to send back verbatim on the next turn.
    assert body["history"] == history + [
        {"role": "user", "content": "What should we fix first?"},
        {"role": "assistant", "content": body["reply"]},
    ]
    # The service was handed the full analysis document as grounding.
    assert FakeChatService.last_call["document"]["target"] == "demo.testfire.net"
    assert FakeChatService.last_call["history"] == history


def test_chat_link_is_advertised_on_the_job(client, completed_job):
    job = client.get(f"/api/v1/analyses/{completed_job}").json()
    assert job["links"]["chat"] == f"/api/v1/analyses/{completed_job}/chat"


def test_chat_on_unknown_job_returns_404(client):
    assert client.post("/api/v1/analyses/nope/chat", json={"message": "hi"}).status_code == 404


def test_chat_before_completion_returns_409(client, sample_document):
    import api.server as server

    job = server._store.create(AnalysisRequest(report=sample_document, options=OFFLINE))
    server._store._update(job["job_id"], status="running")

    response = client.post(f"/api/v1/analyses/{job['job_id']}/chat", json={"message": "hi"})
    assert response.status_code == 409
    assert "chat unavailable" in response.json()["error"]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"message": ""},
        {"message": "   "},
        {"message": 42},
        {"message": "hi", "history": "not a list"},
        {"message": "hi", "history": [{"role": "system", "content": "x"}]},
        {"message": "hi", "history": [{"role": "user"}]},
        {"message": "hi", "unknown_field": 1},
    ],
)
def test_invalid_chat_bodies_are_rejected_with_422(client, completed_job, body):
    response = client.post(f"/api/v1/analyses/{completed_job}/chat", json=body)
    assert response.status_code == 422, response.text


def test_chat_without_a_live_llm_returns_503(client, completed_job, monkeypatch):
    import api.server as server

    class OfflineChat:
        def __init__(self, settings, provider=None):
            pass

        @property
        def available(self):
            return False

    monkeypatch.setattr(server, "ChatService", OfflineChat)
    response = client.post(f"/api/v1/analyses/{completed_job}/chat", json={"message": "hi"})
    assert response.status_code == 503
    assert "live LLM" in response.json()["error"]


# --- CORS ------------------------------------------------------------------


def test_preflight_allows_the_frontend_origin(client):
    response = client.options(
        "/api/v1/analyses",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "POST" in response.headers["access-control-allow-methods"]


def test_actual_request_carries_cors_header(client, sample_document):
    response = client.post(
        "/api/v1/analyses",
        json={"report": sample_document, "options": OFFLINE},
        headers={"Origin": "http://localhost:3000"},
    )
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
