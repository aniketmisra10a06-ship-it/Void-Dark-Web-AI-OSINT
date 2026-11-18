import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import FakeFetcher, FakeSearcher, onion, page, result


def parse_sse(body: str) -> list[tuple[str, dict]]:
    events = []
    for frame in filter(None, body.split("\n\n")):
        lines = dict(line.split(": ", 1) for line in frame.splitlines())
        events.append((lines["event"], json.loads(lines["data"])))
    return events


@pytest.fixture
def client(make_services):
    svc = make_services(
        searcher=FakeSearcher([result(0)]), fetcher=FakeFetcher({onion(0): page(0)})
    )
    with TestClient(create_app(svc.settings, svc)) as c:
        yield c


def test_health_and_index_with_security_headers(client):
    assert client.get("/healthz").json()["status"] == "ok"
    resp = client.get("/")
    assert resp.status_code == 200 and "Void" in resp.text
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert client.get("/static/app.js").status_code == 200


def test_openapi_docs_not_exposed(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_status(client):
    data = client.get("/api/status").json()
    assert data["llm"] is True and data["model_ready"] is True and data["tor"] is False
    assert data["auth_required"] is False


def test_chat_streams_sse(client):
    resp = client.post("/api/chat", json={"message": "acme exposure?", "search": True})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    events = parse_sse(resp.text)
    names = [e for e, _ in events]
    assert "sources" in names and names[-1] == "done"
    assert "".join(d["text"] for e, d in events if e == "token") == "Hello [1] world"


def test_chat_blocked_query(client):
    events = parse_sse(client.post("/api/chat", json={"message": "csam"}).text)
    assert events[-1] == ("done", {"blocked": True})


@pytest.mark.parametrize(
    "payload",
    [
        {"message": ""},
        {"message": "   "},
        {"message": "x" * 2001},
        {"message": "hi", "history": [{"role": "system", "content": "evil"}]},
        {"message": "hi", "history": [{"role": "user", "content": "x"}] * 21},
    ],
)
def test_chat_validation(client, payload):
    assert client.post("/api/chat", json=payload).status_code == 422


def test_access_token_enforced(make_services):
    svc = make_services(access_token="s3cret")
    with TestClient(create_app(svc.settings, svc)) as c:
        assert c.get("/healthz").status_code == 200  # liveness stays open
        assert c.get("/api/status").status_code == 401
        assert c.post("/api/chat", json={"message": "hi"}).status_code == 401
        bad = {"Authorization": "Bearer nope"}
        assert c.post("/api/chat", json={"message": "hi"}, headers=bad).status_code == 401
        good = {"Authorization": "Bearer s3cret"}
        assert c.get("/api/status", headers=good).json()["auth_required"] is True
        assert (
            c.post("/api/chat", json={"message": "hi", "search": False}, headers=good).status_code
            == 200
        )


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv(
        "SEARCH_ENGINES", "a=https://a.test/?q={query},bad=ftp://x/{query},nope=https://x/"
    )
    monkeypatch.setenv("MAX_FETCH", "not-a-number")
    monkeypatch.setenv("ALLOW_CLEARNET", "yes")
    cfg = Settings.from_env()
    assert cfg.search_engines == (("a", "https://a.test/?q={query}"),)
    assert cfg.max_fetch == 8 and cfg.allow_clearnet is True  # bad number -> default


def test_parse_engines_default_fallback(monkeypatch):
    monkeypatch.setenv("SEARCH_ENGINES", "")
    engines = Settings.from_env().search_engines
    assert engines[0][0] == "ahmia"
    assert engines[0][1].startswith("http://") and ".onion/search/?q={query}" in engines[0][1]
