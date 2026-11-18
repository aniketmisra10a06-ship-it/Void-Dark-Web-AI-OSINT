import json
import os
import stat

import pytest
from fastapi.testclient import TestClient

from app.llm import LLMError, SwitchableLLM
from app.llm_store import LLMStore, initial_llm_config
from app.main import create_app
from app.providers import LLMConfig, build_config
from tests.conftest import FakeLLM

KEY = "sk-test-SECRETKEY1234567890"
OTHER = "sk-other-ZZZZZZZZZZZZZZZZZZ"


class FailingLLM(FakeLLM):
    async def complete(self, messages, **options):
        raise LLMError("provider says: quota exceeded")


@pytest.fixture
def build(settings, make_services, tmp_path):
    """Create (client, svc) with a real SwitchableLLM backed by fake clients."""
    created: list[TestClient] = []

    def _build(config: LLMConfig | None = None, factory=None, **overrides):
        llm = SwitchableLLM(
            config or LLMConfig(provider="openai"),
            settings,
            factory=factory or (lambda c, s: FakeLLM()),
        )
        svc = make_services(llm=llm, **overrides)
        svc.llm_store = LLMStore(tmp_path / "llm.json")
        client = TestClient(create_app(svc.settings, svc))
        client.__enter__()
        created.append(client)
        return client, svc

    yield _build
    for c in created:
        c.__exit__(None, None, None)


def put(client, **body):
    return client.put("/api/settings", json=body)


def test_get_settings_lists_presets_and_never_returns_the_key(build):
    client, _ = build(build_config("openai", "m", api_key=KEY))
    resp = client.get("/api/settings")
    assert KEY not in resp.text and "SECRETKEY" not in resp.text
    data = resp.json()
    assert data["current"]["has_key"] is True and data["current"]["key_hint"] == "…7890"
    assert data["current"]["configured"] is True and data["current"]["can_edit"] is True
    ids = [p["id"] for p in data["providers"]]
    assert {"openai", "anthropic", "gemini", "openrouter", "custom", "ollama"} <= set(ids)
    anthropic = next(p for p in data["providers"] if p["id"] == "anthropic")
    assert anthropic["default_model"] == "claude-sonnet-5-5"


def test_put_applies_immediately_persists_and_survives_restart(build, settings, tmp_path):
    client, svc = build()
    assert client.get("/api/status").json()["llm_state"] == "needs_setup"

    resp = put(client, provider="anthropic", model="claude-x", api_key=KEY)
    assert resp.status_code == 200 and KEY not in resp.text
    body = resp.json()
    assert body["configured"] and body["provider"] == "anthropic" and body["source"] == "saved"

    status = client.get("/api/status").json()
    assert status["llm_state"] == "ready" and status["label"] == "Anthropic · claude-x"

    path = tmp_path / "llm.json"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert json.loads(path.read_text())["api_key"] == KEY  # stored server-side only

    cfg, source = initial_llm_config(settings, LLMStore(path))  # simulated restart
    assert source == "saved" and cfg.api_key == KEY and cfg.provider == "anthropic"

    # chat now works through the freshly configured provider
    chat = client.post("/api/chat", json={"message": "tell me about acme", "search": False})
    assert "Hello" in chat.text and "model" in chat.text


def test_saved_key_is_kept_only_when_provider_and_url_are_unchanged(build):
    client, svc = build(build_config("openai", "m", api_key=KEY))
    assert put(client, provider="openai", model="new-model").json()["has_key"] is True
    assert svc.llm.config.api_key == KEY and svc.llm.config.model == "new-model"

    # switching provider must NOT reuse a key that was issued for a different service
    moved = put(client, provider="gemini", model="g").json()
    assert moved["has_key"] is False and svc.llm.config.api_key == ""

    client, svc = build(build_config("custom", "m", "https://one.example.com/v1", KEY))
    assert (
        put(
            client, provider="custom", model="m", base_url="https://attacker.example.com/v1"
        ).json()["has_key"]
        is False
    )


def test_new_key_replaces_and_clear_key_removes(build):
    client, svc = build(build_config("openai", "m", api_key=KEY))
    assert put(client, provider="openai", model="m", api_key=OTHER).json()["key_hint"] == "…ZZZZ"
    assert svc.llm.config.api_key == OTHER
    cleared = put(client, provider="openai", model="m", clear_key=True).json()
    assert cleared["has_key"] is False and cleared["configured"] is False


@pytest.mark.parametrize(
    ("body", "msg"),
    [
        ({"provider": "evil", "model": "m"}, "Unknown provider"),
        ({"provider": "openai", "model": ""}, "model name"),
        ({"provider": "custom", "model": "m", "base_url": "http://api.example.com/v1"}, "https://"),
        ({"provider": "custom", "model": "m", "base_url": "http://169.254.169.254"}, "not allowed"),
        ({"provider": "openai", "model": "m", "api_key": "has a space"}, "API key"),
        ({"provider": "openai", "model": "bad model!"}, "invalid characters"),
    ],
)
def test_invalid_settings_are_rejected_and_not_applied(build, body, msg, tmp_path):
    client, svc = build()
    before = svc.llm.config
    resp = put(client, **body)
    assert resp.status_code == 422 and msg in resp.json()["detail"]
    assert svc.llm.config == before and not (tmp_path / "llm.json").exists()


def test_failure_to_persist_leaves_running_config_untouched(build):
    class BrokenStore:
        def save(self, cfg):
            raise OSError("read-only")

    client, svc = build()
    svc.llm_store = BrokenStore()
    resp = put(client, provider="openai", model="m", api_key=KEY)
    assert resp.status_code == 500 and "writable" in resp.json()["detail"]
    assert svc.llm.config.api_key == ""


def test_settings_can_be_locked_by_the_operator(build):
    client, svc = build(build_config("openai", "m", api_key=KEY), allow_ui_config=False)
    assert client.get("/api/settings").json()["current"]["can_edit"] is False
    assert put(client, provider="openai", model="x").status_code == 403
    assert client.post("/api/settings/test").status_code == 403
    assert svc.llm.config.model == "m"


def test_connection_test_reports_success_and_provider_errors(build):
    client, _ = build(build_config("openai", "m", api_key=KEY))
    assert client.post("/api/settings/test").json() == {
        "ok": True,
        "message": "Connected: OpenAI · m answered.",
    }

    client, _ = build(build_config("openai", "m", api_key=KEY), factory=lambda c, s: FailingLLM())
    result = client.post("/api/settings/test").json()
    assert result["ok"] is False and "quota exceeded" in result["message"]

    client, _ = build()  # nothing configured yet
    result = client.post("/api/settings/test").json()
    assert result["ok"] is False and "API key" in result["message"]


def test_unconfigured_chat_explains_what_to_do(build):
    client, _ = build()
    events = client.post("/api/chat", json={"message": "tell me about acme", "search": False}).text
    assert "event: error" in events and "add your API key" in events


# ------------------------------------------------------------------------------ access guard


def test_unknown_host_header_is_rejected_without_token(build):
    client, _ = build()
    for path in ("/api/status", "/api/settings"):
        assert client.get(path, headers={"host": "evil.example"}).status_code == 403
    assert (
        client.post(
            "/api/chat", json={"message": "x"}, headers={"host": "evil.example"}
        ).status_code
        == 403
    )
    assert client.get("/healthz", headers={"host": "evil.example"}).status_code == 200


def test_token_replaces_the_host_check(build):
    client, _ = build(access_token="s3cret")
    auth = {"Authorization": "Bearer s3cret", "host": "dw.example.com"}
    assert client.get("/api/settings", headers=auth).status_code == 200
    assert client.get("/api/settings", headers={"host": "dw.example.com"}).status_code == 401


def test_cross_site_requests_cannot_change_settings(build):
    client, svc = build(build_config("openai", "m", api_key=KEY))
    evil = {"origin": "http://evil.example"}
    resp = client.put(
        "/api/settings",
        json={"provider": "custom", "model": "m", "base_url": "https://attacker.example.com/v1"},
        headers=evil,
    )
    assert resp.status_code == 403
    assert (
        client.put(
            "/api/settings", json={"provider": "openai", "model": "m"}, headers={"origin": "null"}
        ).status_code
        == 403
    )
    assert client.post("/api/chat", json={"message": "x"}, headers=evil).status_code == 403
    assert svc.llm.config.provider == "openai" and svc.llm.config.api_key == KEY
    same = {"origin": "http://testserver"}
    assert (
        client.put(
            "/api/settings", json={"provider": "openai", "model": "m2"}, headers=same
        ).status_code
        == 200
    )


def test_fake_llm_backends_report_501_for_settings(settings, make_services):
    svc = make_services()  # plain FakeLLM, not switchable
    with TestClient(create_app(svc.settings, svc)) as c:
        assert c.get("/api/settings").status_code == 501
        assert c.get("/api/status").json()["llm_state"] == "ready"
