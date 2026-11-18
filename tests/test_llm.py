import json

import httpx
import pytest

from app.config import Settings
from app.llm import (
    AnthropicClient,
    LLMError,
    LLMNotConfigured,
    OllamaClient,
    OpenAIClient,
    SwitchableLLM,
    make_client,
    scrub,
    to_anthropic,
)
from app.providers import build_config

KEY = "sk-test-SECRETKEY1234567890"
MSGS = [
    {"role": "system", "content": "be brief"},
    {"role": "user", "content": "hello"},
]


def http(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def sse(*events: dict | str) -> httpx.Response:
    body = "".join(f"data: {e if isinstance(e, str) else json.dumps(e)}\n\n" for e in events)
    return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})


def openai(handler, **kw) -> OpenAIClient:
    cfg = build_config("openai", "test-model", api_key=KEY)
    return OpenAIClient(cfg, http=http(handler), **kw)


async def collect(agen) -> str:
    return "".join([c async for c in agen])


# ----------------------------------------------------------------------------- OpenAI-compatible


async def test_openai_streams_deltas_and_sends_bearer_key():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((str(req.url), req.headers["authorization"], json.loads(req.content)))
        return sse(
            {"choices": [{"delta": {"role": "assistant"}}]},
            {"choices": [{"delta": {"content": "Hel"}}]},
            {"choices": [{"delta": {"content": "lo"}}]},
            "[DONE]",
        )

    assert await collect(openai(handler).stream(MSGS)) == "Hello"
    url, auth, body = seen[0]
    assert url == "https://api.openai.com/v1/chat/completions"
    assert auth == f"Bearer {KEY}"
    assert body["model"] == "test-model" and body["stream"] is True and body["temperature"] == 0.2
    assert body["messages"] == MSGS


async def test_openai_complete():
    client = openai(
        lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "OK"}}]})
    )
    assert await client.complete(MSGS, temperature=0, max_tokens=8) == "OK"


async def test_strict_models_trigger_one_retry_then_remember():
    bodies = []

    def handler(req: httpx.Request) -> httpx.Response:
        payload = json.loads(req.content)
        bodies.append(payload)
        if "max_tokens" in payload or "temperature" in payload:
            return httpx.Response(
                400,
                json={
                    "error": {
                        "message": "Unsupported parameter: 'max_tokens' is not supported "
                        "with this model. Use 'max_completion_tokens' instead."
                    }
                },
            )
        return httpx.Response(200, json={"choices": [{"message": {"content": "fine"}}]})

    client = openai(handler)
    assert await client.complete(MSGS, temperature=0.2, max_tokens=64) == "fine"
    assert len(bodies) == 2
    assert bodies[1]["max_completion_tokens"] == 64
    assert "temperature" not in bodies[1] and "max_tokens" not in bodies[1]
    await client.complete(MSGS, temperature=0.2, max_tokens=64)
    assert len(bodies) == 3  # learned: the next call goes straight to the relaxed form


async def test_falls_back_to_responses_api_when_chat_endpoint_refused():
    paths = []

    def handler(req: httpx.Request) -> httpx.Response:
        paths.append(req.url.path)
        body = json.loads(req.content)
        if req.url.path.endswith("/chat/completions"):
            return httpx.Response(
                404, json={"error": {"message": "This model is only supported in v1/responses."}}
            )
        assert body["instructions"] == "be brief"
        assert body["input"] == [{"role": "user", "content": "hello"}]
        if body["stream"]:
            return sse(
                {"type": "response.output_text.delta", "delta": "Hi "},
                {"type": "response.output_text.delta", "delta": "there"},
                {"type": "response.completed"},
            )
        return httpx.Response(
            200,
            json={
                "output": [
                    {"type": "message", "content": [{"type": "output_text", "text": "done"}]}
                ]
            },
        )

    client = openai(handler)
    assert await collect(client.stream(MSGS, max_tokens=5)) == "Hi there"
    assert paths == ["/v1/chat/completions", "/v1/responses"]
    assert await client.complete(MSGS) == "done"  # remembered; no further chat attempts
    assert paths[2:] == ["/v1/responses"]


async def test_non_openai_providers_never_fall_back_to_responses():
    cfg = build_config("groq", "m", api_key=KEY)
    client = OpenAIClient(
        cfg,
        http=http(lambda r: httpx.Response(404, json={"error": {"message": "see responses docs"}})),
    )
    with pytest.raises(LLMError, match="could not find"):
        await client.complete(MSGS)


@pytest.mark.parametrize(
    ("status", "needle"),
    [
        (401, "rejected the API key"),
        (403, "rejected the API key"),
        (404, "could not find"),
        (429, "rate-limiting"),
        (500, "HTTP 500"),
    ],
)
async def test_http_errors_are_explained_and_never_leak_the_key(status, needle):
    body = {"error": {"message": f"Incorrect key {KEY} provided"}}
    client = openai(lambda r: httpx.Response(status, json=body))
    with pytest.raises(LLMError) as exc:
        await client.complete(MSGS)
    assert needle in str(exc.value)
    assert KEY not in str(exc.value) and "SECRETKEY" not in str(exc.value)


async def test_network_failure_is_friendly():
    def boom(req):
        raise httpx.ConnectError("no route", request=req)

    with pytest.raises(LLMError, match="Could not reach api.openai.com"):
        await openai(boom).complete(MSGS)


async def test_mid_stream_error_event_becomes_llm_error():
    client = openai(
        lambda r: sse(
            {"choices": [{"delta": {"content": "a"}}]}, {"error": {"message": f"overloaded {KEY}"}}
        )
    )
    with pytest.raises(LLMError) as exc:
        await collect(client.stream(MSGS))
    assert "overloaded" in str(exc.value) and KEY not in str(exc.value)


async def test_garbage_success_body_is_reported():
    with pytest.raises(LLMError, match="unexpected format"):
        await openai(lambda r: httpx.Response(200, json={"nope": 1})).complete(MSGS)


async def test_local_server_without_key_sends_no_auth_header():
    seen = []

    def handler(req):
        seen.append(dict(req.headers))
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

    cfg = build_config("custom", "m", "http://localhost:1234/v1")
    await OpenAIClient(cfg, http=http(handler)).complete(MSGS)
    assert "authorization" not in seen[0]


# ----------------------------------------------------------------------------- Anthropic


def test_to_anthropic_splits_system_merges_runs_and_starts_with_user():
    system, turns = to_anthropic(
        [
            {"role": "system", "content": "S1"},
            {"role": "assistant", "content": "orphan reply"},  # truncated history starts here
            {"role": "user", "content": "q1"},
            {"role": "user", "content": "q2"},
            {"role": "assistant", "content": "a1"},
            {"role": "user", "content": "   "},  # empty turns are dropped
            {"role": "user", "content": "q3"},
        ]
    )
    assert system == "S1"
    assert turns == [
        {"role": "user", "content": "q1\n\nq2"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "q3"},
    ]


async def test_anthropic_request_shape_and_stream():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((str(req.url), dict(req.headers), json.loads(req.content)))
        return sse(
            {"type": "message_start"},
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Cl"}},
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "aude"}},
            {"type": "message_stop"},
        )

    client = AnthropicClient(build_config("anthropic", api_key=KEY), http=http(handler))
    assert await collect(client.stream(MSGS)) == "Claude"
    url, headers, body = seen[0]
    assert url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == KEY and headers["anthropic-version"] == "2023-06-01"
    assert "authorization" not in headers
    assert body["model"] == "claude-sonnet-5-5" and body["system"] == "be brief"
    assert body["messages"] == [{"role": "user", "content": "hello"}]
    assert body["max_tokens"] == 4096 and body["stream"] is True


async def test_anthropic_complete_and_temperature_retry():
    bodies = []

    def handler(req):
        payload = json.loads(req.content)
        bodies.append(payload)
        if "temperature" in payload:
            return httpx.Response(400, json={"error": {"message": "temperature is deprecated"}})
        return httpx.Response(200, json={"content": [{"type": "text", "text": "OK"}]})

    client = AnthropicClient(build_config("anthropic", api_key=KEY), http=http(handler))
    assert await client.complete(MSGS, temperature=0, max_tokens=16) == "OK"
    assert len(bodies) == 2 and "temperature" not in bodies[1]


async def test_anthropic_errors_and_inline_error_events():
    client = AnthropicClient(
        build_config("anthropic", api_key=KEY),
        http=http(lambda r: httpx.Response(401, json={"error": {"message": "invalid x-api-key"}})),
    )
    with pytest.raises(LLMError, match="rejected the API key"):
        await client.complete(MSGS)
    client = AnthropicClient(
        build_config("anthropic", api_key=KEY),
        http=http(lambda r: sse({"type": "error", "error": {"message": "Overloaded"}})),
    )
    with pytest.raises(LLMError, match="Overloaded"):
        await collect(client.stream(MSGS))


# ----------------------------------------------------------------------------- Ollama (optional)


def ollama(handler) -> OllamaClient:
    return OllamaClient(build_config("ollama", "llama3.1:8b"), http=http(handler))


async def test_ollama_stream_and_options():
    seen = []

    def handler(req):
        seen.append(json.loads(req.content))
        lines = [{"message": {"content": "a"}}, {"message": {"content": "b"}, "done": True}]
        return httpx.Response(200, text="\n".join(json.dumps(x) for x in lines))

    client = ollama(handler)
    assert await collect(client.stream(MSGS, max_tokens=24)) == "ab"
    assert seen[0]["options"]["num_predict"] == 24 and seen[0]["options"]["num_ctx"] == 8192


async def test_ollama_model_missing_is_explained():
    client = ollama(lambda r: httpx.Response(404, json={"error": "model 'x' not found"}))
    with pytest.raises(LLMError, match="not found"):
        await client.complete(MSGS)


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        ({"models": [{"name": "llama3.1:8b"}]}, {"reachable": True, "model_ready": True}),
        ({"models": []}, {"reachable": True, "model_ready": False}),
    ],
)
async def test_ollama_status(tags, expected):
    assert await ollama(lambda r: httpx.Response(200, json=tags)).status() == expected


async def test_ollama_status_unreachable():
    def boom(req):
        raise httpx.ConnectError("down", request=req)

    assert await ollama(boom).status() == {"reachable": False, "model_ready": False}


# ----------------------------------------------------------------------------- switching + misc


def test_make_client_picks_wire_protocol():
    s = Settings()
    assert isinstance(make_client(build_config("openai", "m", api_key=KEY), s), OpenAIClient)
    assert isinstance(make_client(build_config("gemini", "m", api_key=KEY), s), OpenAIClient)
    assert isinstance(make_client(build_config("anthropic", api_key=KEY), s), AnthropicClient)
    assert isinstance(make_client(build_config("ollama"), s), OllamaClient)


async def test_switchable_requires_configuration():
    llm = SwitchableLLM(build_config("openai", "m"), Settings())  # model but no key
    with pytest.raises(LLMNotConfigured, match="API key"):
        await llm.complete(MSGS)
    with pytest.raises(LLMNotConfigured, match="API key"):
        await collect(llm.stream(MSGS))
    llm = SwitchableLLM(build_config("openai", ""), Settings())
    with pytest.raises(LLMNotConfigured, match="model name"):
        llm.ensure_ready()
    assert (await llm.status())["configured"] is False


async def test_switchable_apply_swaps_provider_at_runtime():
    llm = SwitchableLLM(build_config("openai", "m"), Settings())
    assert llm.label == "OpenAI · m"
    await llm.apply(build_config("anthropic", api_key=KEY))
    assert llm.label == "Anthropic · claude-sonnet-5-5" and llm.config.configured
    assert isinstance(llm._client, AnthropicClient)
    llm.ensure_ready()


def test_scrub_masks_key_and_key_shaped_tokens():
    assert KEY not in scrub(f"bad key {KEY}", KEY)
    assert "sk-proj-abcdefghij1234" not in scrub("token sk-proj-abcdefghij1234 leaked")
    assert scrub("nothing secret here") == "nothing secret here"
