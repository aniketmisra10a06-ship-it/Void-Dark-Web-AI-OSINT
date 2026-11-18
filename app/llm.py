"""LLM clients behind one small interface.

* ``OpenAIClient``    - OpenAI, Gemini, OpenRouter, Groq, Mistral and any OpenAI-compatible server
                        (Chat Completions, with automatic fallback to the Responses API).
* ``AnthropicClient`` - Claude via the Messages API.
* ``OllamaClient``    - optional local models.
* ``SwitchableLLM``   - what the app actually holds; lets the UI change provider at runtime.

Error messages are written for end users and never contain the API key.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import Settings
from .providers import LLMConfig

log = logging.getLogger(__name__)
Messages = list[dict[str, str]]


class LLMError(RuntimeError):
    """The model could not be reached or returned an error. The message is safe to show users."""


class LLMNotConfigured(LLMError):
    """No usable model/API key has been configured yet."""


# --------------------------------------------------------------------------- error helpers

_SECRETISH = re.compile(r"\b(?:sk|gsk|xai|pk|key)[-_][A-Za-z0-9_\-]{10,}")


def scrub(text: str, key: str = "") -> str:
    """Remove the API key (and anything shaped like one) from text before it is shown or logged."""
    if key:
        text = text.replace(key, "***")
    return _SECRETISH.sub("***", text)


def _err_text(err: Any) -> str:
    if isinstance(err, dict):
        return str(err.get("message") or err)
    return str(err)


def _detail(body: str, key: str) -> str:
    try:
        msg = _err_text(json.loads(body)["error"])
    except (ValueError, KeyError, TypeError):
        msg = body
    return scrub(msg[:300], key).strip()


def explain(status: int, body: str, cfg: LLMConfig) -> str:
    host = urlparse(cfg.base_url).hostname or "The provider"
    detail = _detail(body, cfg.api_key)
    tail = f" Provider said: {detail}" if detail else ""
    if status in (401, 403):
        return (
            f"{host} rejected the API key (HTTP {status}). "
            f"Check the key and its permissions in the AI model settings.{tail}"
        )
    if status == 404:
        return (
            f"{host} could not find that model or endpoint (HTTP 404). "
            f"Check the model name and base URL.{tail}"
        )
    if status == 429:
        return f"{host} is rate-limiting this key or its quota is used up (HTTP 429).{tail}"
    return f"{host} returned HTTP {status}.{tail}"


# --------------------------------------------------------------------------- base client


class _Client:
    """Shared HTTP plumbing: one request path, adaptive retries, friendly errors."""

    def __init__(
        self,
        cfg: LLMConfig,
        *,
        timeout: float = 300.0,
        http: httpx.AsyncClient | None = None,
        trust_env: bool = True,
    ) -> None:
        self.cfg = cfg
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=15.0),
            follow_redirects=False,  # a redirect could carry the key to another host
            trust_env=trust_env,
        )
        self._level = 0  # 0 = standard parameters, 1 = relaxed (for stricter models)

    # -- subclass hooks
    def _build(
        self, messages: Messages, stream: bool, temperature: float | None, max_tokens: int | None
    ) -> tuple[str, dict[str, Any], dict[str, str]]:
        raise NotImplementedError

    def _adapt(self, status: int, body: str) -> bool:
        """Return True if the request should be retried with adjusted parameters."""
        return False

    def _parse_complete(self, obj: dict[str, Any]) -> str:
        raise NotImplementedError

    # -- shared behaviour
    @asynccontextmanager
    async def _open(
        self, messages: Messages, stream: bool, temperature: float | None, max_tokens: int | None
    ) -> AsyncIterator[httpx.Response]:
        host = urlparse(self.cfg.base_url).hostname or "the provider"
        for _ in range(3):
            url, payload, headers = self._build(messages, stream, temperature, max_tokens)
            try:
                async with self._http.stream("POST", url, json=payload, headers=headers) as resp:
                    if resp.status_code == 200:
                        yield resp
                        return
                    body = (await resp.aread()).decode("utf-8", "replace")
                    status = resp.status_code
            except httpx.HTTPError as exc:
                raise LLMError(
                    f"Could not reach {host} ({type(exc).__name__}). "
                    "Check the base URL and your network connection."
                ) from exc
            if not self._adapt(status, body):
                raise LLMError(explain(status, body, self.cfg))
        raise LLMError(f"{host} kept rejecting the request parameters.")

    async def complete(
        self, messages: Messages, *, temperature: float | None = None, max_tokens: int | None = None
    ) -> str:
        async with self._open(messages, False, temperature, max_tokens) as resp:
            raw = await resp.aread()
        try:
            return self._parse_complete(json.loads(raw))
        except (ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMError("The provider returned a response in an unexpected format.") from exc

    async def status(self) -> dict[str, bool]:
        ready = self.cfg.configured
        return {"reachable": ready, "model_ready": ready}

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()


# --------------------------------------------------------------------------- OpenAI-compatible


class OpenAIClient(_Client):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._api = "chat"  # becomes "responses" if the provider requires that endpoint
        self._tried_responses = False

    def _build(self, messages, stream, temperature, max_tokens):
        base = self.cfg.base_url.rstrip("/")
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if stream else "application/json",
        }
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        if self._api == "responses":
            system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
            payload: dict[str, Any] = {
                "model": self.cfg.model,
                "input": [m for m in messages if m["role"] != "system"],
                "stream": stream,
            }
            if system:
                payload["instructions"] = system
            if max_tokens:
                payload["max_output_tokens"] = max(16, max_tokens)
            if temperature is not None and self._level == 0:
                payload["temperature"] = temperature
            return f"{base}/responses", payload, headers
        payload = {"model": self.cfg.model, "messages": messages, "stream": stream}
        if self._level == 0:
            if temperature is not None:
                payload["temperature"] = temperature
            if max_tokens:
                payload["max_tokens"] = max_tokens
        elif max_tokens:  # stricter/reasoning models: no temperature, new token-limit name
            payload["max_completion_tokens"] = max_tokens
        return f"{base}/chat/completions", payload, headers

    def _adapt(self, status: int, body: str) -> bool:
        if status not in (400, 404, 405, 422):
            return False
        low = body.lower()
        if (
            self._api == "chat"
            and self.cfg.provider == "openai"
            and "responses" in low
            and not self._tried_responses
        ):
            self._api, self._tried_responses = "responses", True
            return True
        if self._level == 0 and any(
            w in low for w in ("temperature", "max_tokens", "max_completion_tokens")
        ):
            self._level = 1
            return True
        return False

    def _parse_complete(self, obj: dict[str, Any]) -> str:
        if self._api == "responses":
            parts = [
                c.get("text", "")
                for item in obj.get("output", [])
                for c in (item.get("content") or [])
                if c.get("type") == "output_text"
            ]
            return "".join(parts)
        return obj["choices"][0]["message"].get("content") or ""

    def _stream_text(self, obj: dict[str, Any]) -> str:
        key = self.cfg.api_key
        if obj.get("error"):
            raise LLMError(scrub(_err_text(obj["error"]), key))
        kind = obj.get("type", "")
        if kind == "response.output_text.delta":
            return obj.get("delta") or ""
        if kind in ("response.failed", "error"):
            err = (obj.get("response") or {}).get("error") or obj.get("message") or "request failed"
            raise LLMError(scrub(_err_text(err), key))
        for choice in obj.get("choices") or []:
            content = (choice.get("delta") or {}).get("content")
            if isinstance(content, str) and content:
                return content
        return ""

    async def stream(
        self, messages: Messages, *, temperature: float | None = 0.2, max_tokens: int | None = None
    ) -> AsyncIterator[str]:
        async with self._open(messages, True, temperature, max_tokens) as resp:
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    return
                try:
                    obj = json.loads(data)
                except ValueError:
                    continue
                text = self._stream_text(obj)
                if text:
                    yield text
                if obj.get("type") == "response.completed":
                    return


# --------------------------------------------------------------------------- Anthropic


def to_anthropic(messages: Messages) -> tuple[str, Messages]:
    """Split out the system prompt; merge same-role runs; make sure the first turn is 'user'."""
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    turns: Messages = []
    for m in messages:
        if m["role"] not in ("user", "assistant") or not m["content"].strip():
            continue
        if turns and turns[-1]["role"] == m["role"]:
            turns[-1] = {"role": m["role"], "content": turns[-1]["content"] + "\n\n" + m["content"]}
        else:
            turns.append({"role": m["role"], "content": m["content"]})
    while turns and turns[0]["role"] != "user":
        turns.pop(0)
    return system, turns


class AnthropicClient(_Client):
    def _build(self, messages, stream, temperature, max_tokens):
        base = self.cfg.base_url.rstrip("/")
        url = f"{base}/messages" if base.endswith("/v1") else f"{base}/v1/messages"
        system, turns = to_anthropic(messages)
        payload: dict[str, Any] = {
            "model": self.cfg.model,
            "max_tokens": max_tokens or 4096,
            "messages": turns,
            "stream": stream,
        }
        if system:
            payload["system"] = system
        if temperature is not None and self._level == 0:
            payload["temperature"] = temperature
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.cfg.api_key,
            "anthropic-version": "2023-06-01",
        }
        return url, payload, headers

    def _adapt(self, status: int, body: str) -> bool:
        if status == 400 and self._level == 0 and "temperature" in body.lower():
            self._level = 1
            return True
        return False

    def _parse_complete(self, obj: dict[str, Any]) -> str:
        return "".join(b.get("text", "") for b in obj["content"] if b.get("type") == "text")

    async def stream(
        self, messages: Messages, *, temperature: float | None = 0.2, max_tokens: int | None = None
    ) -> AsyncIterator[str]:
        async with self._open(messages, True, temperature, max_tokens) as resp:
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                try:
                    obj = json.loads(line[5:].strip())
                except ValueError:
                    continue
                kind = obj.get("type")
                if kind == "content_block_delta":
                    delta = obj.get("delta") or {}
                    if delta.get("type") == "text_delta" and delta.get("text"):
                        yield delta["text"]
                elif kind == "error":
                    raise LLMError(scrub(_err_text(obj.get("error")), self.cfg.api_key))
                elif kind == "message_stop":
                    return


# --------------------------------------------------------------------------- Ollama (optional)


class OllamaClient(_Client):
    def __init__(self, cfg: LLMConfig, *, num_ctx: int = 8192, **kwargs: Any) -> None:
        kwargs.setdefault("trust_env", False)  # local/internal host: never route via a proxy
        super().__init__(cfg, **kwargs)
        self._num_ctx = num_ctx

    def _build(self, messages, stream, temperature, max_tokens):
        options: dict[str, Any] = {"num_ctx": self._num_ctx}
        if temperature is not None:
            options["temperature"] = temperature
        if max_tokens:
            options["num_predict"] = max_tokens
        payload = {
            "model": self.cfg.model,
            "messages": messages,
            "stream": stream,
            "options": options,
        }
        return (
            f"{self.cfg.base_url.rstrip('/')}/api/chat",
            payload,
            {"Content-Type": "application/json"},
        )

    def _parse_complete(self, obj: dict[str, Any]) -> str:
        return obj["message"]["content"]

    async def stream(
        self, messages: Messages, *, temperature: float | None = 0.2, max_tokens: int | None = None
    ) -> AsyncIterator[str]:
        async with self._open(messages, True, temperature, max_tokens) as resp:
            async for line in resp.aiter_lines():
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if obj.get("error"):
                    raise LLMError(_err_text(obj["error"])[:300])
                chunk = (obj.get("message") or {}).get("content", "")
                if chunk:
                    yield chunk
                if obj.get("done"):
                    return

    async def status(self) -> dict[str, bool]:
        try:
            resp = await self._http.get(f"{self.cfg.base_url.rstrip('/')}/api/tags", timeout=5.0)
            resp.raise_for_status()
            names = {m.get("name", "") for m in resp.json().get("models", [])}
        except (httpx.HTTPError, ValueError):
            return {"reachable": False, "model_ready": False}
        wanted = self.cfg.model if ":" in self.cfg.model else f"{self.cfg.model}:latest"
        return {"reachable": True, "model_ready": wanted in names}


# --------------------------------------------------------------------------- runtime switching


class BuiltinClient:
    """Placeholder client for the built-in analyst: reports are produced by ``app.analysis``."""

    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg

    async def complete(self, messages: Messages, **_: Any) -> str:
        return ""

    async def stream(self, messages: Messages, **_: Any) -> AsyncIterator[str]:
        return
        yield ""  # pragma: no cover - makes this an async generator

    async def status(self) -> dict[str, bool]:
        return {"reachable": True, "model_ready": True}

    async def aclose(self) -> None:
        return None


def make_client(cfg: LLMConfig, settings: Settings, http: httpx.AsyncClient | None = None) -> Any:
    if cfg.builtin:
        return BuiltinClient(cfg)
    if cfg.kind == "anthropic":
        return AnthropicClient(cfg, timeout=settings.llm_timeout, http=http)
    if cfg.kind == "ollama":
        return OllamaClient(cfg, num_ctx=settings.num_ctx, timeout=settings.llm_timeout, http=http)
    return OpenAIClient(cfg, timeout=settings.llm_timeout, http=http)


class SwitchableLLM:
    """Holds the active client; the UI can replace it without restarting the server."""

    def __init__(
        self,
        config: LLMConfig,
        settings: Settings,
        factory: Callable[[LLMConfig, Settings], Any] = make_client,
    ) -> None:
        self._settings = settings
        self._factory = factory
        self.config = config
        self._client = factory(config, settings)

    @property
    def label(self) -> str:
        return self.config.label

    @property
    def builtin(self) -> bool:
        return self.config.builtin

    def ensure_ready(self) -> None:
        cfg = self.config
        if cfg.configured:
            return
        missing_key = cfg.needs_key and not cfg.api_key
        if missing_key and not cfg.model:
            what = "add your API key and model name"
        elif missing_key:
            what = "add your API key"
        else:
            what = "enter a model name"
        raise LLMNotConfigured(
            f"No AI model is configured for {cfg.preset.label} yet. "
            f"Click the model badge at the top right and {what}."
        )

    async def complete(self, messages: Messages, **kwargs: Any) -> str:
        self.ensure_ready()
        return await self._client.complete(messages, **kwargs)

    async def stream(self, messages: Messages, **kwargs: Any) -> AsyncIterator[str]:
        self.ensure_ready()
        async for chunk in self._client.stream(messages, **kwargs):
            yield chunk

    async def status(self) -> dict[str, bool]:
        return {**await self._client.status(), "configured": self.config.configured}

    async def apply(self, config: LLMConfig) -> None:
        """Switch to a new configuration. In-flight requests finish on the old client."""
        old = self._client
        self._client = self._factory(config, self._settings)
        self.config = config
        asyncio.get_running_loop().call_later(
            self._settings.llm_timeout + 30, lambda: asyncio.ensure_future(old.aclose())
        )

    async def aclose(self) -> None:
        await self._client.aclose()
