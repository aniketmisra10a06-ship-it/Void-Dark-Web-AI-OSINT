"""FastAPI application: static chat UI + streaming chat API + AI-model settings API."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StringConstraints
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import __version__
from .audit import AuditLog
from .config import Settings
from .fetcher import TorFetcher
from .llm import LLMError, SwitchableLLM
from .llm_store import LLMStore, initial_llm_config
from .pipeline import ChatTurn, Services, run_chat
from .providers import PRESETS, LLMConfig, build_config, key_hint
from .safety import SafetyPolicy
from .search import TorSearcher, make_tor_client
from .tor import TorManager

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).resolve().parent / "static"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class SecurityHeadersMiddleware:
    """Pure-ASGI middleware (unlike BaseHTTPMiddleware it never buffers streaming responses)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in SECURITY_HEADERS.items():
                    headers.setdefault(key, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)


class Turn(BaseModel):
    role: Literal["user", "assistant"]  # "system" is deliberately not accepted from clients
    content: Annotated[str, StringConstraints(max_length=8000)]


class ChatRequest(BaseModel):
    message: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
    history: list[Turn] = Field(default_factory=list, max_length=20)
    search: bool = True


class LLMSettingsIn(BaseModel):
    provider: Annotated[str, StringConstraints(strip_whitespace=True, max_length=32)]
    model: Annotated[str, StringConstraints(strip_whitespace=True, max_length=120)] = ""
    base_url: Annotated[str, StringConstraints(strip_whitespace=True, max_length=300)] = ""
    # None / empty = keep the saved key (only if provider and URL are unchanged)
    api_key: Annotated[str, StringConstraints(max_length=512)] | None = None
    clear_key: bool = False


def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def build_services(settings: Settings) -> tuple[Services, list]:
    tor = TorManager(settings.tor_proxy, settings.tor_binary, settings.data_dir)
    tor_client = make_tor_client(tor.proxy_url, settings.fetch_timeout)
    store = LLMStore(settings.data_dir / "llm.json")
    config, source = initial_llm_config(settings, store)
    llm = SwitchableLLM(config, settings)
    cache: dict[str, Any] = {"at": 0.0, "ok": False}

    async def tor_check() -> bool:
        """True if Tor is usable: bootstrapped (embedded) or exiting via Tor (external proxy)."""
        if tor.embedded:
            return tor.ready
        if time.monotonic() - cache["at"] < 30:
            return cache["ok"]
        ok = False
        if settings.tor_check_url:
            try:
                resp = await tor_client.get(settings.tor_check_url, timeout=20.0)
                ok = bool(resp.json().get("IsTor"))
            except (httpx.HTTPError, ValueError):
                ok = False
        cache.update(at=time.monotonic(), ok=ok)
        return ok

    services = Services(
        settings=settings,
        llm=llm,
        searcher=TorSearcher(
            tor_client,
            settings.search_engines,
            settings.allow_clearnet,
            per_host=settings.per_host,
            max_results=settings.max_results,
            concurrency=settings.engine_concurrency,
            timeout=settings.fetch_timeout + 20,
        ),
        fetcher=TorFetcher(
            tor_client,
            max_bytes=settings.max_bytes,
            max_chars=settings.max_chars_per_page,
            allow_clearnet=settings.allow_clearnet,
            concurrency=6,
        ),
        policy=SafetyPolicy.from_file(settings.blocklist_file),
        audit=AuditLog(settings.data_dir / "audit.jsonl"),
        tor_check=tor_check,
        llm_store=store,
        llm_source=source,
        tor=tor,
    )
    return services, [tor_client.aclose, llm.aclose, tor.stop]


def _llm_state(cfg: LLMConfig | None, probe: dict[str, bool]) -> str:
    if cfg is not None and cfg.builtin:
        return "ready"
    if cfg is not None and not cfg.configured:
        return "needs_setup"
    if not probe.get("reachable", True):
        return "offline"
    if not probe.get("model_ready", True):
        return "pulling"
    return "ready"


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    settings = settings or Settings.from_env()
    closers: list = []
    if services is None:
        services, closers = build_services(settings)
    svc = services
    sem = asyncio.Semaphore(settings.max_concurrent)
    allowed_hosts = {h.strip("[]").lower() for h in settings.allowed_hosts}

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if svc.tor is not None:
            await svc.tor.start()
        yield
        for close in closers:
            await close()

    app = FastAPI(
        title="Void",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    # ------------------------------------------------------------------ access control
    async def guard(request: Request) -> None:
        """Token auth when configured; otherwise a host allow-list (anti DNS-rebinding).

        State-changing requests must also be same-origin, which blocks cross-site forgery.
        """
        host_header = request.headers.get("host", "")
        if settings.access_token:
            header = request.headers.get("authorization", "")
            supplied = header[7:] if header.lower().startswith("bearer ") else ""
            if not secrets.compare_digest(supplied.encode(), settings.access_token.encode()):
                raise HTTPException(
                    401, "Invalid or missing access token", headers={"WWW-Authenticate": "Bearer"}
                )
        else:
            hostname = (urlparse(f"//{host_header}").hostname or "").lower()
            if hostname not in allowed_hosts:
                raise HTTPException(
                    403,
                    "This host name is not allowed. Set ACCESS_TOKEN, or add the name to "
                    "ALLOWED_HOSTS, to use Void from another address.",
                )
        origin = request.headers.get("origin")
        if (
            request.method in UNSAFE_METHODS
            and origin
            and urlparse(origin).netloc.lower() != host_header.lower()
        ):
            raise HTTPException(403, "Cross-origin request blocked.")

    protected = [Depends(guard)]

    # ------------------------------------------------------------------ helpers
    def switchable() -> SwitchableLLM:
        if not isinstance(svc.llm, SwitchableLLM):
            raise HTTPException(501, "This server's AI backend cannot be changed at runtime.")
        return svc.llm

    def editable() -> SwitchableLLM:
        if not settings.allow_ui_config:
            raise HTTPException(
                403, "AI settings are locked by the server administrator (ALLOW_UI_CONFIG=false)."
            )
        return switchable()

    def public(cfg: LLMConfig) -> dict[str, Any]:
        return {
            "provider": cfg.provider,
            "model": cfg.model,
            "base_url": cfg.base_url,
            "kind": cfg.kind,
            "has_key": bool(cfg.api_key),
            "key_hint": key_hint(cfg.api_key),  # never the key itself
            "needs_key": cfg.needs_key,
            "configured": cfg.configured,
            "source": svc.llm_source,
            "can_edit": settings.allow_ui_config,
        }

    # ------------------------------------------------------------------ routes
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/status", dependencies=protected)
    async def status() -> dict[str, Any]:
        tor_ok, probe = await asyncio.gather(
            svc.tor_check() if svc.tor_check else asyncio.sleep(0, result=False),
            svc.llm.status(),
        )
        cfg: LLMConfig | None = getattr(svc.llm, "config", None)
        return {
            "version": __version__,
            "provider": cfg.provider if cfg else "",
            "model": cfg.model if cfg else "",
            "label": svc.llm.label,
            "tor": bool(tor_ok),
            "tor_progress": svc.tor.progress if svc.tor and svc.tor.embedded else None,
            "tor_error": svc.tor.error if svc.tor else "",
            "engines": len(settings.search_engines),
            "llm_state": _llm_state(cfg, probe),
            "llm": probe["reachable"],
            "model_ready": probe["model_ready"],
            "auth_required": bool(settings.access_token),
        }

    @app.get("/api/settings", dependencies=protected)
    async def get_settings() -> dict[str, Any]:
        llm = switchable()
        providers = [
            {
                "id": p.id,
                "label": p.label,
                "kind": p.kind,
                "base_url": settings.ollama_host if p.kind == "ollama" else p.base_url,
                "default_model": p.default_model,
                "model_hint": p.model_hint,
                "needs_key": p.needs_key,
            }
            for p in PRESETS
        ]
        return {"current": public(llm.config), "providers": providers}

    @app.put("/api/settings", dependencies=protected)
    async def put_settings(body: LLMSettingsIn) -> dict[str, Any]:
        llm = editable()
        current = llm.config
        explicit_key = "" if body.clear_key else (body.api_key or "")
        try:
            new = build_config(
                body.provider,
                body.model,
                body.base_url,
                explicit_key,
                ollama_host=settings.ollama_host,
                require_model=True,
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        # Keep the saved key only if it would still go to the same provider and URL; otherwise
        # a changed endpoint could silently receive a key that was issued for another service.
        same_target = new.provider == current.provider and new.base_url == current.base_url.rstrip(
            "/"
        )
        if not explicit_key and not body.clear_key and same_target:
            new = replace(new, api_key=current.api_key)
        if svc.llm_store is not None:
            try:
                svc.llm_store.save(new)
            except OSError:
                log.exception("Could not persist AI settings")
                raise HTTPException(
                    500, "Could not save settings. Is the data directory writable?"
                ) from None
        await llm.apply(new)
        svc.llm_source = "saved"
        return public(new)

    @app.post("/api/settings/test", dependencies=protected)
    async def test_settings() -> dict[str, Any]:
        llm = editable()
        try:
            await llm.complete(
                [{"role": "user", "content": "Reply with the single word OK."}],
                temperature=0,
                max_tokens=16,
            )
        except LLMError as exc:
            return {"ok": False, "message": str(exc)}
        return {"ok": True, "message": f"Connected: {llm.label} answered."}

    @app.post("/api/chat", dependencies=protected, response_model=None)
    async def chat(req: ChatRequest) -> StreamingResponse | JSONResponse:
        if sem.locked():
            return JSONResponse(
                {"detail": "Server is busy with other investigations. Try again shortly."},
                status_code=429,
            )

        async def stream() -> AsyncIterator[str]:
            async with sem:
                try:
                    turns = [ChatTurn(t.role, t.content) for t in req.history]
                    async for event, data in run_chat(svc, req.message, turns, req.search):
                        yield _sse(event, data)
                except Exception:
                    log.exception("Unhandled error in chat pipeline")
                    yield _sse("error", {"message": "Unexpected server error. Check the logs."})

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
