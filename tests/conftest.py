"""Shared fakes so the whole pipeline runs without Tor or an LLM."""

from __future__ import annotations

import pytest

from app.audit import AuditLog
from app.config import Settings
from app.fetcher import Page
from app.pipeline import ChatTurn, Services, run_chat
from app.safety import SafetyPolicy
from app.search import SearchOutcome, SearchResult


def onion(n: int = 0, path: str = "") -> str:
    """A syntactically valid v3 onion URL (56 base32 chars); n picks a distinct host."""
    return f"http://{chr(97 + n) * 56}.onion{path}"


class FakeLLM:
    label = "Fake · test-model"

    def __init__(self, refined: str = "ransomware healthcare", tokens=("Hello ", "[1] world")):
        self.refined = refined
        self.tokens = tokens
        self.complete_calls: list[list[dict]] = []
        self.stream_calls: list[list[dict]] = []
        self.fail_stream = False
        self.not_ready: str | None = None  # set to a message to simulate "no API key yet"

    def ensure_ready(self):
        from app.llm import LLMNotConfigured

        if self.not_ready:
            raise LLMNotConfigured(self.not_ready)

    async def complete(self, messages, **options):
        self.complete_calls.append(messages)
        return self.refined

    async def stream(self, messages, **options):
        from app.llm import LLMError

        self.stream_calls.append(messages)
        if self.fail_stream:
            raise LLMError("boom")
        for token in self.tokens:
            yield token

    async def status(self):
        return {"reachable": True, "model_ready": True}

    async def aclose(self):
        pass


class FakeSearcher:
    def __init__(self, results=None, errors=None):
        self.results = results or []
        self.errors = errors or []
        self.queries: list[str] = []

    async def search(self, query):
        self.queries.append(query)
        return SearchOutcome(list(self.results), list(self.errors))


class FakeFetcher:
    def __init__(self, pages: dict[str, Page | None] | None = None):
        self.pages = pages or {}
        self.requested: list[str] = []

    async def fetch_many(self, urls):
        self.requested = list(urls)
        return {u: self.pages.get(u) for u in urls}


def result(n: int, title: str = "Result", snippet: str = "snippet") -> SearchResult:
    return SearchResult(title=f"{title} {n}", url=onion(n), snippet=snippet, engine="fake")


def page(n: int, text: str = "page body", title: str = "Page") -> Page:
    return Page(url=onion(n), title=f"{title} {n}", text=text)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        blocklist_file=None,
        max_fetch=3,
        max_results=6,
        allowed_hosts=("testserver", "localhost"),
    )


@pytest.fixture
def make_services(settings):
    def _make(llm=None, searcher=None, fetcher=None, **setting_overrides) -> Services:
        cfg = (
            Settings(**{**settings.__dict__, **setting_overrides})
            if setting_overrides
            else settings
        )
        return Services(
            settings=cfg,
            llm=llm or FakeLLM(),
            searcher=searcher or FakeSearcher(),
            fetcher=fetcher or FakeFetcher(),
            policy=SafetyPolicy(),
            audit=AuditLog(cfg.data_dir / "audit.jsonl"),
        )

    return _make


@pytest.fixture
def collect():
    async def _collect(svc, message="what is going on with acme?", history=None, search=True):
        turns = [ChatTurn(**t) for t in (history or [])]
        return [event async for event in run_chat(svc, message, turns, search)]

    return _collect
