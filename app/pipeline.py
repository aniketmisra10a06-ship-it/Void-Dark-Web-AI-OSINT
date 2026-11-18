"""The investigation pipeline: refine -> search -> filter -> fetch -> redact -> analyse.

``run_chat`` is an async generator of ``(event, data)`` tuples that the API layer streams
to the browser as Server-Sent Events. All collaborators are injected, so the pipeline is
fully testable without Tor or an LLM.
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from . import analysis
from .audit import AuditLog
from .config import Settings
from .fetcher import Page
from .llm import LLMError
from .prompts import REFINE_PROMPT, REFUSAL, SYSTEM_PROMPT, SourceDoc, build_context
from .safety import SafetyPolicy, defang, normalize_url, redact, sanitize
from .search import SearchOutcome

log = logging.getLogger(__name__)

Event = tuple[str, dict[str, Any]]
HISTORY_TURNS = 8


class LLM(Protocol):
    label: str  # human-readable "Provider · model"

    def ensure_ready(self) -> None: ...
    async def complete(self, messages: list[dict[str, str]], **options: Any) -> str: ...
    def stream(self, messages: list[dict[str, str]]) -> AsyncIterator[str]: ...
    async def status(self) -> dict[str, bool]: ...


class Searcher(Protocol):
    async def search(self, query: str) -> SearchOutcome: ...


class Fetcher(Protocol):
    async def fetch_many(self, urls: list[str]) -> dict[str, Page | None]: ...


@dataclass
class Services:
    settings: Settings
    llm: LLM
    searcher: Searcher
    fetcher: Fetcher
    policy: SafetyPolicy
    audit: AuditLog
    tor_check: Callable[[], Awaitable[bool]] | None = None
    llm_store: Any = None  # app.llm_store.LLMStore; persists the UI-chosen provider/key
    llm_source: str = "env"  # where the active AI config came from: "env" or "saved"
    tor: Any = None  # app.tor.TorManager (embedded or external Tor)


@dataclass(frozen=True)
class ChatTurn:
    role: str
    content: str


def _status(step: str, message: str) -> Event:
    return "status", {"step": step, "message": message}


async def _refine(svc: Services, question: str) -> str:
    """Ask the LLM for a short keyword query; fall back to local keyword extraction."""
    prompt = [{"role": "user", "content": REFINE_PROMPT.format(question=question)}]
    try:
        out = await svc.llm.complete(prompt, temperature=0, max_tokens=64)
    except LLMError:
        return analysis.refine_query(question)
    first_line = next((ln for ln in out.splitlines() if ln.strip()), "")
    cleaned = re.sub(r"[\"'`]", "", first_line).strip()[:80]
    return cleaned or analysis.refine_query(question)


def _history_messages(history: list[ChatTurn]) -> list[dict[str, str]]:
    return [
        {"role": t.role, "content": sanitize(t.content, 4000)}
        for t in history[-HISTORY_TURNS:]
        if t.role in ("user", "assistant") and t.content.strip()
    ]


def _pick_links(pages: list[Page], known: set[str], terms: list[str], limit: int) -> list[str]:
    """Outbound links worth following one hop: anchor text or URL matching the query terms."""
    scored: dict[str, int] = {}
    for page in pages:
        for url, anchor in page.links:
            key = normalize_url(url)
            if key in known:
                continue
            score = analysis.relevance(f"{anchor} {url}", terms)
            if score:
                scored[url] = max(scored.get(url, 0), score)
    return [u for u, _ in sorted(scored.items(), key=lambda kv: -kv[1])[:limit]]


async def run_chat(
    svc: Services, message: str, history: list[ChatTurn], search: bool
) -> AsyncIterator[Event]:
    cfg = svc.settings

    verdict = svc.policy.check_query(message)
    if not verdict.allowed:
        svc.audit.record(
            {"type": "blocked_query", "reason": verdict.reason, "query": message[:200]}
        )
        yield "token", {"text": REFUSAL}
        yield "done", {"blocked": True}
        return

    if analysis.is_smalltalk(message):
        yield "token", {"text": analysis.SMALLTALK_REPLY}
        yield "done", {"refined": "", "sources": 0}
        return

    builtin = bool(getattr(svc.llm, "builtin", False))
    notice = ""
    if not builtin:
        try:
            svc.llm.ensure_ready()
        except LLMError as exc:
            if not search:
                yield "error", {"message": str(exc)}
                return
            # The chosen AI is not usable: keep working with the built-in analyst instead.
            builtin, notice = True, f"{exc} Using the built-in analyst for this answer."
    if builtin and not search:
        yield (
            "token",
            {
                "text": "Follow-up chat needs an AI model. Turn on **Search dark web** for a new "
                "investigation, or add an API key under *AI model & API key* (optional)."
            },
        )
        yield "done", {"refined": "", "sources": 0}
        return
    label = "Void built-in" if builtin else svc.llm.label
    if notice:
        yield _status("warn", notice)

    base = [{"role": "system", "content": SYSTEM_PROMPT}, *_history_messages(history)]
    refined = ""
    docs: list[SourceDoc] = []
    stats = analysis.RunStats()
    terms: list[str] = []

    if search:
        yield _status("refine", "Preparing the search query")
        refined = analysis.refine_query(message) if builtin else await _refine(svc, message)
        verdict = svc.policy.check_query(refined)
        if not verdict.allowed:
            svc.audit.record({"type": "blocked_query", "reason": verdict.reason, "query": refined})
            yield "token", {"text": REFUSAL}
            yield "done", {"blocked": True}
            return
        terms = analysis.keywords(f"{refined} {message}", 8)

        total = len(cfg.search_engines)
        yield _status(
            "search", f"Searching {total} dark-web search engines for “{refined}” via Tor"
        )
        outcome = await svc.searcher.search(refined)
        if outcome.engines_total:
            yield _status(
                "search",
                f"{outcome.engines_answered} of {outcome.engines_total} engines answered "
                f"({outcome.engines_empty} empty, {len(outcome.errors)} unreachable): "
                f"{len(outcome.results)} unique results",
            )
        if outcome.errors:  # one calm line: dead engines are normal on Tor
            yield _status(
                "search",
                "Offline or blocked right now (normal for hidden services): "
                + "; ".join(outcome.errors),
            )

        dropped = 0
        results = []
        for r in outcome.results:
            if svc.policy.check_content(f"{r.title}\n{r.snippet}").allowed:
                results.append(r)
            else:
                dropped += 1
        results = results[: cfg.max_results]

        if not results:
            svc.audit.record(
                {
                    "type": "investigation",
                    "query": message[:200],
                    "refined": refined,
                    "urls": [],
                    "dropped": dropped,
                }
            )
            hint = (
                "Every search engine failed (details are under *Investigation steps*). "
                "Usually Tor is still bootstrapping, or the engines are down or blocking Tor; "
                "wait a minute and retry."
                if outcome.errors and not outcome.results and not outcome.engines_answered
                else "Try different or broader keywords."
            )
            yield "token", {"text": f"No usable results for **{refined}**. {hint}"}
            yield "done", {"refined": refined, "sources": 0}
            return

        yield _status(
            "fetch", f"Reading up to {cfg.max_fetch * 2} of {len(results)} results (text only)"
        )
        candidates = results[: cfg.max_fetch * 2]
        fetched = await svc.fetcher.fetch_many([r.url for r in candidates])
        pages: list[tuple[Page, str, bool]] = []  # (page, title, crawled)
        first_hop: list[Page] = []
        for r in candidates:
            page = fetched.get(r.url)
            if page is not None:
                pages.append((page, page.title or r.title, False))
                first_hop.append(page)

        if cfg.crawl_links and first_hop:
            known = {normalize_url(r.url) for r in results}
            extra = _pick_links(first_hop, known, terms, cfg.crawl_links)
            if extra:
                yield _status(
                    "fetch", f"Following {len(extra)} relevant links found on those pages"
                )
                more = await svc.fetcher.fetch_many(extra)
                for url in extra:
                    page = more.get(url)
                    if page is not None:
                        pages.append((page, page.title, True))

        ranked: list[tuple[int, int, Page, str, bool]] = []
        for i, (page, title, crawled) in enumerate(pages):
            if not svc.policy.check_content(f"{page.title}\n{page.text}").allowed:
                dropped += 1
                continue
            ranked.append(
                (analysis.relevance(f"{title}\n{page.text}", terms), i, page, title, crawled)
            )
        ranked.sort(key=lambda t: (-t[0], t[1]))
        crawled_used = 0
        for _, _, page, title, crawled in ranked[: cfg.max_fetch]:
            text = redact(page.text) if cfg.redact_pii else page.text
            docs.append(SourceDoc(len(docs) + 1, title, page.url, text, True))
            crawled_used += crawled

        if not docs:  # pages unreachable: fall back to search-result snippets
            for r in results[: cfg.max_fetch]:
                if r.snippet:
                    snippet = redact(r.snippet) if cfg.redact_pii else r.snippet
                    docs.append(SourceDoc(len(docs) + 1, r.title, r.url, snippet, False))

        if not docs:
            yield (
                "token",
                {
                    "text": "I found results but none of the pages could be read or "
                    "they were filtered out. Try again or rephrase."
                },
            )
            yield "done", {"refined": refined, "sources": 0}
            return

        urls_read = [d.url for d in docs]
        svc.audit.record(
            {
                "type": "investigation",
                "query": message[:200],
                "refined": refined,
                "urls": urls_read,
                "dropped": dropped,
            }
        )
        yield (
            "sources",
            {
                "items": [
                    {
                        "n": d.n,
                        "title": d.title,
                        "url": d.url,
                        "display": defang(d.url),
                        "fetched": d.fetched,
                    }
                    for d in docs
                ],
                "more": max(0, len(results) - len(docs)),
            },
        )
        stats = analysis.RunStats(
            engines_total=outcome.engines_total,
            engines_answered=outcome.engines_answered,
            results_total=len(outcome.results),
            pages_read=len(pages),
            pages_crawled=crawled_used,
        )
        user_content = build_context(message, docs)
        yield _status("analyze", f"Analysing {len(docs)} source(s) with {label}")
    else:
        user_content = message
        yield _status("analyze", f"Thinking with {label}")

    if not builtin:
        messages = [*base, {"role": "user", "content": user_content}]
        started = False
        try:
            async for chunk in svc.llm.stream(messages):
                started = True
                yield "token", {"text": chunk}
        except LLMError as exc:  # messages are user-safe and never contain the API key
            log.warning("LLM failure: %s", exc)
            if started or not docs:
                yield "error", {"message": str(exc)}
                return
            builtin = True
            notice = f"{exc} Showing the built-in analysis instead."
            label = "Void built-in"
            yield _status("warn", notice)
        else:
            yield "done", {"refined": refined, "sources": len(docs), "model": label}
            return

    report = analysis.build_report(message, docs, terms, stats)
    if notice:
        report = f"*{notice}*\n\n{report}"
    for piece in analysis.chunk(report):
        yield "token", {"text": piece}
    yield "done", {"refined": refined, "sources": len(docs), "model": label}
