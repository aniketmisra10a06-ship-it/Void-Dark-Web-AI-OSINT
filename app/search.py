"""Query dark-web search engines through Tor and parse their result pages."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .safety import is_allowed_url, normalize_url, sanitize

log = logging.getLogger(__name__)

_REDIRECT_PARAMS = ("redirect_url", "url")


@dataclass(frozen=True)
class SearchResult:
    title: str
    url: str
    snippet: str
    engine: str


@dataclass
class SearchOutcome:
    results: list[SearchResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    engines_total: int = 0
    engines_answered: int = 0  # returned at least one result
    engines_empty: int = 0  # reachable but returned nothing usable
    hits: dict[str, int] = field(default_factory=dict)  # url key -> number of engines that found it


def _unwrap(href: str, base_url: str) -> str:
    """Engines often wrap targets in a redirect (``?redirect_url=http://xyz.onion``)."""
    absolute = urljoin(base_url, href)
    query = parse_qs(urlparse(absolute).query)
    for key in _REDIRECT_PARAMS:
        for value in query.get(key, []):
            if value.startswith(("http://", "https://")):
                return value
    return absolute


def parse_results(
    html: str,
    engine: str,
    base_url: str,
    allow_clearnet: bool = False,
    skip_hosts: frozenset[str] = frozenset(),
) -> list[SearchResult]:
    soup = BeautifulSoup(html, "html.parser")
    own_host = urlparse(base_url).hostname or ""
    best: dict[str, SearchResult] = {}
    for anchor in soup.find_all("a", href=True):
        url = _unwrap(anchor["href"], base_url)
        if not is_allowed_url(url, allow_clearnet):
            continue
        target = urlparse(url).hostname or ""
        if target == own_host or target in skip_hosts:  # the engine's own links, other engines
            continue
        key = normalize_url(url)
        host = urlparse(url).hostname or ""
        title = sanitize(anchor.get_text(" ", strip=True), 160) or host
        container = anchor.find_parent(["li", "article"]) or anchor.parent
        para = container.find("p") if container else None
        snippet = sanitize(para.get_text(" ", strip=True), 300) if para else ""
        current = best.get(key)
        if current is None or (current.title == host and title != host):
            best[key] = SearchResult(title=title, url=url, snippet=snippet, engine=engine)
    return list(best.values())


def describe_error(exc: BaseException) -> str:
    """Short, human-readable reason a request through Tor failed."""
    if isinstance(exc, TimeoutError):
        return "timed out"
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        hint = " (the site blocks Tor or rate-limits you)" if code in (403, 429) else ""
        return f"HTTP {code}{hint}"
    if isinstance(exc, httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, httpx.ProxyError | httpx.ConnectError):
        return "offline or unreachable"
    return type(exc).__name__ + (f": {exc}" if str(exc) else "")


class TorSearcher:
    """Queries every configured engine at once and merges the answers into one ranked list."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        engines: tuple[tuple[str, str], ...],
        allow_clearnet: bool = False,
        *,
        per_host: int = 3,
        max_results: int = 40,
        concurrency: int = 8,
        timeout: float = 60.0,
    ) -> None:
        self._client = client
        self._engines = engines
        self._allow_clearnet = allow_clearnet
        self._per_host = per_host
        self._max_results = max_results
        self._sem = asyncio.Semaphore(concurrency)
        self._timeout = timeout
        self._engine_hosts = frozenset(urlparse(t).hostname or "" for _, t in engines)

    async def _one(self, name: str, template: str, query: str) -> list[SearchResult]:
        url = template.replace("{query}", quote_plus(query))
        host = urlparse(url).hostname
        async with self._sem:
            resp = await self._client.get(url)
            for _ in range(3):  # follow a few redirects, but only within the engine's own host
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                target = urljoin(url, resp.headers.get("location", ""))
                if urlparse(target).hostname != host:
                    raise RuntimeError(f"redirected to another host ({urlparse(target).hostname})")
                url = target
                resp = await self._client.get(url)
            resp.raise_for_status()
        return parse_results(resp.text, name, url, self._allow_clearnet, self._engine_hosts)

    async def _guarded(self, name: str, template: str, query: str) -> list[SearchResult]:
        return await asyncio.wait_for(self._one(name, template, query), self._timeout)

    async def search(self, query: str) -> SearchOutcome:
        outcome = SearchOutcome(engines_total=len(self._engines))
        settled = await asyncio.gather(
            *(self._guarded(name, tpl, query) for name, tpl in self._engines),
            return_exceptions=True,
        )
        merged: dict[str, SearchResult] = {}
        order: list[str] = []
        for (name, _), item in zip(self._engines, settled, strict=True):
            if isinstance(item, BaseException):
                log.warning("Search engine %s failed: %s", name, item)
                outcome.errors.append(f"{name}: {describe_error(item)}")
                continue
            if item:
                outcome.engines_answered += 1
            else:
                outcome.engines_empty += 1
            for result in item:
                key = normalize_url(result.url)
                outcome.hits[key] = outcome.hits.get(key, 0) + 1
                if key not in merged:
                    merged[key] = result
                    order.append(key)
        # Results found by several engines first, then engine order; cap per onion site.
        ranked = sorted(order, key=lambda k: -outcome.hits[k])  # stable sort keeps engine order
        per_host: dict[str, int] = {}
        for key in ranked:
            host = urlparse(merged[key].url).hostname or ""
            if per_host.get(host, 0) >= self._per_host:
                continue
            per_host[host] = per_host.get(host, 0) + 1
            outcome.results.append(merged[key])
            if len(outcome.results) >= self._max_results:
                break
        return outcome


def make_tor_client(proxy: str, timeout: float) -> httpx.AsyncClient:
    """HTTP client that routes everything through Tor, resolving DNS inside Tor (socks5h)."""
    return httpx.AsyncClient(
        proxy=proxy,
        timeout=httpx.Timeout(timeout, connect=30.0),
        follow_redirects=False,  # redirects are followed manually so every hop is validated
        trust_env=False,  # ignore HTTP(S)_PROXY from the environment
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1",
            "Accept-Language": "en-US,en;q=0.5",
        },
        limits=httpx.Limits(max_connections=10),
    )


__all__ = ["SearchOutcome", "SearchResult", "TorSearcher", "make_tor_client", "parse_results"]
