"""Fetch pages through Tor as *text only*: no images, no downloads, strict size limits."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .safety import is_allowed_url, sanitize

log = logging.getLogger(__name__)

ALLOWED_CONTENT_TYPES = {"text/html", "application/xhtml+xml", "text/plain"}
MAX_REDIRECTS = 3
_STRIP_TAGS = ("script", "style", "noscript", "iframe", "svg", "img", "video", "audio", "object")


@dataclass(frozen=True)
class Page:
    url: str
    title: str
    text: str
    links: tuple[tuple[str, str], ...] = ()  # (absolute url, anchor text) of allowed outbound links


def html_to_text(raw: str, limit: int) -> tuple[str, str]:
    soup = BeautifulSoup(raw, "html.parser")
    title = sanitize(soup.title.get_text(" ", strip=True), 160) if soup.title else ""
    for tag in soup(_STRIP_TAGS):
        tag.decompose()
    return title, sanitize(soup.get_text("\n", strip=True), limit)


def extract_links(
    raw: str, base_url: str, allow_clearnet: bool = False, limit: int = 60
) -> tuple[tuple[str, str], ...]:
    """Outbound links to other allowed hosts, with their anchor text (for one-hop crawling)."""
    base_host = urlparse(base_url).hostname
    soup = BeautifulSoup(raw, "html.parser")
    seen: dict[str, str] = {}
    for a in soup.find_all("a", href=True):
        url = urljoin(base_url, a["href"]).split("#")[0]
        host = urlparse(url).hostname
        if host == base_host or url in seen or not is_allowed_url(url, allow_clearnet):
            continue
        seen[url] = sanitize(a.get_text(" ", strip=True), 120)
        if len(seen) >= limit:
            break
    return tuple(seen.items())


class TorFetcher:
    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        max_bytes: int,
        max_chars: int,
        allow_clearnet: bool = False,
        concurrency: int = 6,
    ) -> None:
        self._client = client
        self._max_bytes = max_bytes
        self._max_chars = max_chars
        self._allow_clearnet = allow_clearnet
        self._sem = asyncio.Semaphore(concurrency)

    async def fetch(self, url: str) -> Page | None:
        current = url
        try:
            async with self._sem:
                for _ in range(MAX_REDIRECTS + 1):
                    if not is_allowed_url(current, self._allow_clearnet):
                        return None
                    async with self._client.stream("GET", current) as resp:
                        if resp.status_code in (301, 302, 303, 307, 308):
                            location = resp.headers.get("location")
                            if not location:
                                return None
                            current = urljoin(current, location)
                            continue
                        if resp.status_code != 200:
                            return None
                        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                        if ctype not in ALLOWED_CONTENT_TYPES:
                            return None
                        buf = bytearray()
                        async for chunk in resp.aiter_bytes():
                            buf.extend(chunk)
                            if len(buf) >= self._max_bytes:
                                break
                        raw = bytes(buf[: self._max_bytes]).decode(
                            resp.encoding or "utf-8", errors="replace"
                        )
                    links = extract_links(raw, current, self._allow_clearnet)
                    title, text = html_to_text(raw, self._max_chars)
                    return Page(url=url, title=title, text=text, links=links) if text else None
        except (httpx.HTTPError, OSError, LookupError) as exc:
            log.info("Fetch failed for %s: %s", url, type(exc).__name__)
        return None

    async def fetch_many(self, urls: list[str]) -> dict[str, Page | None]:
        pages = await asyncio.gather(*(self.fetch(u) for u in urls))
        return dict(zip(urls, pages, strict=True))
