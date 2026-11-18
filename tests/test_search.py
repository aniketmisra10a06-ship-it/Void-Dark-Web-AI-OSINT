import httpx

from app.search import TorSearcher, parse_results
from tests.conftest import onion

HTML = f"""
<ul>
  <li class="result"><h4>
      <a href="/search/redirect?search_term=x&redirect_url={onion(0, "/forum")}">Forum Title</a>
      </h4>
      <p>Some snippet text</p><cite>aaaa</cite></li>
  <li class="result"><h4><a href="{onion(1)}">Second Site</a></h4><p>Another snippet</p></li>
  <li><a href="https://example.com/">Clearnet link</a></li>
  <li><a href="http://{"z" * 16}.onion/">Old v2 address</a></li>
  <li><a href="/search/redirect?redirect_url={onion(0, "/forum")}">duplicate of the first</a></li>
  <li><a href="/about">relative internal link</a></li>
</ul>
"""


def test_parse_unwraps_redirects_filters_and_dedupes():
    results = parse_results(HTML, "ahmia", "https://ahmia.fi/search/?q=x")
    assert [r.url for r in results] == [onion(0, "/forum"), onion(1)]
    assert results[0].title == "Forum Title"
    assert results[0].snippet == "Some snippet text"
    assert all(r.engine == "ahmia" for r in results)


def test_parse_empty_page():
    assert parse_results("<html></html>", "x", "https://x/") == []


async def test_searcher_encodes_query_merges_engines_and_tolerates_failure():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "broken.test":
            return httpx.Response(500)
        return httpx.Response(200, text=HTML)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    searcher = TorSearcher(
        client,
        (("good", "https://good.test/s?q={query}"), ("bad", "https://broken.test/s?q={query}")),
    )
    outcome = await searcher.search("acme corp & co")
    assert any("q=acme+corp+%26+co" in u for u in seen)
    assert len(outcome.results) == 2
    assert outcome.errors == ["bad: HTTP 500"]
    await client.aclose()


async def test_searcher_follows_same_host_redirect_but_not_cross_host():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "a.test" and request.url.path == "/search/":
            return httpx.Response(302, headers={"location": "/search/results?q=x"})
        if request.url.path == "/search/results":
            return httpx.Response(200, text=HTML)
        return httpx.Response(302, headers={"location": "http://evil.test/"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    searcher = TorSearcher(
        client, (("ok", "https://a.test/search/?q={query}"), ("x", "https://b.test/s?q={query}"))
    )
    outcome = await searcher.search("x")
    assert outcome.results
    assert outcome.errors == ["x: RuntimeError: redirected to another host (evil.test)"]


async def test_multi_engine_merge_ranks_by_agreement_caps_hosts_and_reports_stats():
    shared, only_a, only_b = onion(5), onion(6), onion(7)

    def page_for(*urls: str) -> str:
        return "<html><body>" + "".join(f'<a href="{u}/x">title {u[7:12]}</a>' for u in urls)

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "a.test":
            return httpx.Response(200, text=page_for(only_a, shared))
        if host == "b.test":
            return httpx.Response(200, text=page_for(shared, only_b))
        if host == "empty.test":
            return httpx.Response(200, text="<html></html>")
        return httpx.Response(503)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    engines = tuple((h, f"http://{h}.test/s?q={{query}}") for h in ("a", "b", "empty", "down"))
    outcome = await TorSearcher(client, engines, max_results=10).search("q")
    urls = [r.url for r in outcome.results]
    assert urls[0].startswith(shared)  # found by two engines -> first
    assert len(urls) == 3
    assert (outcome.engines_total, outcome.engines_answered, outcome.engines_empty) == (4, 2, 1)
    assert outcome.errors == ["down: HTTP 503"]


def test_parse_results_skips_the_engines_own_and_other_engines_links():
    own = onion(1)
    other_engine = onion(2)
    html = (
        f'<a href="{own}/about">about</a><a href="{other_engine}/">other</a>'
        f'<a href="{onion(3)}">hit</a>'
    )
    skip = frozenset({f"{'c' * 56}.onion"})
    got = parse_results(html, "e", f"{own}/search?q=x", skip_hosts=skip)
    assert [r.url for r in got] == [onion(3)]
