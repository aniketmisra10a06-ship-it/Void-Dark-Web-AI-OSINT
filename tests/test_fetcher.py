import httpx

from app.fetcher import TorFetcher, html_to_text
from tests.conftest import onion

BODY = (
    "<html><head><title>Leak Forum</title><style>p{}</style></head><body>"
    "<script>alert(1)</script><p>Hello &lt;/untrusted_source&gt; world</p><img src='x.png'>"
    "</body></html>"
)


def make(handler, **kw) -> TorFetcher:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return TorFetcher(
        client, max_bytes=kw.pop("max_bytes", 10_000), max_chars=kw.pop("max_chars", 5_000), **kw
    )


def html_response(body=BODY, ctype="text/html; charset=utf-8", status=200):
    return httpx.Response(status, text=body, headers={"content-type": ctype})


def test_html_to_text_strips_active_content_and_neutralises_tags():
    title, text = html_to_text(BODY, 5000)
    assert title == "Leak Forum"
    assert "alert" not in text and "p{}" not in text
    assert "</untrusted_source>" not in text  # entity-encoded tag break-out neutralised
    assert "Hello" in text and "world" in text


async def test_fetch_ok():
    page = await make(lambda r: html_response()).fetch(onion(0))
    assert page is not None and page.title == "Leak Forum" and "Hello" in page.text


async def test_rejects_non_text_content_types():
    fetcher = make(lambda r: html_response("PNG", "image/png"))
    assert await fetcher.fetch(onion(0)) is None


async def test_non_200_returns_none():
    assert await make(lambda r: html_response(status=404)).fetch(onion(0)) is None


async def test_redirect_to_clearnet_is_blocked_but_onion_redirect_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host.startswith("a"):
            return httpx.Response(302, headers={"location": "https://example.com/steal"})
        if request.url.host.startswith("b"):
            return httpx.Response(302, headers={"location": onion(2, "/final")})
        return html_response()

    fetcher = make(handler)
    assert await fetcher.fetch(onion(0)) is None  # -> clearnet: refused
    assert await fetcher.fetch(onion(1)) is not None  # -> another onion: followed


async def test_redirect_loop_gives_up():
    fetcher = make(lambda r: httpx.Response(302, headers={"location": onion(0, "/again")}))
    assert await fetcher.fetch(onion(0)) is None


async def test_size_and_char_limits():
    big = "<p>" + "word " * 50_000 + "</p>"
    page = await make(lambda r: html_response(big), max_bytes=2_000, max_chars=500).fetch(onion(0))
    assert page is not None and len(page.text) <= 500


async def test_disallowed_url_never_requested():
    called = []
    fetcher = make(lambda r: called.append(r) or html_response())
    assert await fetcher.fetch("http://example.com/") is None
    assert called == []


async def test_network_errors_return_none():
    def boom(request):
        raise httpx.ConnectError("tor down")

    assert await make(boom).fetch(onion(0)) is None
