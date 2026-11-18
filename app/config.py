"""Runtime configuration, read once from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Public onion search engines (the same set the open-source Robin project queries).
# Liveness varies day to day, which is why a query goes to all of them at once.
_ENGINE_LIST = (
    ("ahmia", "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd", "/search/?q={query}"),
    ("onionland", "3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad", "/search?q={query}"),
    (
        "torgle",
        "iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad",
        "/torgle/?query={query}",
    ),
    (
        "amnesia",
        "amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad",
        "/search?query={query}",
    ),
    ("kaizer", "kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid", "/search?q={query}"),
    ("anima", "anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid", "/search?q={query}"),
    ("tornado", "tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd", "/search?q={query}"),
    ("tornet", "tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid", "/search?q={query}"),
    (
        "torland",
        "torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd",
        "/index.php?a=search&q={query}",
    ),
    ("findtor", "findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd", "/search?q={query}"),
    (
        "excavator",
        "2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad",
        "/search?query={query}",
    ),
    (
        "onionway",
        "oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad",
        "/search.php?s={query}",
    ),
    ("tor66", "tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid", "/search?q={query}"),
    (
        "oss",
        "3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd",
        "/oss/index.php?search={query}",
    ),
    ("torgol", "torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd", "/?q={query}"),
    (
        "deepsearches",
        "searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad",
        "/search?q={query}",
    ),
)
DEFAULT_ENGINES = ",".join(f"{n}=http://{h}.onion{path}" for n, h, path in _ENGINE_LIST)
DEFAULT_BLOCKLIST = Path(__file__).resolve().parent.parent / "config" / "blocklist.txt"


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _num(name: str, default: float, cast=int):
    raw = os.environ.get(name, "").strip()
    try:
        return cast(raw) if raw else default
    except ValueError:
        return default


def parse_engines(raw: str) -> tuple[tuple[str, str], ...]:
    """Parse ``name=url_template,name2=url_template2``. Templates must contain ``{query}``."""
    engines: list[tuple[str, str]] = []
    for part in raw.split(","):
        name, sep, template = part.strip().partition("=")
        if sep and "{query}" in template and template.startswith(("http://", "https://")):
            engines.append((name.strip(), template.strip()))
    return tuple(engines)


@dataclass(frozen=True)
class Settings:
    # LLM: any OpenAI-compatible API, Anthropic, or (optionally) local Ollama.
    llm_provider: str = "builtin"
    llm_model: str = ""
    llm_base_url: str = ""
    llm_api_key: str = field(default="", repr=False)
    llm_timeout: float = 300.0
    allow_ui_config: bool = True  # let the browser UI change the provider / API key
    # Ollama-only settings (used when the provider is "ollama")
    ollama_host: str = "http://ollama:11434"
    ollama_model: str = "llama3.1:8b"
    num_ctx: int = 8192

    # Tor / crawling
    # "auto" = Void starts and manages its own Tor process (no Tor Browser or daemon needed).
    # Set e.g. socks5h://127.0.0.1:9050 to use an existing Tor instead.
    tor_proxy: str = "auto"
    tor_binary: str = "tor"
    tor_check_url: str = "https://check.torproject.org/api/ip"
    search_engines: tuple[tuple[str, str], ...] = field(
        default_factory=lambda: parse_engines(DEFAULT_ENGINES)
    )
    max_results: int = 40  # unique results kept after merging all engines
    max_fetch: int = 8  # pages read and analysed
    crawl_links: int = 8  # extra pages reached by following links out of the pages read
    per_host: int = 3  # at most this many results from one onion site
    engine_concurrency: int = 8
    fetch_timeout: float = 45.0
    max_bytes: int = 400_000
    max_chars_per_page: int = 4000
    allow_clearnet: bool = False

    # Safety / access
    redact_pii: bool = True
    access_token: str = field(default="", repr=False)
    # Without an access token, only these Host headers are served (blocks DNS-rebinding attacks).
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")
    max_concurrent: int = 2
    blocklist_file: Path | None = DEFAULT_BLOCKLIST

    # Storage
    data_dir: Path = Path("data")

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ.get
        engines = parse_engines(env("SEARCH_ENGINES", "")) or parse_engines(DEFAULT_ENGINES)
        blocklist = env("BLOCKLIST_FILE", "").strip()
        provider = env("LLM_PROVIDER", "").strip().lower() or cls.llm_provider
        vendor_key = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}.get(
            provider, ""
        )
        hosts = tuple(h.strip().lower() for h in env("ALLOWED_HOSTS", "").split(",") if h.strip())
        return cls(
            llm_provider=provider,
            llm_model=env("LLM_MODEL", "").strip(),
            llm_base_url=env("LLM_BASE_URL", "").strip(),
            llm_api_key=(
                env("LLM_API_KEY", "") or (env(vendor_key, "") if vendor_key else "")
            ).strip(),
            allow_ui_config=_bool(env("ALLOW_UI_CONFIG"), cls.allow_ui_config),
            allowed_hosts=hosts or cls.allowed_hosts,
            ollama_host=env("OLLAMA_HOST", cls.ollama_host).rstrip("/"),
            ollama_model=env("OLLAMA_MODEL", cls.ollama_model),
            num_ctx=_num("OLLAMA_NUM_CTX", cls.num_ctx),
            llm_timeout=_num("LLM_TIMEOUT", cls.llm_timeout, float),
            tor_proxy=env("TOR_PROXY", cls.tor_proxy).strip() or cls.tor_proxy,
            tor_binary=env("TOR_BINARY", cls.tor_binary),
            crawl_links=max(0, _num("CRAWL_LINKS", cls.crawl_links)),
            per_host=max(1, _num("PER_HOST", cls.per_host)),
            engine_concurrency=max(1, _num("ENGINE_CONCURRENCY", cls.engine_concurrency)),
            tor_check_url=env("TOR_CHECK_URL", cls.tor_check_url),
            search_engines=engines,
            max_results=max(1, _num("MAX_RESULTS", cls.max_results)),
            max_fetch=max(1, _num("MAX_FETCH", cls.max_fetch)),
            fetch_timeout=_num("FETCH_TIMEOUT", cls.fetch_timeout, float),
            max_bytes=_num("MAX_BYTES", cls.max_bytes),
            max_chars_per_page=_num("MAX_CHARS_PER_PAGE", cls.max_chars_per_page),
            allow_clearnet=_bool(env("ALLOW_CLEARNET"), cls.allow_clearnet),
            redact_pii=_bool(env("REDACT_PII"), cls.redact_pii),
            access_token=env("ACCESS_TOKEN", "").strip(),
            max_concurrent=max(1, _num("MAX_CONCURRENT", cls.max_concurrent)),
            blocklist_file=Path(blocklist) if blocklist else DEFAULT_BLOCKLIST,
            data_dir=Path(env("DATA_DIR", "") or cls.data_dir),
        )
