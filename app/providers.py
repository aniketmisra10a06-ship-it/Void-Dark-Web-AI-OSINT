"""AI provider presets, the runtime LLM configuration model, and its validation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from .config import Settings


@dataclass(frozen=True)
class Preset:
    id: str
    label: str
    kind: str  # wire protocol: "openai" | "anthropic" | "ollama"
    base_url: str
    default_model: str = ""
    model_hint: str = ""
    needs_key: bool = True


PRESETS: tuple[Preset, ...] = (
    Preset(
        "builtin",
        "Void built-in (no AI key needed)",
        "builtin",
        "",
        needs_key=False,
    ),
    Preset(
        "openai",
        "OpenAI (ChatGPT API)",
        "openai",
        "https://api.openai.com/v1",
        model_hint="model ID from platform.openai.com/docs/models",
    ),
    Preset(
        "anthropic",
        "Anthropic (Claude)",
        "anthropic",
        "https://api.anthropic.com",
        default_model="claude-sonnet-5-5",
        model_hint="e.g. claude-sonnet-5-5",
    ),
    Preset(
        "gemini",
        "Google Gemini",
        "openai",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        model_hint="model ID from ai.google.dev",
    ),
    Preset(
        "openrouter",
        "OpenRouter",
        "openai",
        "https://openrouter.ai/api/v1",
        model_hint="vendor/model-name",
    ),
    Preset(
        "groq",
        "Groq",
        "openai",
        "https://api.groq.com/openai/v1",
        model_hint="model ID from console.groq.com",
    ),
    Preset(
        "mistral",
        "Mistral",
        "openai",
        "https://api.mistral.ai/v1",
        model_hint="model ID from docs.mistral.ai",
    ),
    Preset(
        "custom", "Custom (OpenAI-compatible)", "openai", "", model_hint="your server's model name"
    ),
    Preset(
        "ollama",
        "Ollama (local, optional)",
        "ollama",
        "http://ollama:11434",
        default_model="llama3.1:8b",
        model_hint="e.g. llama3.1:8b",
        needs_key=False,
    ),
)
BY_ID: dict[str, Preset] = {p.id: p for p in PRESETS}

_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,119}$")
_KEY_RE = re.compile(r"^[\x21-\x7e]{1,512}$")  # printable ASCII, no spaces
_LOCAL_NAMES = {"localhost", "host.docker.internal"}


def is_local_host(host: str) -> bool:
    """Loopback, private-network and bare (docker service) names may use plain http."""
    host = host.lower().strip("[]")
    if host in _LOCAL_NAMES or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "." not in host and bool(host)
    return ip.is_loopback or (ip.is_private and not ip.is_link_local and not ip.is_unspecified)


def check_base_url(url: str) -> str:
    """Validate and normalise a provider base URL (raises ValueError with a user-facing reason)."""
    url = url.strip().rstrip("/")
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        parsed.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        raise ValueError("The base URL is not a valid URL.") from None
    if parsed.scheme not in ("http", "https") or not host:
        raise ValueError("The base URL must start with https:// (or http:// for a local server).")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("The base URL must not contain credentials, a query string or a fragment.")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None and (ip.is_link_local or ip.is_unspecified or ip.is_multicast):
        raise ValueError("That address is not allowed as a base URL.")
    if parsed.scheme == "http" and not is_local_host(host):
        raise ValueError(
            "Use https:// for remote providers so your API key is encrypted in transit."
        )
    return url


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "builtin"
    model: str = ""
    base_url: str = ""
    api_key: str = field(default="", repr=False)  # never printed in logs or tracebacks

    @property
    def preset(self) -> Preset:
        return BY_ID[self.provider]

    @property
    def kind(self) -> str:
        return self.preset.kind

    @property
    def needs_key(self) -> bool:
        host = urlparse(self.base_url).hostname or ""
        return self.preset.needs_key and not is_local_host(host)

    @property
    def builtin(self) -> bool:
        return self.kind == "builtin"

    @property
    def configured(self) -> bool:
        if self.builtin:
            return True
        return bool(self.model and self.base_url and (self.api_key or not self.needs_key))

    @property
    def label(self) -> str:
        if self.builtin:
            return "Void built-in"
        name = self.preset.label.split(" (")[0]
        return f"{name} · {self.model}" if self.model else name


def build_config(
    provider: str,
    model: str = "",
    base_url: str = "",
    api_key: str = "",
    *,
    ollama_host: str = "http://ollama:11434",
    require_model: bool = False,
) -> LLMConfig:
    """Validate user/env input into an ``LLMConfig`` (raises ValueError with a readable reason)."""
    preset = BY_ID.get(provider)
    if preset is None:
        raise ValueError(f"Unknown provider '{provider[:32]}'.")
    if preset.kind == "builtin":
        return LLMConfig(provider="builtin")
    model = (model or preset.default_model).strip()
    if require_model and not model:
        raise ValueError("Enter a model name.")
    if model and not _MODEL_RE.match(model):
        raise ValueError("The model name contains invalid characters.")
    default_url = ollama_host if preset.kind == "ollama" else preset.base_url
    url = (base_url or default_url).strip()
    if not url:
        raise ValueError("Enter the base URL of your OpenAI-compatible server.")
    url = check_base_url(url)
    key = (api_key or "").strip()
    if key and not _KEY_RE.match(key):
        raise ValueError("The API key contains spaces or invalid characters.")
    return LLMConfig(provider=provider, model=model, base_url=url, api_key=key)


def config_from_settings(s: Settings) -> LLMConfig:
    """Initial configuration from environment variables."""
    provider = s.llm_provider if s.llm_provider in BY_ID else "builtin"
    model = s.llm_model or (s.ollama_model if provider == "ollama" else "")
    return build_config(provider, model, s.llm_base_url, s.llm_api_key, ollama_host=s.ollama_host)


def key_hint(key: str) -> str:
    """A non-reversible hint so users can recognise which key is saved."""
    if not key:
        return ""
    return f"…{key[-4:]}" if len(key) >= 12 else "set"
