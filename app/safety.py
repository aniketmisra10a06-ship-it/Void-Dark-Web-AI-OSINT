"""Safety layer: query/content policy, URL allow-listing, redaction and defanging.

Design notes
------------
* The policy is deliberately written in plain English patterns. It does not ship
  lists of coded slang; operators extend it through ``config/blocklist.txt``.
* Anything flagged is dropped *before* it reaches the LLM, the audit log or the UI.
* This is a defence-in-depth filter, not a guarantee. Keep a human in the loop.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- policy

_MINOR = (
    r"(?:child|children|kid|kids|minor|minors|underage|under-age|preteen|toddler|infant|teen)s?"
)
_SEXUAL = r"(?:sex\w*|porn\w*|nude\w*|naked|explicit|erotic\w*)"

# Always-on rules. Case-insensitive.
CHILD_SAFETY_PATTERNS = [
    rf"\b{_MINOR}\b.{{0,40}}\b{_SEXUAL}\b",
    rf"\b{_SEXUAL}\b.{{0,40}}\b{_MINOR}\b",
    r"\bcsam\b",
    r"\bchild\s+(?:abuse|exploitation)\s+(?:material|images?|videos?|content)\b",
]

_ACQUIRE = r"(?:buy|purchase|order|hire|rent|acquire|where\s+(?:can\s+i\s+|to\s+)(?:get|find|buy))"
_ILLEGAL_GOODS = (
    r"(?:firearms?|guns?|weapons?|explosives?|hit\s?men|hitman|assassins?|contract\s+killers?|"
    r"fentanyl|cocaine|heroin|methamphetamine|counterfeit\s+\w+|"
    r"forged\s+(?:passports?|documents?|ids?)|stolen\s+(?:cards?|credit\s+cards?|identities|accounts?))"
)
# Only applied to user queries (not to scraped content).
PURCHASE_INTENT_PATTERNS = [rf"\b{_ACQUIRE}\b.{{0,40}}\b{_ILLEGAL_GOODS}\b"]


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str = ""


ALLOWED = Verdict(True)


def _compile(patterns: list[str]) -> list[re.Pattern[str]]:
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE | re.DOTALL))
        except re.error as exc:
            log.warning("Ignoring invalid blocklist pattern %r: %s", p, exc)
    return compiled


def load_patterns(path: Path | None) -> list[str]:
    if not path or not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


class SafetyPolicy:
    def __init__(self, extra_patterns: list[str] | None = None) -> None:
        self._child = _compile(CHILD_SAFETY_PATTERNS)
        self._purchase = _compile(PURCHASE_INTENT_PATTERNS)
        self._extra = _compile(extra_patterns or [])

    @classmethod
    def from_file(cls, path: Path | None) -> SafetyPolicy:
        return cls(load_patterns(path))

    def check_query(self, query: str) -> Verdict:
        if any(p.search(query) for p in self._child):
            return Verdict(False, "child-safety")
        if any(p.search(query) for p in self._purchase):
            return Verdict(False, "illegal-acquisition")
        if any(p.search(query) for p in self._extra):
            return Verdict(False, "operator-blocklist")
        return ALLOWED

    def check_content(self, text: str) -> Verdict:
        """Check scraped text (page body, title, snippet)."""
        if any(p.search(text) for p in self._child):
            return Verdict(False, "child-safety")
        if any(p.search(text) for p in self._extra):
            return Verdict(False, "operator-blocklist")
        return ALLOWED


# --------------------------------------------------------------------------- URLs

_ONION_HOST = re.compile(r"^(?:[a-z0-9-]+\.)*[a-z2-7]{56}\.onion$")  # v3 onion services only
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".lan", ".home.arpa")


def is_allowed_url(url: str, allow_clearnet: bool = False) -> bool:
    """Only http(s) URLs on v3 .onion hosts (or public hostnames if explicitly enabled)."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        parsed.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not host:
        return False
    if parsed.username or parsed.password:
        return False
    if _ONION_HOST.match(host):
        return True
    if not allow_clearnet:
        return False
    try:
        ipaddress.ip_address(host)
        return False  # no IP literals
    except ValueError:
        pass
    return "." in host and host != "localhost" and not host.endswith(_BLOCKED_SUFFIXES)


def normalize_url(url: str) -> str:
    p = urlparse(url)
    netloc = (p.hostname or "").lower() + (f":{p.port}" if p.port else "")
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", "", p.query, ""))


def defang(url: str) -> str:
    """Make a URL non-clickable and non-resolvable when displayed (hxxp://abc[.]onion)."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


# --------------------------------------------------------------------------- text hygiene

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SECRET = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+")


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def sanitize(text: str, limit: int | None = None) -> str:
    """Strip control/bidi characters, neutralise angle brackets and collapse whitespace."""
    text = _CONTROL.sub("", text)
    text = text.replace("<", "‹").replace(">", "›")  # blocks tag break-outs in prompts
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:limit] if limit else text


def redact(text: str) -> str:
    """Mask credentials, card numbers and the local part of email addresses.

    The email *domain* is kept on purpose: knowing that ``@yourcompany.com`` addresses
    appear in a leak is the useful signal; the individual mailbox is not.
    """
    text = _SECRET.sub(lambda m: f"{m.group(1)}: [redacted]", text)
    text = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)

    def _card(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group())
        return "[card redacted]" if 13 <= len(digits) <= 19 and _luhn(digits) else m.group()

    return _CARD.sub(_card, text)
