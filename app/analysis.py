"""The built-in analyst: extractive threat-intelligence reports with no AI model involved.

Everything here is deterministic and runs locally: keyword extraction, relevance scoring,
indicator extraction (CVEs, hashes, crypto wallets, onion hosts, ransomware group names) and a
templated report. It never invents text: every finding is a sentence copied from a source, with a
citation, and the report says plainly what it could not establish.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

from .prompts import SourceDoc
from .safety import defang, sanitize

_STOPWORDS = frozenset(
    [
        "a",
        "about",
        "above",
        "after",
        "again",
        "all",
        "also",
        "am",
        "an",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "because",
        "been",
        "before",
        "being",
        "below",
        "between",
        "both",
        "but",
        "by",
        "can",
        "could",
        "did",
        "do",
        "does",
        "doing",
        "down",
        "during",
        "each",
        "few",
        "for",
        "from",
        "further",
        "had",
        "has",
        "have",
        "having",
        "he",
        "her",
        "here",
        "hers",
        "him",
        "his",
        "how",
        "i",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "just",
        "me",
        "more",
        "most",
        "my",
        "no",
        "nor",
        "not",
        "of",
        "off",
        "on",
        "once",
        "only",
        "or",
        "other",
        "our",
        "out",
        "over",
        "own",
        "same",
        "she",
        "should",
        "so",
        "some",
        "such",
        "than",
        "that",
        "the",
        "their",
        "them",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "through",
        "to",
        "too",
        "under",
        "until",
        "up",
        "very",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "while",
        "who",
        "whom",
        "why",
        "will",
        "with",
        "would",
        "you",
        "your",
        "tell",
        "show",
        "find",
        "give",
        "search",
        "look",
        "looking",
        "lookup",
        "please",
        "info",
        "information",
        "latest",
        "recent",
        "news",
        "data",
        "anything",
        "something",
        "related",
        "regarding",
        "exposed",
        "leaked",
        "leak",
        "leaks",
    ]
)
_STOPWORDS |= {
    "dark",
    "web",
    "darkweb",
    "darknet",
    "deep",
    "onion",
    "tor",
    "being",
    "going",
    "extorted",
}
_GREETING = re.compile(
    r"^\s*(hi|hello|hey|yo|hola|thanks|thank you|ok|okay|test|help|who are you|what can you do)"
    r"\W*$",
    re.IGNORECASE,
)

# Open-ended, best-effort lexicon of well-known extortion groups. Not exhaustive.
GROUPS = [
    "LockBit",
    "BlackCat",
    "ALPHV",
    "Cl0p",
    "Clop",
    "Akira",
    "Black Basta",
    "BlackBasta",
    "Conti",
    "REvil",
    "Sodinokibi",
    "Hive",
    "Medusa",
    "Rhysida",
    "8Base",
    "BianLian",
    "Qilin",
    "Play",
    "Royal",
    "RansomHub",
    "DragonForce",
    "Lynx",
    "Interlock",
    "Everest",
    "Karakurt",
    "Vice Society",
    "Scattered Spider",
    "ShinyHunters",
    "LAPSUS\\$",
    "Babuk",
    "Ragnar Locker",
    "Hunters International",
    "Cactus",
    "Trigona",
    "Snatch",
    "Stormous",
    "NoEscape",
    "Nitrogen",
    "Killsec",
    "Meow",
]
_GROUP_RE = re.compile(r"\b(" + "|".join(GROUPS) + r")\b", re.IGNORECASE)

_INDICATORS: dict[str, re.Pattern[str]] = {
    "CVE": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "SHA-256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "SHA-1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "MD5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "Bitcoin wallet": re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "Monero wallet": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "IPv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "Onion host": re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE),
}
_PRIVATE_IP = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.)")

# Signal vocabulary used for the heuristic classification and risk score.
SIGNALS: dict[str, tuple[str, ...]] = {
    "ransomware or extortion": (
        "ransomware",
        "ransom",
        "extortion",
        "encrypted",
        "decryptor",
        "leak site",
        "double extortion",
        "data will be published",
    ),
    "data leak or breach": (
        "leaked",
        "leak",
        "breach",
        "breached",
        "dump",
        "database",
        "exfiltrated",
        "stolen data",
        "compromised",
        "combolist",
        "stealer logs",
    ),
    "credentials for sale": (
        "credentials",
        "logins",
        "passwords",
        "accounts for sale",
        "stealer",
        "infostealer",
        "cookies",
        "session tokens",
    ),
    "initial access or exploits": (
        "initial access",
        "rdp",
        "vpn access",
        "exploit",
        "zero-day",
        "0day",
        "vulnerability",
        "webshell",
        "rce",
        "cve-",
    ),
    "malware or tooling": (
        "malware",
        "botnet",
        "loader",
        "rat ",
        "stealer",
        "builder",
        "crypter",
        "phishing kit",
    ),
}
_ACTIONS: dict[str, tuple[str, ...]] = {
    "ransomware or extortion": (
        "Check whether the named victim or domain is yours; if so, invoke your incident-response plan.",
        "Verify offline, tested backups and restrict internet-exposed remote access (RDP/VPN).",
    ),
    "data leak or breach": (
        "Confirm with your own logs whether the data could belong to you before acting on it.",
        "Prepare notification duties (legal, regulators, customers) in case it is confirmed.",
    ),
    "credentials for sale": (
        "Force password resets and revoke sessions for affected accounts; enforce MFA.",
        "Check your identity provider for impossible-travel and new-device sign-ins.",
    ),
    "initial access or exploits": (
        "Patch or mitigate any CVE mentioned and review exposure of the named services.",
        "Hunt for web shells and unexpected remote-access tools on exposed systems.",
    ),
    "malware or tooling": (
        "Add the listed indicators to detection tooling and search endpoint telemetry for them.",
    ),
}


# --------------------------------------------------------------------------- query handling


def is_smalltalk(message: str) -> bool:
    return bool(_GREETING.match(message)) or len(message.strip()) < 3


def keywords(text: str, limit: int = 6) -> list[str]:
    """Distinctive search terms: stop-words removed, order kept, duplicates dropped."""
    out: list[str] = []
    for tok in re.findall(r"[A-Za-z0-9][A-Za-z0-9.\-_$]{1,}", text):
        low = tok.lower().strip(".-_")
        if len(low) < 2 or low in _STOPWORDS or low in out:
            continue
        out.append(low)
        if len(out) >= limit:
            break
    return out


def refine_query(question: str) -> str:
    """Short keyword query for the search engines (keeps names, domains and CVE ids)."""
    terms = keywords(question, 5)
    return " ".join(terms) if terms else question[:80].strip()


def relevance(text: str, terms: list[str]) -> int:
    """How strongly a text matches the query terms: distinct hits weigh more than repeats."""
    if not terms:
        return 0
    low = text.lower()
    score = 0
    for t in terms:
        n = low.count(t)
        if n:
            score += 3 + min(n, 5)
    return score


# --------------------------------------------------------------------------- extraction


@dataclass
class Indicators:
    by_type: dict[str, list[str]] = field(default_factory=dict)
    groups: list[str] = field(default_factory=list)

    def empty(self) -> bool:
        return not self.by_type and not self.groups


def extract_indicators(texts: list[str], cap: int = 8) -> Indicators:
    found: dict[str, Counter[str]] = {}
    groups: Counter[str] = Counter()
    for text in texts:
        for name, rx in _INDICATORS.items():
            for value in rx.findall(text):
                if name in ("Onion host", "CVE", "SHA-256", "SHA-1", "MD5"):
                    value = value.upper() if name == "CVE" else value.lower()
                if name == "IPv4" and _PRIVATE_IP.match(value):
                    continue
                found.setdefault(name, Counter())[value] += 1
        for m in _GROUP_RE.findall(text):
            groups[m] += 1
    return Indicators(
        by_type={k: [v for v, _ in c.most_common(cap)] for k, c in found.items() if c},
        groups=[g for g, _ in groups.most_common(cap)],
    )


_SENT = re.compile(r"(?<=[.!?])\s+|\n+")


def best_sentences(text: str, terms: list[str], limit: int = 2) -> list[str]:
    """The sentences that mention the most query terms (and signal words)."""
    scored: list[tuple[int, int, str]] = []
    signal_words = [w for words in SIGNALS.values() for w in words]
    for idx, raw in enumerate(_SENT.split(text)):
        s = sanitize(raw, 400).strip()
        if len(s) < 25 or len(s.split()) < 4:
            continue
        low = s.lower()
        hit = sum(1 for t in terms if t in low)
        if terms and hit == 0:
            continue
        sig = sum(1 for w in signal_words if w in low)
        scored.append((hit * 3 + min(sig, 3), -idx, s))
    scored.sort(reverse=True)
    out: list[str] = []
    for _, _, s in scored:
        if all(s[:60].lower() != o[:60].lower() for o in out):
            out.append(s)
        if len(out) >= limit:
            break
    return out


def classify(texts: list[str]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for text in texts:
        low = text.lower()
        for label, words in SIGNALS.items():
            if any(w in low for w in words):
                counts[label] += 1
    return counts


def _defang_text(text: str) -> str:
    """Defang any URL or onion host that appears inside a copied sentence."""
    text = re.sub(r"https?://\S+", lambda m: defang(m.group(0)), text)
    return re.sub(r"\b([a-z2-7]{56})\.onion\b", r"\1[.]onion", text, flags=re.IGNORECASE)


# --------------------------------------------------------------------------- the report


@dataclass(frozen=True)
class RunStats:
    engines_total: int = 0
    engines_answered: int = 0
    results_total: int = 0
    pages_read: int = 0
    pages_crawled: int = 0  # reached by following links from a result page


def build_report(question: str, docs: list[SourceDoc], terms: list[str], stats: RunStats) -> str:
    """A cited report assembled only from the sources' own text."""
    texts = [d.text for d in docs]
    matched = [d for d in docs if relevance(d.text, terms) > 0]
    signals = classify([d.text for d in matched] or texts)
    ind = extract_indicators(texts)
    lines: list[str] = []

    # ---- summary
    reach = (
        f"{stats.engines_answered} of {stats.engines_total} search engines answered "
        f"({stats.results_total} unique results)"
        if stats.engines_total
        else "no search engines were queried"
    )
    crawl = f", {stats.pages_crawled} reached by following links" if stats.pages_crawled else ""
    lines += ["## Summary", ""]
    if matched:
        term_txt = ", ".join(f"**{t}**" for t in terms) or "your query"
        lines.append(
            f"{len(matched)} of {len(docs)} sources read mention {term_txt}. "
            f"Coverage: {reach}; {stats.pages_read} pages read{crawl}."
        )
        if signals:
            top = ", ".join(f"{k} ({v})" for k, v in signals.most_common(3))
            lines.append(f"\nThemes in the matching sources: {top}.")
    else:
        lines.append(
            f"None of the {len(docs)} sources read contain your search terms directly. "
            f"Coverage: {reach}; {stats.pages_read} pages read{crawl}. "
            "The hits are probably indirect matches from the search engines."
        )

    # ---- key findings
    lines += ["", "## Key findings", ""]
    shown = 0
    for d in sorted(docs, key=lambda d: -relevance(d.text, terms)):
        for sent in best_sentences(d.text, terms, 2):
            lines.append(f"- {_defang_text(sent)} [{d.n}]")
            shown += 1
        if shown >= 10:
            break
    if not shown:
        lines.append(
            "- No sentence in the pages read discusses the query terms. "
            "Try different keywords, a company or domain name, or the exact actor name."
        )

    # ---- indicators
    lines += ["", "## Indicators", ""]
    if ind.empty():
        lines.append(
            "- No technical indicators (CVEs, hashes, wallets, IPs) found in the pages read."
        )
    else:
        if ind.groups:
            lines.append(f"- **Threat actors / groups named:** {', '.join(ind.groups)}")
        for name, values in ind.by_type.items():
            shown_vals = ", ".join(f"`{_defang_text(v)}`" for v in values)
            lines.append(f"- **{name}:** {shown_vals}")

    # ---- risk
    level, why = _risk(len(matched), signals, ind)
    lines += ["", "## Risk assessment", "", f"**{level}**: {why}"]

    # ---- actions
    lines += ["", "## Recommended defensive actions", ""]
    actions: list[str] = []
    for label, _ in signals.most_common(3):
        actions += list(_ACTIONS.get(label, ()))
    actions += [
        "Treat everything here as a lead: confirm against your own logs before acting.",
        "Do not open the listed sources in a normal browser or download anything from them.",
    ]
    for a in dict.fromkeys(actions):
        lines.append(f"- {a}")

    # ---- limits
    lines += [
        "",
        "## Confidence and limits",
        "",
        "- Written by Void's built-in extractive analyst: it copies and counts what the "
        "sources say. It does not reason, verify claims or judge source quality.",
        "- Dark-web pages are often stale, duplicated or deliberately false. "
        "Coverage is limited to the engines that answered and the pages that loaded.",
        "- Want a fluent narrative summary? Add an AI key under *AI model (optional)*.",
    ]
    return "\n".join(lines)


def _risk(matches: int, signals: Counter[str], ind: Indicators) -> tuple[str, str]:
    strong = signals.get("ransomware or extortion", 0) + signals.get("data leak or breach", 0)
    cred = signals.get("credentials for sale", 0) + signals.get("initial access or exploits", 0)
    if matches >= 2 and (strong >= 2 or (strong and cred)):
        return "High", (
            f"{matches} sources mention your terms alongside extortion, leak or access-sale language."
        )
    if matches >= 1 and (strong or cred or ind.groups):
        return "Medium", (
            "your terms appear in sources that also contain breach, extortion or access-sale "
            "language; this is not proof that you are affected."
        )
    if matches >= 1:
        return "Low", "your terms appear, but without leak, extortion or access-sale context."
    return "Low", "no source read mentions your terms."


def chunk(text: str, size: int = 160) -> Iterator[str]:
    """Split a finished report into stream-sized pieces (on line boundaries when possible)."""
    buf = ""
    for line in text.splitlines(keepends=True):
        if len(buf) + len(line) > size and buf:
            yield buf
            buf = ""
        buf += line
    if buf:
        yield buf


SMALLTALK_REPLY = (
    "Hi! I'm Void. Ask me about a company, domain, threat actor, ransomware group or CVE and "
    "I'll search many dark-web search engines through Tor, read the matching pages and write a "
    "cited report.\n\nTry: *ransomware healthcare*, *acme.com credentials*, or *LockBit leak site*."
)
