from app.analysis import (
    RunStats,
    build_report,
    chunk,
    extract_indicators,
    is_smalltalk,
    keywords,
    refine_query,
    relevance,
)
from app.prompts import SourceDoc
from tests.conftest import onion


def test_refine_query_keeps_names_and_drops_filler():
    q = refine_query("Please tell me what leaked about acme.com in the latest breach")
    assert "acme.com" in q and "breach" in q and "please" not in q.split()
    assert len(q.split()) <= 5
    assert refine_query("CVE-2024-1234 exploit") == "cve-2024-1234 exploit"


def test_smalltalk_detection():
    assert is_smalltalk("hi") and is_smalltalk("Thanks!") and is_smalltalk("?")
    assert not is_smalltalk("ransomware healthcare")


def test_relevance_prefers_distinct_term_hits():
    terms = keywords("acme ransomware")
    assert relevance("acme and ransomware", terms) > relevance("acme acme acme", terms) > 0
    assert relevance("nothing here", terms) == 0


def test_indicators_are_extracted_and_private_ips_skipped():
    host = "a" * 56
    ind = extract_indicators(
        [f"LockBit used CVE-2023-4966 from 8.8.8.8 and 10.0.0.5, see {host}.onion. " + "b" * 64]
    )
    assert ind.groups == ["LockBit"]
    assert ind.by_type["CVE"] == ["CVE-2023-4966"]
    assert ind.by_type["IPv4"] == ["8.8.8.8"]
    assert ind.by_type["Onion host"] == [f"{host}.onion"]
    assert ind.by_type["SHA-256"] == ["b" * 64]


def _docs():
    return [
        SourceDoc(
            1,
            "Leak site",
            onion(0),
            "Acme Corp data will be published unless they pay. LockBit claims 2 TB were "
            "exfiltrated from Acme. Unrelated cooking tips follow here.",
            True,
        ),
        SourceDoc(
            2, "Forum", onion(1), "Acme credentials and logins are for sale by a vendor.", True
        ),
        SourceDoc(
            3, "Noise", onion(2), "Completely unrelated text about gardening and weather.", True
        ),
    ]


def test_report_is_cited_sectioned_and_defanged():
    terms = keywords("acme")
    report = build_report("acme", _docs(), terms, RunStats(16, 9, 40, 3, 1))
    for section in (
        "## Summary",
        "## Key findings",
        "## Indicators",
        "## Risk assessment",
        "## Recommended defensive actions",
        "## Confidence and limits",
    ):
        assert section in report
    assert "[1]" in report and "[2]" in report and "gardening" not in report
    assert "9 of 16 search engines answered" in report and "reached by following links" in report
    assert "LockBit" in report and "**High**" in report
    assert ".onion" not in report.replace("[.]onion", "")  # nothing clickable


def test_report_with_no_matches_says_so_and_is_low_risk():
    docs = [SourceDoc(1, "x", onion(0), "Completely unrelated text about weather today.", True)]
    report = build_report("acme", docs, ["acme"], RunStats(16, 2, 3, 1, 0))
    assert "None of the 1 sources" in report and "**Low**" in report


def test_chunks_reassemble_exactly():
    text = "line one\n" * 50
    assert "".join(chunk(text, 40)) == text
