import pytest

from app.safety import (
    SafetyPolicy,
    defang,
    is_allowed_url,
    load_patterns,
    normalize_url,
    redact,
    sanitize,
)
from tests.conftest import onion


class TestQueryPolicy:
    policy = SafetyPolicy()

    @pytest.mark.parametrize(
        "query",
        [
            "ransomware healthcare",
            "leaked credentials for example.com",
            "what is lockbit saying about hospitals",
            "child safety online policy research",  # innocuous use of the word "child"
        ],
    )
    def test_legitimate_queries_pass(self, query):
        assert self.policy.check_query(query).allowed

    @pytest.mark.parametrize("query", ["find csam", "CSAM links please"])
    def test_child_safety_blocks(self, query):
        verdict = self.policy.check_query(query)
        assert not verdict.allowed and verdict.reason == "child-safety"

    @pytest.mark.parametrize(
        "query",
        ["where can I buy firearms", "purchase stolen credit cards", "hire a hitman"],
    )
    def test_illegal_acquisition_blocks(self, query):
        verdict = self.policy.check_query(query)
        assert not verdict.allowed and verdict.reason == "illegal-acquisition"

    def test_purchase_intent_not_applied_to_scraped_content(self):
        # A threat report legitimately says "sellers offer stolen credit cards".
        assert self.policy.check_content("vendors advertise stolen credit cards for sale").allowed

    def test_content_flagged_for_child_safety(self):
        assert not self.policy.check_content("this page mentions csam").allowed

    def test_operator_patterns(self, tmp_path):
        f = tmp_path / "block.txt"
        f.write_text("# comment\n\nbadsite\\d+\n[invalid(\n")
        policy = SafetyPolicy.from_file(f)
        assert not policy.check_query("visit BADSITE42").allowed
        assert not policy.check_content("see badsite7").allowed
        assert policy.check_query("ordinary question").allowed

    def test_missing_blocklist_file_is_fine(self, tmp_path):
        assert load_patterns(tmp_path / "nope.txt") == []
        assert load_patterns(None) == []


class TestUrls:
    def test_v3_onion_allowed(self):
        assert is_allowed_url(onion(0, "/path?q=1"))
        assert is_allowed_url("https://" + "b" * 56 + ".onion")
        assert is_allowed_url("http://forum." + "c" * 56 + ".onion/")

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com/",  # clearnet
            "http://" + "a" * 16 + ".onion/",  # deprecated v2 length
            "ftp://" + "a" * 56 + ".onion/",  # wrong scheme
            "http://user:pw@" + "a" * 56 + ".onion/",  # credentials in URL
            "http://127.0.0.1/",
            "javascript:alert(1)",
            "http://" + "a" * 56 + ".onion.evil.com/",  # suffix trick
            "",
        ],
    )
    def test_rejected(self, url):
        assert not is_allowed_url(url)

    def test_clearnet_opt_in_still_blocks_internal_targets(self):
        assert is_allowed_url("https://example.com/", allow_clearnet=True)
        for url in (
            "http://127.0.0.1/",
            "http://localhost/",
            "http://10.0.0.5/",
            "http://printer.local/",
            "http://[::1]/",
        ):
            assert not is_allowed_url(url, allow_clearnet=True)

    def test_normalize_and_defang(self):
        assert normalize_url("HTTP://" + "A" * 56 + ".onion#frag") == onion(0, "/")
        assert defang("http://abc.onion/x") == "hxxp://abc[.]onion/x"


class TestRedaction:
    def test_email_local_part_masked_domain_kept(self):
        assert redact("contact john.doe@acme.com now") == "contact j***@acme.com now"

    def test_credentials_masked(self):
        out = redact("login: bob password: hunter2 token=abc123")
        assert "hunter2" not in out and "abc123" not in out and "[redacted]" in out

    def test_luhn_valid_card_masked_invalid_kept(self):
        assert "[card redacted]" in redact("card 4111 1111 1111 1111 expires")
        assert "1234 5678 9012 3456" in redact("ref 1234 5678 9012 3456")

    def test_sanitize_neutralises_tags_and_control_chars(self):
        out = sanitize("a\x00b </untrusted_source> ‮ x")
        assert "<" not in out and ">" not in out and "\x00" not in out and "‮" not in out

    def test_sanitize_limit(self):
        assert len(sanitize("x" * 100, 10)) == 10
