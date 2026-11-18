import os
import stat

import pytest

from app.config import Settings
from app.llm_store import LLMStore, initial_llm_config
from app.providers import (
    BY_ID,
    LLMConfig,
    build_config,
    check_base_url,
    config_from_settings,
    is_local_host,
    key_hint,
)


class TestBaseUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "https://api.openai.com/v1",
            "https://api.openai.com/v1/",
            "http://localhost:1234/v1",
            "http://127.0.0.1:8080",
            "http://host.docker.internal:11434",
            "http://ollama:11434",  # bare docker service name
            "http://192.168.1.20:8000/v1",
        ],
    )
    def test_accepted(self, url):
        assert check_base_url(url) == url.rstrip("/")

    @pytest.mark.parametrize(
        "url",
        [
            "http://api.openai.com/v1",  # key would travel unencrypted
            "ftp://example.com",
            "https://user:pw@example.com",
            "https://example.com/v1?x=1",
            "https://example.com/v1#frag",
            "http://169.254.169.254/latest",  # cloud metadata address
            "http://0.0.0.0:80",
            "https://",
            "not a url",
            "",
        ],
    )
    def test_rejected(self, url):
        with pytest.raises(ValueError):
            check_base_url(url)

    def test_is_local_host(self):
        assert is_local_host("localhost") and is_local_host("10.1.2.3") and is_local_host("ollama")
        assert not is_local_host("api.openai.com") and not is_local_host("8.8.8.8")
        assert not is_local_host("169.254.169.254")


class TestBuildConfig:
    def test_openai_uses_preset_url_and_needs_key(self):
        cfg = build_config("openai", "some-model", api_key="sk-test-abcdef123456")
        assert cfg.base_url == "https://api.openai.com/v1" and cfg.configured and cfg.needs_key
        assert cfg.kind == "openai"

    def test_anthropic_defaults(self):
        cfg = build_config("anthropic", api_key="k" * 20)
        assert cfg.model == "claude-sonnet-5-5" and cfg.kind == "anthropic" and cfg.configured

    def test_not_configured_without_key_or_model(self):
        assert not build_config("openai", "m").configured  # no key
        assert not build_config("openai", "", api_key="k" * 20).configured  # no model

    def test_local_server_needs_no_key(self):
        cfg = build_config("custom", "local-model", "http://localhost:1234/v1")
        assert cfg.configured and not cfg.needs_key

    def test_custom_requires_url(self):
        with pytest.raises(ValueError, match="base URL"):
            build_config("custom", "m")

    def test_ollama_uses_configured_host(self):
        cfg = build_config("ollama", ollama_host="http://localhost:11434")
        assert cfg.base_url == "http://localhost:11434" and cfg.configured

    @pytest.mark.parametrize(
        ("provider", "model", "key", "msg"),
        [
            ("nope", "m", "", "Unknown provider"),
            ("openai", "bad model!", "", "model name"),
            ("openai", "m", "has space", "API key"),
            ("openai", "m", "new\nline", "API key"),
        ],
    )
    def test_invalid_input(self, provider, model, key, msg):
        with pytest.raises(ValueError, match=msg):
            build_config(provider, model, api_key=key)

    def test_require_model(self):
        with pytest.raises(ValueError, match="model name"):
            build_config("openai", "", require_model=True)

    def test_secret_never_in_repr(self):
        cfg = build_config("openai", "m", api_key="sk-supersecret-value-123")
        assert "supersecret" not in repr(cfg) and "supersecret" not in repr(
            Settings(llm_api_key="x")
        )

    def test_label_and_hint(self):
        assert build_config("openai", "m").label == "OpenAI · m"
        assert key_hint("sk-abcdefghijklmnop") == "…mnop" and key_hint("") == ""
        assert key_hint("short") == "set"
        assert {"openai", "anthropic", "ollama", "custom"} <= set(BY_ID)


class TestEnvResolution:
    def test_from_env_reads_vendor_key_names(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "a" * 30)
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        cfg = config_from_settings(Settings.from_env())
        assert cfg.provider == "anthropic" and cfg.api_key == "a" * 30 and cfg.configured

    def test_generic_key_wins(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setenv("LLM_API_KEY", "generic-key-123456")
        monkeypatch.setenv("OPENAI_API_KEY", "vendor-key-123456")
        monkeypatch.setenv("LLM_MODEL", "m")
        assert Settings.from_env().llm_api_key == "generic-key-123456"

    def test_default_is_the_builtin_analyst_needing_no_setup(self, monkeypatch):
        for var in ("LLM_PROVIDER", "LLM_MODEL", "LLM_API_KEY", "OPENAI_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        cfg = config_from_settings(Settings.from_env())
        assert cfg.provider == "builtin" and cfg.configured and not cfg.needs_key
        assert cfg.label == "Void built-in"

    def test_allowed_hosts_env(self, monkeypatch):
        monkeypatch.setenv("ALLOWED_HOSTS", "Dw.example.com, localhost")
        assert Settings.from_env().allowed_hosts == ("dw.example.com", "localhost")


class TestStore:
    def test_roundtrip_with_owner_only_permissions(self, tmp_path):
        store = LLMStore(tmp_path / "sub" / "llm.json")
        cfg = build_config("openai", "m", api_key="sk-test-abcdef123456")
        store.save(cfg)
        assert store.load() == {
            "provider": "openai",
            "model": "m",
            "base_url": "https://api.openai.com/v1",
            "api_key": "sk-test-abcdef123456",
        }
        mode = stat.S_IMODE(os.stat(tmp_path / "sub" / "llm.json").st_mode)
        assert mode == 0o600
        assert not list((tmp_path / "sub").glob("*.tmp"))  # atomic write leaves no temp file

    def test_missing_and_corrupt_files_are_ignored(self, tmp_path):
        store = LLMStore(tmp_path / "llm.json")
        assert store.load() is None
        (tmp_path / "llm.json").write_text("{not json")
        assert store.load() is None
        (tmp_path / "llm.json").write_text("[1, 2]")
        assert store.load() is None

    def test_saved_settings_override_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setenv("LLM_MODEL", "env-model")
        monkeypatch.setenv("LLM_API_KEY", "env-key-123456789")
        settings = Settings.from_env()
        store = LLMStore(tmp_path / "llm.json")
        assert initial_llm_config(settings, store)[1] == "env"
        store.save(build_config("anthropic", api_key="saved-key-123456789"))
        cfg, source = initial_llm_config(settings, store)
        assert source == "saved" and cfg.provider == "anthropic"

    def test_invalid_saved_file_falls_back_to_env(self, tmp_path):
        store = LLMStore(tmp_path / "llm.json")
        (tmp_path / "llm.json").write_text('{"provider": "evil", "model": "", "base_url": ""}')
        cfg, source = initial_llm_config(Settings(), store)
        assert source == "env" and isinstance(cfg, LLMConfig)
