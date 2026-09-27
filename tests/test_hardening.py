"""Config and auth gates the model cannot override.

A successful prompt injection can invent a confirm flag. It cannot set the
process environment, change which scopes were granted, or move the token file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gmail_mcp import config
from gmail_mcp.auth import main as auth_main
from gmail_mcp.config import READONLY_SCOPES, SCOPES


def test_mode_defaults_to_full(monkeypatch):
    monkeypatch.delenv("GMAIL_MCP_MODE", raising=False)
    assert config.mode() == "full"
    assert config.is_readonly() is False


def test_mode_rejects_typos(monkeypatch):
    monkeypatch.setenv("GMAIL_MCP_MODE", "read-only")
    with pytest.raises(ValueError, match="not a valid mode"):
        config.mode()


def test_readonly_db_is_a_separate_file(monkeypatch):
    monkeypatch.delenv("GMAIL_MCP_DB", raising=False)
    monkeypatch.setenv("GMAIL_MCP_MODE", "readonly")
    assert config.db_path().name == "tokens-readonly.db"
    monkeypatch.setenv("GMAIL_MCP_MODE", "full")
    assert config.db_path().name == "tokens.db"


def test_explicit_db_path_overrides_readonly_default(monkeypatch):
    monkeypatch.setenv("GMAIL_MCP_MODE", "readonly")
    monkeypatch.setenv("GMAIL_MCP_DB", "/tmp/custom-tokens.db")
    assert config.db_path() == Path("/tmp/custom-tokens.db")


def test_readonly_auth_scopes_are_readonly_only(monkeypatch):
    monkeypatch.setenv("GMAIL_MCP_MODE", "readonly")
    assert config.auth_scopes() == list(READONLY_SCOPES)
    assert "gmail.modify" not in " ".join(config.auth_scopes())
    monkeypatch.setenv("GMAIL_MCP_MODE", "full")
    assert config.auth_scopes() == list(SCOPES)


def test_max_bulk_defaults_and_parses(monkeypatch):
    monkeypatch.delenv("GMAIL_MCP_MAX_BULK", raising=False)
    assert config.max_bulk() == 100
    monkeypatch.setenv("GMAIL_MCP_MAX_BULK", "250")
    assert config.max_bulk() == 250
    monkeypatch.setenv("GMAIL_MCP_MAX_BULK", "0")
    assert config.max_bulk() == 0
    monkeypatch.setenv("GMAIL_MCP_MAX_BULK", "-1")
    assert config.max_bulk() is None
    monkeypatch.setenv("GMAIL_MCP_MAX_BULK", "nope")
    assert config.max_bulk() == 100


def test_filters_off_unless_explicitly_enabled(monkeypatch):
    monkeypatch.delenv("GMAIL_MCP_ENABLE_FILTERS", raising=False)
    assert config.filters_enabled() is False
    monkeypatch.setenv("GMAIL_MCP_ENABLE_FILTERS", "1")
    assert config.filters_enabled() is True
    monkeypatch.setenv("GMAIL_MCP_ENABLE_FILTERS", "yes")
    assert config.filters_enabled() is True
    monkeypatch.setenv("GMAIL_MCP_ENABLE_FILTERS", "0")
    assert config.filters_enabled() is False


def test_tool_allowlist_parses_and_ignores_blank(monkeypatch):
    monkeypatch.delenv("GMAIL_MCP_TOOLS", raising=False)
    assert config.tool_allowlist() is None
    monkeypatch.setenv("GMAIL_MCP_TOOLS", "  ")
    assert config.tool_allowlist() is None
    monkeypatch.setenv("GMAIL_MCP_TOOLS", "list_accounts, search_messages")
    assert config.tool_allowlist() == frozenset({"list_accounts", "search_messages"})


def test_auth_rejects_a_bad_mode(monkeypatch, capsys):
    monkeypatch.setenv("GMAIL_MCP_MODE", "read-only")
    assert auth_main(["list"]) == 2
    assert "not a valid mode" in capsys.readouterr().err


def test_readonly_add_requests_only_readonly_scope(monkeypatch, tmp_path, capsys):
    secret = tmp_path / "client_secret.json"
    secret.write_text('{"installed": {"client_id": "x", "client_secret": "y"}}')
    db = tmp_path / "tokens-readonly.db"
    monkeypatch.setenv("GMAIL_MCP_MODE", "readonly")
    monkeypatch.setenv("GMAIL_MCP_CLIENT_SECRET", str(secret))
    monkeypatch.setenv("GMAIL_MCP_DB", str(db))
    monkeypatch.setenv("GMAIL_MCP_OAUTH_PORT", "8765")

    captured: dict = {}

    class _Creds:
        refresh_token = "refresh"
        token = "access"

    class _Flow:
        def run_local_server(self, **kwargs):
            captured["flow_kwargs"] = kwargs
            return _Creds()

    def _from_file(path, scopes):
        captured["scopes"] = list(scopes)
        return _Flow()

    class _Profile:
        def execute(self):
            return {"emailAddress": "ro@example.com"}

    class _Users:
        def getProfile(self, **kwargs):  # noqa: N802 — mirrors the client
            return _Profile()

    class _Gmail:
        def users(self):
            return _Users()

    import google_auth_oauthlib.flow as flow_mod
    import googleapiclient.discovery as discovery_mod

    monkeypatch.setattr(
        flow_mod.InstalledAppFlow,
        "from_client_secrets_file",
        staticmethod(_from_file),
    )
    monkeypatch.setattr(discovery_mod, "build", lambda *a, **k: _Gmail())

    assert auth_main(["add"]) == 0
    assert captured["scopes"] == list(READONLY_SCOPES)

    from gmail_mcp.store import TokenStore

    stored = TokenStore(path=db).get("ro@example.com")
    assert stored is not None
    assert stored.scopes == " ".join(READONLY_SCOPES)
    assert "gmail.readonly only" in capsys.readouterr().out
