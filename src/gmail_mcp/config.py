"""Configuration and path resolution for gmail-mcp.

Resolves the on-disk locations the server and auth CLI need:

  * The token database (SQLite) — default ``~/.gmail-mcp/tokens.db``,
    overridable via the ``GMAIL_MCP_DB`` environment variable.
  * The Google OAuth "Desktop app" client-secret JSON — default
    ``~/.gmail-mcp/client_secret.json``, overridable via the
    ``GMAIL_MCP_CLIENT_SECRET`` environment variable.
  * The attachment download root, default ``~/.gmail-mcp/attachments``,
    overridable via the ``GMAIL_MCP_ATTACHMENT_DIR`` environment variable.

No secrets are hardcoded here. The client_id / client_secret are read
from the client-secret JSON you download from the Google Cloud Console.
"""

from __future__ import annotations

import os
from pathlib import Path

# OAuth scopes. Granular — read, compose drafts, modify labels, and manage
# filters/settings. NOT the full https://mail.google.com/ scope. gmail.send is
# intentionally NOT requested: this server never sends mail autonomously, it
# only creates drafts that you send by hand (prompt-injection safety).
#
# gmail.settings.basic backs the filter tools (list/create/delete_filter). It
# permits filter management but NOT forwarding-address changes (that needs
# gmail.settings.sharing, which we deliberately do not request) — so a filter
# created here can label/archive/trash mail but can never forward it off-account.
SCOPES: list[str] = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.settings.basic",
]

# What a readonly session asks Google for. A token granted only this scope
# cannot draft, label, trash, filter, or send, even if it is copied out of
# the token store and used somewhere else.
READONLY_SCOPES: list[str] = [
    "https://www.googleapis.com/auth/gmail.readonly",
]

_VALID_MODES = ("full", "readonly")

_DEFAULT_DIR = Path.home() / ".gmail-mcp"

# Per-message body cap, in characters, applied when surfacing parsed message
# bodies (read_message / read_thread). Long marketing mail and quoted threads
# are the dominant token cost; capping keeps a single read from flooding the
# model's context. The default is deliberately tight (~500 chars ≈ 125 tokens —
# enough to triage the gist) so reads are cheap by default and the agent opts
# into a full body explicitly. 0 or negative ⇒ unlimited. A caller can override
# per-request, and re-fetch in full by passing max_body_chars=0.
_DEFAULT_MAX_BODY_CHARS = 500

# Hard ceiling on a single downloaded attachment, in bytes. Gmail's own
# attachment limit is 25 MB, so this refuses nothing Gmail would deliver; it
# exists so a malformed or hostile size can't be decoded into memory unbounded.
_DEFAULT_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024

# Search-based mutations (trash / bulk_action / modify_labels by query) refuse
# to touch more than this many matches. Explicit message ids are not capped:
# naming them is slower and visible. Raise with GMAIL_MCP_MAX_BULK; a negative
# value disables the cap. The model cannot override this from a tool call.
_DEFAULT_MAX_BULK = 100


def mode() -> str:
    """Process mode: ``full`` (default) or ``readonly``.

    Honors ``GMAIL_MCP_MODE``. Anything else is a configuration error — a typo
    must not silently run with write tools available. Callers should surface
    the ``ValueError`` and exit rather than serving.
    """
    raw = os.environ.get("GMAIL_MCP_MODE", "full").strip().lower()
    if raw in ("", "full"):
        return "full"
    if raw == "readonly":
        return "readonly"
    valid = ", ".join(_VALID_MODES)
    raise ValueError(
        f"GMAIL_MCP_MODE={raw!r} is not a valid mode. Use one of: {valid}."
    )


def is_readonly() -> bool:
    """True when this process must not offer or perform write actions."""
    return mode() == "readonly"


def auth_scopes() -> list[str]:
    """Scopes ``gmail-mcp-auth add`` should request for the current mode.

    Readonly mode asks only for ``gmail.readonly``, so the stored token itself
    cannot mutate mail. Full mode asks for the usual four granular scopes.
    """
    if is_readonly():
        return list(READONLY_SCOPES)
    return list(SCOPES)


def db_path() -> Path:
    """Path to the SQLite token store.

    Honors ``GMAIL_MCP_DB``. Otherwise defaults to ``~/.gmail-mcp/tokens.db``,
    or ``~/.gmail-mcp/tokens-readonly.db`` when ``GMAIL_MCP_MODE=readonly``.
    The separate file is the point: a readonly grant must not land in the
    same database as a token that can draft or trash.
    """
    override = os.environ.get("GMAIL_MCP_DB")
    if override:
        return Path(override).expanduser()
    name = "tokens-readonly.db" if is_readonly() else "tokens.db"
    return _DEFAULT_DIR / name


def client_secret_path() -> Path:
    """Path to the Google OAuth client-secret JSON.

    Honors ``GMAIL_MCP_CLIENT_SECRET``; defaults to
    ``~/.gmail-mcp/client_secret.json``.
    """
    override = os.environ.get("GMAIL_MCP_CLIENT_SECRET")
    if override:
        return Path(override).expanduser()
    return _DEFAULT_DIR / "client_secret.json"


def max_body_chars() -> int:
    """Default per-message body cap in characters.

    Honors ``GMAIL_MCP_MAX_BODY_CHARS``; defaults to
    ``_DEFAULT_MAX_BODY_CHARS``. A value <= 0 means unlimited. A malformed
    value falls back to the default rather than crashing the server.
    """
    raw = os.environ.get("GMAIL_MCP_MAX_BODY_CHARS")
    if raw is None:
        return _DEFAULT_MAX_BODY_CHARS
    try:
        return int(raw)
    except ValueError:
        return _DEFAULT_MAX_BODY_CHARS


def attachments_dir() -> Path:
    """Root directory attachments are downloaded into.

    Honors ``GMAIL_MCP_ATTACHMENT_DIR``; defaults to
    ``~/.gmail-mcp/attachments``. Downloads are confined to a per-message
    subdirectory of this root, and the root is the ONLY writable location the
    server has. There is deliberately no per-call destination argument, because
    that would be an arbitrary-file-write primitive reachable by an instruction
    embedded in an email.
    """
    override = os.environ.get("GMAIL_MCP_ATTACHMENT_DIR")
    if override:
        return Path(override).expanduser()
    return _DEFAULT_DIR / "attachments"


def max_attachment_bytes() -> int:
    """Per-attachment size ceiling in bytes.

    Honors ``GMAIL_MCP_MAX_ATTACHMENT_BYTES``; defaults to 25 MB. A value <= 0
    means unlimited. A malformed value falls back to the default rather than
    crashing the server.
    """
    raw = os.environ.get("GMAIL_MCP_MAX_ATTACHMENT_BYTES")
    if raw is None:
        return _DEFAULT_MAX_ATTACHMENT_BYTES
    try:
        return int(raw)
    except ValueError:
        return _DEFAULT_MAX_ATTACHMENT_BYTES


def max_bulk() -> int | None:
    """Cap on how many messages a search-based mutation may select.

    Honors ``GMAIL_MCP_MAX_BULK``; defaults to 100. A value < 0 disables the
    cap. ``0`` refuses every search-based mutation (explicit ids still work).
    A malformed value falls back to the default rather than crashing, and
    rather than treating the cap as unlimited.
    """
    raw = os.environ.get("GMAIL_MCP_MAX_BULK")
    if raw is None or not raw.strip():
        return _DEFAULT_MAX_BULK
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_BULK
    if value < 0:
        return None
    return value


def filters_enabled() -> bool:
    """Whether ``create_filter`` / ``delete_filter`` may run.

    Off unless ``GMAIL_MCP_ENABLE_FILTERS`` is ``1``, ``true``, ``yes``, or
    ``on``. A filter keeps acting on mail after the session ends, so it is
    not available just because the server is in full mode. ``list_filters``
    is unaffected.
    """
    raw = os.environ.get("GMAIL_MCP_ENABLE_FILTERS", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def tool_allowlist() -> frozenset[str] | None:
    """Optional comma-separated tool allowlist (``GMAIL_MCP_TOOLS``).

    ``None`` means no allowlist: the mode and the filter gate decide. A
    non-empty value is the only set of tools this process may offer. It can
    only narrow what the mode already allows — listing a write tool here does
    not turn it back on in readonly mode. Blank or whitespace is treated as
    unset, not as "offer nothing".
    """
    raw = os.environ.get("GMAIL_MCP_TOOLS")
    if raw is None:
        return None
    names = frozenset(part.strip() for part in raw.split(",") if part.strip())
    if not names:
        return None
    return names
