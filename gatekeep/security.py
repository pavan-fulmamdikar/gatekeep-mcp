"""Security analyzers for outbound DLP, SSRF, sensitive paths, destructive payloads, and MCP schema pinning."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import posixpath
import re
import socket
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from gatekeep.redaction import (
    _API_TOKEN_RE,
    _BEARER_RE,
    _CARD_CANDIDATE_RE,
    _SSN_RE,
    _luhn_valid,
)

# ---------------------------------------------------------------------------
# Outbound Secret / DLP Detection
# ---------------------------------------------------------------------------

_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)

_DB_URI_SECRET_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:/\s]+:[^@/\s]+@[^\s]+",
    re.IGNORECASE,
)

_ENV_ASSIGNMENT_RE = re.compile(
    r"(?:^|[\n\r;&])\s*(?:export\s+)?([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|AUTH_KEY)[A-Z0-9_]*)\s*=\s*(['\"]?)([^\s'\"]{8,})\2",
    re.IGNORECASE,
)

_SAFE_PLACEHOLDER_RE = re.compile(
    r"^(?:example|placeholder|changeme|your[_-]|xxx+|redacted|\*+|dummy|fake)",
    re.IGNORECASE,
)

_INVISIBLE_CHARS_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u00ad]")

_B64_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{22,}={0,2}(?![A-Za-z0-9+/=_-])"
)


def _normalize_for_inspection(text: str) -> str:
    """Strip zero-width/bidi obfuscation characters and fold Unicode lookalikes via NFKC."""
    stripped = _INVISIBLE_CHARS_RE.sub("", text)
    return unicodedata.normalize("NFKC", stripped)


def _scan_plaintext_secret_patterns(text: str, *, check_luhn: bool = True) -> Optional[str]:
    if not text or "[REDACTED" in text:
        return None
    if _PEM_PRIVATE_KEY_RE.search(text):
        return "private_key"
    if _DB_URI_SECRET_RE.search(text):
        return "credentialed_db_uri"
    if _BEARER_RE.search(text):
        return "bearer_token"
    if _API_TOKEN_RE.search(text):
        return "api_token"
    if _SSN_RE.search(text):
        return "ssn"
    env_match = _ENV_ASSIGNMENT_RE.search(text)
    if env_match and not _SAFE_PLACEHOLDER_RE.match(env_match.group(3)):
        return "secret_assignment"
    if check_luhn:
        for match in _CARD_CANDIDATE_RE.finditer(text):
            digits = "".join(ch for ch in match.group(0) if ch.isdigit())
            if _luhn_valid(digits):
                return "payment_card"
    return None


def _scan_string_for_secret(text: str) -> Optional[str]:
    """Return secret category if ``text`` (or base64-encoded segments) contains a live credential."""
    if not text or "[REDACTED" in text:
        return None
    normalized = _normalize_for_inspection(text)
    direct = _scan_plaintext_secret_patterns(normalized, check_luhn=True)
    if direct is not None:
        return direct

    # Detect base64-obfuscated secrets/keys in outbound arguments
    for b64_match in _B64_TOKEN_RE.finditer(normalized):
        token = b64_match.group(0)
        if token.isalnum() and "=" not in token:
            # Avoid futile decode attempts on plain long alphanumeric identifiers like hashes
            if len(token) % 4 != 0:
                continue
        padded = token.replace("-", "+").replace("_", "/")
        padded += "=" * ((4 - len(padded) % 4) % 4)
        try:
            raw_bytes = base64.b64decode(padded, validate=True)
            decoded = raw_bytes.decode("utf-8")
        except Exception:
            continue
        decoded_norm = _normalize_for_inspection(decoded)
        decoded_hit = _scan_plaintext_secret_patterns(decoded_norm, check_luhn=False)
        if decoded_hit is not None:
            return f"encoded_{decoded_hit}"
    return None


def _iter_arg_strings(
    value: Any,
    path: str = "",
) -> Iterable[Tuple[str, str]]:
    """Yield ``(arg_path, string_value)`` recursively from tool arguments."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from _iter_arg_strings(item, child_path)
    elif isinstance(value, (list, tuple, set)):
        for idx, item in enumerate(value):
            child_path = f"{path}[{idx}]" if path else f"[{idx}]"
            yield from _iter_arg_strings(item, child_path)


def scan_outbound_secrets(args: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Inspect outbound write arguments for live credentials, private keys, SSNs, or cards.

    Returns:
        ``(arg_path, secret_kind)`` when a live secret is detected, else ``None``.
    """
    for arg_path, text in _iter_arg_strings(args):
        secret_kind = _scan_string_for_secret(text)
        if secret_kind is not None:
            return arg_path, secret_kind
    return None


# ---------------------------------------------------------------------------
# Sensitive Path, SSRF, and Destructive Payload Inspection
# ---------------------------------------------------------------------------

_PATH_KEYS = frozenset(
    {
        "path",
        "file_path",
        "filepath",
        "file",
        "filename",
        "source",
        "destination",
        "dest",
        "target_path",
        "paths",
    }
)

_URL_KEYS = frozenset(
    {
        "url",
        "uri",
        "endpoint",
        "webhook",
        "webhook_url",
        "href",
        "target_url",
        "callback_url",
    }
)

_SQL_KEYS = frozenset({"sql", "query", "statement"})

_SHELL_KEYS = frozenset({"command", "cmd", "script", "shell_command"})

_SENSITIVE_FILENAMES = frozenset(
    {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "authorized_keys",
        ".netrc",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        "shadow",
        "gshadow",
    }
)

_CLOUD_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)

_DROP_OR_TRUNCATE_RE = re.compile(
    r"\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW|INDEX)|TRUNCATE\s+(?:TABLE\s+)?[A-Za-z0-9_`\"\.]+)\b",
    re.IGNORECASE,
)

_DELETE_STMT_RE = re.compile(
    r"\bDELETE\s+FROM\s+[A-Za-z0-9_`\"\.]+(?:\s*;|\s*$)",
    re.IGNORECASE,
)

_UPDATE_NO_WHERE_RE = re.compile(
    r"\bUPDATE\s+[A-Za-z0-9_`\"\.]+\s+SET\b(?![\s\S]*\bWHERE\b)",
    re.IGNORECASE,
)

_SQL_CHAIN_DANGEROUS_RE = re.compile(
    r";\s*(?:DROP|DELETE|TRUNCATE|ALTER|EXEC(?:UTE)?)\b",
    re.IGNORECASE,
)

_DANGEROUS_SHELL_RE = re.compile(
    r"(?:"
    r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:/(?:\s|$|\*)|\*|~|\$HOME)"
    r"|\bmkfs\.[a-z0-9]+\b"
    r"|:\(\)\s*\{[^}]*:\s*\|\s*:\s*&\s*\}\s*;?\s*:"
    r"|\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b"
    r"|[;&|]{1,2}\s*rm\s+-"
    r"|\bdd\s+if=[^\n]*\bof=/dev/"
    r")",
    re.IGNORECASE,
)


_SQL_BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")
_SQL_LINE_COMMENT_RE = re.compile(r"--[^\n\r]*")

_SQL_TAUTOLOGY_WHERE_RE = re.compile(
    r"\b(?:DELETE\s+FROM|UPDATE\s+[A-Za-z0-9_`\"\.]+[\s\S]*?\bSET)\b[\s\S]*?\bWHERE\s+"
    r"(?:TRUE|1\s*=\s*1|'([^']+)'\s*=\s*'\1'|([A-Za-z0-9_]+)\s*=\s*\2)\s*(?:;|$)",
    re.IGNORECASE,
)


def _check_sensitive_path(raw_path: str) -> Optional[str]:
    """Return a denial reason if ``raw_path`` uses traversal or targets credentials."""
    decoded = _normalize_for_inspection(raw_path.strip())
    for _ in range(2):
        unq = unquote(decoded)
        if unq == decoded:
            break
        decoded = unq
    normalized = _normalize_for_inspection(decoded).replace("\\", "/")
    if not normalized:
        return None
    parts = [part for part in normalized.split("/") if part and part != "."]
    if ".." in parts:
        return f"Path traversal ('..') is blocked for path '{raw_path}'."

    cleaned = posixpath.normpath(normalized).lower()
    segments = [seg for seg in cleaned.split("/") if seg]
    basename = segments[-1] if segments else ""

    if basename == ".env" or basename.startswith(".env."):
        return f"Access to environment secret file '{raw_path}' is blocked."
    if basename in _SENSITIVE_FILENAMES:
        return f"Access to credential file '{raw_path}' is blocked."
    if ".ssh" in segments:
        return f"Access to SSH directory '{raw_path}' is blocked."
    if ".aws" in segments and any(s in {"credentials", "config"} for s in segments):
        return f"Access to AWS credential file '{raw_path}' is blocked."
    if cleaned == "/etc/shadow" or cleaned.endswith("/etc/shadow"):
        return f"Access to system shadow file '{raw_path}' is blocked."
    return None


def _is_non_public_ip(ip_obj: Any) -> bool:
    """Return True if an IPv4/IPv6 address (or mapped IPv4) is loopback, private, link-local, or non-public."""
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return _is_non_public_ip(ip_obj.ipv4_mapped)
    return bool(
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
        or ip_obj.is_multicast
        or ip_obj.is_reserved
    )


def _parse_int_part(token: str) -> Optional[int]:
    """Parse decimal, 0x-hex, or leading-zero octal IPv4 integer part."""
    if not token:
        return None
    try:
        if token.startswith("0x"):
            return int(token, 16)
        if len(token) > 1 and token.startswith("0"):
            return int(token, 8)
        if token.isdigit():
            return int(token, 10)
    except ValueError:
        return None
    return None


def _parse_obfuscated_ipv4(hostname: str) -> Optional[ipaddress.IPv4Address]:
    """Resolve decimal integer, hex, octal, or shorthand dotted IPv4 literals."""
    if not hostname:
        return None
    parts = hostname.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums: List[int] = []
    for part in parts:
        val = _parse_int_part(part)
        if val is None or val < 0:
            return None
        nums.append(val)
    if len(nums) == 1:
        ip_int = nums[0]
        if 0 <= ip_int <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(ip_int)
        return None
    if any(n > 255 for n in nums[:-1]):
        return None
    tail = nums[-1]
    remaining_bits = 8 * (5 - len(nums))
    if tail >= (1 << remaining_bits):
        return None
    ip_int = 0
    for idx, n in enumerate(nums[:-1]):
        ip_int |= n << (8 * (3 - idx))
    ip_int |= tail
    return ipaddress.IPv4Address(ip_int)


def _check_ssrf_url(raw_url: str, *, resolve_dns: bool = False) -> Optional[str]:
    """Return a denial reason if ``raw_url`` targets loopback, private, link-local, metadata, or unsafe schemes."""
    candidate = _normalize_for_inspection(raw_url.strip())
    if not candidate:
        return None
    parsed = urlparse(candidate)
    if not parsed.scheme:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return f"Disallowed URL scheme '{scheme}://' in '{raw_url}'; only http/https allowed."

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return f"Malformed URL host in '{raw_url}'."

    if hostname == "localhost" or hostname.endswith(".localhost") or hostname in _CLOUD_METADATA_HOSTS:
        return f"SSRF guard blocked internal/metadata host '{hostname}'."

    ip_obj: Optional[Any] = None
    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        ip_obj = _parse_obfuscated_ipv4(hostname)

    if ip_obj is not None:
        if _is_non_public_ip(ip_obj):
            return f"SSRF guard blocked non-public IP target '{hostname}'."
        return None

    if resolve_dns:
        try:
            infos = socket.getaddrinfo(hostname, parsed.port or (443 if scheme == "https" else 80))
        except OSError:
            return None
        for _family, _type, _proto, _canon, sockaddr in infos:
            resolved_ip_raw = str(sockaddr[0]).split("%", 1)[0]
            try:
                resolved_ip = ipaddress.ip_address(resolved_ip_raw)
            except ValueError:
                continue
            if _is_non_public_ip(resolved_ip):
                return (
                    f"SSRF guard blocked hostname '{hostname}' resolving to "
                    f"non-public IP '{resolved_ip_raw}'."
                )
    return None


def _check_destructive_sql(sql: str) -> Optional[str]:
    """Return a denial reason if ``sql`` (after comment/Unicode normalization) is destructive."""
    cleaned = _normalize_for_inspection(sql)
    cleaned = _SQL_BLOCK_COMMENT_RE.sub(" ", cleaned)
    cleaned = _SQL_LINE_COMMENT_RE.sub(" ", cleaned)
    if _DROP_OR_TRUNCATE_RE.search(cleaned):
        return "Destructive DDL (DROP/TRUNCATE) is blocked by default policy."
    if _SQL_CHAIN_DANGEROUS_RE.search(cleaned):
        return "Chained destructive SQL statement after ';' is blocked."
    if _DELETE_STMT_RE.search(cleaned):
        return "DELETE statement without a WHERE clause is blocked."
    if _UPDATE_NO_WHERE_RE.search(cleaned):
        return "UPDATE statement without a WHERE clause is blocked."
    if _SQL_TAUTOLOGY_WHERE_RE.search(cleaned):
        return "Destructive DELETE/UPDATE with tautological WHERE clause is blocked."
    return None


def _check_destructive_shell(cmd: str) -> Optional[str]:
    """Return a denial reason if ``cmd`` matches high-risk destructive or piped shell execution."""
    cleaned = _normalize_for_inspection(cmd)
    if _DANGEROUS_SHELL_RE.search(cleaned):
        return "Destructive or piped remote-execution shell command is blocked."
    return None


def _leaf_key(arg_path: str) -> str:
    """Extract normalized final dictionary key from a nested argument path."""
    base = arg_path.split("[", 1)[0]
    return base.rsplit(".", 1)[-1].lower()


def inspect_payload_safety(
    tool_name: str,
    args: Dict[str, Any],
    *,
    mode: str,
    allow_sensitive_paths: bool = False,
    allow_private_urls: bool = False,
    allow_destructive_sql: bool = False,
    allow_shell: bool = False,
    resolve_dns_for_ssrf: bool = False,
) -> Optional[Tuple[str, str]]:
    """Inspect tool arguments for path traversal/credential files, SSRF targets, and destructive SQL/shell.

    Returns:
        ``(rule_triggered, reason)`` when blocked, else ``None``.
    """
    del tool_name  # Reserved for future tool-specific heuristics.
    is_mutating = mode != "read"

    for arg_path, text in _iter_arg_strings(args):
        key = _leaf_key(arg_path)

        if not allow_sensitive_paths and key in _PATH_KEYS:
            path_reason = _check_sensitive_path(text)
            if path_reason:
                return "sensitive_path_access", path_reason

        if not allow_private_urls and (key in _URL_KEYS or "://" in text):
            if key in _URL_KEYS or text.lstrip().startswith(("file://", "gopher://", "dict://")):
                ssrf_reason = _check_ssrf_url(text, resolve_dns=resolve_dns_for_ssrf)
                if ssrf_reason:
                    return "ssrf_blocked_target", ssrf_reason

        if is_mutating and not allow_destructive_sql and key in _SQL_KEYS:
            sql_reason = _check_destructive_sql(text)
            if sql_reason:
                return "destructive_payload_blocked", sql_reason

        if is_mutating and not allow_shell and key in _SHELL_KEYS:
            shell_reason = _check_destructive_shell(text)
            if shell_reason:
                return "destructive_payload_blocked", shell_reason

    return None


# ---------------------------------------------------------------------------
# MCP Schema Pinning & Tool Poisoning Detection
# ---------------------------------------------------------------------------

_POISON_TAG_RE = re.compile(
    r"<\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|SECRET|HIDDEN|OVERRIDE)\s*>",
    re.IGNORECASE,
)

_POISON_DIRECTIVE_RE = re.compile(
    r"(?:"
    r"(?:do\s+not|never|don't)\s+(?:tell|inform|mention|show|reveal\s+to)\s+(?:the\s+)?user"
    r"|hide\s+(?:this|these|the\s+\w+)\s+from\s+(?:the\s+)?user"
    r"|silently\s+(?:send|forward|copy|exfiltrate|read|upload|post)"
    r"|(?:before\s+(?:calling|using)\s+this\s+tool[^.\n]{0,80}(?:\.ssh|id_rsa|\.env|credentials|passwd|shadow))"
    r"|ignore\s+(?:all\s+)?previous\s+instructions"
    r")",
    re.IGNORECASE,
)


def compute_tool_schema_hash(tool_schema: Dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 digest over an MCP tool's identity and contract."""
    canonical_payload = {
        "name": str(tool_schema.get("name", "")),
        "description": str(tool_schema.get("description", "")),
        "inputSchema": tool_schema.get("inputSchema") or {},
    }
    encoded = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def detect_tool_description_poisoning(
    tool_name: str,
    description: str,
    input_schema: Dict[str, Any],
) -> Optional[str]:
    """Detect covert prompt-injection instructions embedded in tool metadata or JSON schema descriptions."""
    del tool_name
    candidates: List[Tuple[str, str]] = []
    if description:
        candidates.append(("description", description))
    for path, text in _iter_arg_strings(input_schema, "inputSchema"):
        candidates.append((path, text))

    for source_path, text in candidates:
        cleaned = _normalize_for_inspection(text)
        if _POISON_TAG_RE.search(cleaned):
            return f"Suspicious instruction tag found in {source_path}."
        if _POISON_DIRECTIVE_RE.search(cleaned):
            return f"Covert instruction/exfiltration directive found in {source_path}."
    return None


__all__ = [
    "compute_tool_schema_hash",
    "detect_tool_description_poisoning",
    "inspect_payload_safety",
    "scan_outbound_secrets",
]
