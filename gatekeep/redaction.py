"""
gatekeep/redaction.py

Compliance-grade PII/secret redaction and cryptographic helpers for Gatekeep:
  - Deterministic, non-mutating redaction of secrets, credentials, payment cards,
    SSNs, emails, and custom field names prior to persisting `AuditReceipt`s or
    `EscalationTicket` previews (prevents shadow PII sprawl & preserves GDPR-safe
    SHA-256 audit hash chains).
  - Canonical SHA-256 helpers for token hashing at rest (`hash_secret_token`) and
    tool+argument approval binding (`canonical_action_fingerprint`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Dict, Iterable, Optional, Pattern, Tuple

DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "client_secret",
        "authorization",
        "auth",
        "auth_header",
        "ssn",
        "social_security",
        "social_security_number",
        "tax_id",
        "tin",
        "pan",
        "card_number",
        "credit_card",
        "cvv",
        "cvc",
        "iban",
        "routing_number",
        "account_number",
        "email",
        "email_address",
        "phone",
        "phone_number",
        "date_of_birth",
        "dob",
    }
)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
_API_TOKEN_RE = re.compile(
    r"\b(?:sk|pk|rk|ghp|gho|github_pat|xoxb|xoxp|xoxa|AKIA|AIza)[A-Za-z0-9_\-]{12,}\b"
)
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _luhn_valid(digits: str) -> bool:
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    total = 0
    reverse = digits[::-1]
    for idx, ch in enumerate(reverse):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def hash_secret_token(token: str) -> str:
    """Compute a constant-format SHA-256 hex digest for storing approval tokens safely at rest."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def canonical_action_fingerprint(tool_name: str, arguments: Optional[Dict[str, Any]]) -> str:
    """
    Compute a canonical SHA-256 fingerprint binding a tool invocation (`tool_name` +
    normalized `arguments`) so single-use escalation tokens cannot be replayed against
    different tools or altered argument payloads.
    """
    payload = json.dumps(
        {
            "tool_name": str(tool_name),
            "arguments": arguments if isinstance(arguments, dict) else {},
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class SensitiveDataRedactor:
    """
    Deterministic recursive PII & credential redactor for Gatekeep audit logs,
    escalation previews, and webhooks.

    When `pseudonymize=True` (default), redacted strings emit a compact HMAC/SHA-256
    tag (`[REDACTED:<kind>:<10-hex>]`) so correlation across receipts works cleanly
    without persisting raw PII or secrets.
    """

    def __init__(
        self,
        *,
        sensitive_keys: Optional[Iterable[str]] = None,
        extra_keys: Optional[Iterable[str]] = None,
        extra_patterns: Optional[Iterable[Tuple[str, Pattern[str]]]] = None,
        pseudonymize: bool = True,
        hmac_key: Optional[str] = None,
        mask: str = "[REDACTED]",
    ) -> None:
        base = set(sensitive_keys) if sensitive_keys is not None else set(DEFAULT_SENSITIVE_KEYS)
        if extra_keys:
            base.update(str(k).strip().lower() for k in extra_keys if str(k).strip())
        self.sensitive_keys: frozenset[str] = frozenset(k.lower() for k in base)
        self.extra_patterns: Tuple[Tuple[str, Pattern[str]], ...] = tuple(extra_patterns or ())
        self.pseudonymize = bool(pseudonymize)
        self._hmac_key = hmac_key.encode("utf-8") if hmac_key else None
        self.mask = mask

    def pseudonym_digest(self, raw: str) -> Optional[str]:
        """Return the deterministic 10-hex HMAC/SHA-256 pseudonym digest for `raw`, or None."""
        if not self.pseudonymize:
            return None
        raw_bytes = raw.encode("utf-8", errors="replace")
        if self._hmac_key is not None:
            return hmac.new(self._hmac_key, raw_bytes, hashlib.sha256).hexdigest()[:10]
        return hashlib.sha256(raw_bytes).hexdigest()[:10]

    def _tag(self, kind: str, raw: str) -> str:
        digest = self.pseudonym_digest(raw)
        if digest is None:
            return self.mask
        return f"[REDACTED:{kind}:{digest}]"

    @staticmethod
    def _normalize_key(key: str) -> str:
        return key.strip().lower().replace("-", "_")

    def _is_sensitive_key(self, key: Optional[str]) -> bool:
        if not key:
            return False
        norm = self._normalize_key(key)
        if norm in self.sensitive_keys:
            return True
        return any(
            norm.endswith(f"_{tok}") or norm == tok
            for tok in ("password", "passwd", "secret", "api_key", "token", "ssn", "cvv", "cvc", "email")
        )

    def redact_string(self, text: str) -> str:
        """Scrub inline secrets, emails, SSNs, and Luhn-valid payment card numbers from text."""
        out = _BEARER_RE.sub(lambda m: self._tag("bearer", m.group(0)), text)
        out = _API_TOKEN_RE.sub(lambda m: self._tag("secret", m.group(0)), out)
        out = _SSN_RE.sub(lambda m: self._tag("ssn", m.group(0)), out)
        out = _EMAIL_RE.sub(lambda m: self._tag("email", m.group(0)), out)

        def _replace_card(match: re.Match[str]) -> str:
            raw_cand = match.group(0)
            digits = re.sub(r"[ -]", "", raw_cand)
            return self._tag("card", digits) if _luhn_valid(digits) else raw_cand

        out = _CARD_CANDIDATE_RE.sub(_replace_card, out)
        for label, pat in self.extra_patterns:
            out = pat.sub(lambda m, lbl=label: self._tag(lbl, m.group(0)), out)
        return out

    def redact_value(self, value: Any, key_hint: Optional[str] = None) -> Any:
        """Recursively redact `value` without mutating caller containers."""
        if isinstance(value, dict):
            return {
                k: self.redact_value(v, key_hint=str(k))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.redact_value(item, key_hint=key_hint) for item in value]
        if isinstance(value, tuple):
            return [self.redact_value(item, key_hint=key_hint) for item in value]

        if self._is_sensitive_key(key_hint):
            if value is None:
                return None
            return self._tag(self._normalize_key(str(key_hint)), str(value))

        if isinstance(value, str):
            return self.redact_string(value)
        return value

    def redact_dict(self, mapping: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Return a redacted shallow/deep copy of `mapping` safe for persistence and audit logs."""
        if not isinstance(mapping, dict):
            return {}
        return self.redact_value(mapping)
