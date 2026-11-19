"""
gatekeep/control_plane.py

Enterprise Control Plane & Governance Layer for Gatekeep:
  1. `CentralPolicyRegistry` & `ToolPolicySpec`: Dynamically load/reload AST-validated
     policies, prerequisites, risk controls, and declarative Saga compensation rules
     across tools without modifying agent/microservice decorators.
  2. `EscalationRouter` & `EscalationTicket`: Human-in-the-loop (HITL) approval routing
     for `Verdict.ESCALATE`, dispatching Slack/webhook notifications and persisting
     cryptographic approval tokens directly to live or store-backed sessions.
  3. `SagaRecoveryDaemon`: Out-of-band crash sweeper that detects orphaned/stale
     uncommitted Saga transactions across durable `SessionStateStore`s and executes
     deterministic LIFO compensation rollbacks automatically.
  4. `AuditVault`: Multi-session SHA-256 hash-chain verification, compliance querying,
     and JSONL audit export.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

from gatekeep.policy import PolicySyntaxError, SafePolicyEvaluator
from gatekeep.redaction import (
    SensitiveDataRedactor,
    canonical_action_fingerprint,
    hash_secret_token,
)

logger = logging.getLogger("gatekeep.control_plane")


# ── Central Policy Registry ───────────────────────────────────────────────────


@dataclass(frozen=True)
class ToolPolicySpec:
    """
    Declarative runtime governance policy for a single tool (or wildcard `"*"`).
    Managed centrally and overlaid onto registered `ToolDefinition`s at evaluation time.
    """

    tool_name: str
    enabled: bool = True
    mode: Optional[str] = None
    provides: Optional[Tuple[str, ...]] = None
    requires: Optional[Tuple[str, ...]] = None
    provenance_args: Optional[Tuple[str, ...]] = None
    policy: Optional[str] = None
    requires_approval: Optional[bool] = None
    compensates_with: Optional[str] = None
    compensation_args: Optional[Dict[str, Any]] = None
    risk_level: Optional[str] = None
    description: Optional[str] = None
    max_calls_per_minute: Optional[int] = None
    max_cumulative_amount: Optional[float] = None
    amount_arg: Optional[str] = None
    global_scope: bool = False
    allow_secrets: bool = False
    allow_private_urls: bool = False
    allow_sensitive_paths: bool = False
    allow_destructive_sql: bool = False
    allow_shell: bool = False

    def __post_init__(self) -> None:
        if self.policy and self.policy.strip():
            # Fail fast on malformed or unsafe declarative policy syntax
            SafePolicyEvaluator(self.policy)
        if self.max_calls_per_minute is not None and int(self.max_calls_per_minute) < 1:
            raise ValueError("max_calls_per_minute must be >= 1")
        if self.max_cumulative_amount is not None and float(self.max_cumulative_amount) < 0:
            raise ValueError("max_cumulative_amount must be >= 0")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "enabled": self.enabled,
            "mode": self.mode,
            "provides": list(self.provides) if self.provides is not None else None,
            "requires": list(self.requires) if self.requires is not None else None,
            "provenance_args": list(self.provenance_args) if self.provenance_args is not None else None,
            "policy": self.policy,
            "requires_approval": self.requires_approval,
            "compensates_with": self.compensates_with,
            "compensation_args": dict(self.compensation_args) if self.compensation_args is not None else None,
            "risk_level": self.risk_level,
            "description": self.description,
            "max_calls_per_minute": self.max_calls_per_minute,
            "max_cumulative_amount": self.max_cumulative_amount,
            "amount_arg": self.amount_arg,
            "global_scope": self.global_scope,
            "allow_secrets": self.allow_secrets,
            "allow_private_urls": self.allow_private_urls,
            "allow_sensitive_paths": self.allow_sensitive_paths,
            "allow_destructive_sql": self.allow_destructive_sql,
            "allow_shell": self.allow_shell,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolPolicySpec":
        def _opt_tuple(val: Any) -> Optional[Tuple[str, ...]]:
            if val is None:
                return None
            return tuple(str(x) for x in val)

        comp_args = data.get("compensation_args")
        max_calls = data.get("max_calls_per_minute")
        max_amt = data.get("max_cumulative_amount")
        return cls(
            tool_name=str(data["tool_name"]),
            enabled=bool(data.get("enabled", True)),
            mode=data.get("mode"),
            provides=_opt_tuple(data.get("provides")),
            requires=_opt_tuple(data.get("requires")),
            provenance_args=_opt_tuple(data.get("provenance_args")),
            policy=data.get("policy"),
            requires_approval=data.get("requires_approval"),
            compensates_with=data.get("compensates_with"),
            compensation_args=dict(comp_args) if isinstance(comp_args, dict) else None,
            risk_level=data.get("risk_level"),
            description=data.get("description"),
            max_calls_per_minute=int(max_calls) if max_calls is not None else None,
            max_cumulative_amount=float(max_amt) if max_amt is not None else None,
            amount_arg=data.get("amount_arg"),
            global_scope=bool(data.get("global_scope", False)),
            allow_secrets=bool(data.get("allow_secrets", False)),
            allow_private_urls=bool(data.get("allow_private_urls", False)),
            allow_sensitive_paths=bool(data.get("allow_sensitive_paths", False)),
            allow_destructive_sql=bool(data.get("allow_destructive_sql", False)),
            allow_shell=bool(data.get("allow_shell", False)),
        )


def _merge_unique(first: Any, second: Any) -> Optional[List[str]]:
    if first is None and second is None:
        return None
    merged: List[str] = []
    for src in (first, second):
        if src:
            for item in src:
                s = str(item)
                if s not in merged:
                    merged.append(s)
    return merged


def resolve_effective_tool(tool_def: Any, policy_spec: Optional[ToolPolicySpec]) -> Any:
    """
    Merge a base `ToolDefinition` with an optional central `ToolPolicySpec` overlay.
    Returns a lightweight namespace carrying merged `requires`, `provides`,
    `provenance_args`, `mode`, `requires_approval`, `compensates_with`, etc.,
    while preserving references to `tool_def.check`, `tool_def.fn`, `tool_def.policy`.
    """
    if policy_spec is None:
        return tool_def

    base_requires = getattr(tool_def, "requires", None)
    base_provides = getattr(tool_def, "provides", None)
    base_prov = getattr(tool_def, "provenance_args", None)
    merged_prov = (
        list(policy_spec.provenance_args)
        if policy_spec.provenance_args is not None
        else (list(base_prov) if base_prov is not None else None)
    )
    req_approval = (
        policy_spec.requires_approval
        if policy_spec.requires_approval is not None
        else getattr(tool_def, "requires_approval", False)
    )

    return SimpleNamespace(
        name=getattr(tool_def, "name", policy_spec.tool_name),
        description=policy_spec.description or getattr(tool_def, "description", ""),
        fn=getattr(tool_def, "fn", None),
        mode=policy_spec.mode or getattr(tool_def, "mode", None),
        provides=_merge_unique(base_provides, policy_spec.provides),
        requires=_merge_unique(base_requires, policy_spec.requires),
        provenance_args=merged_prov,
        check=getattr(tool_def, "check", None),
        policy=getattr(tool_def, "policy", None),
        central_policy=policy_spec.policy,
        requires_approval=bool(req_approval),
        compensates_with=policy_spec.compensates_with or getattr(tool_def, "compensates_with", None),
        compensation_args=(
            policy_spec.compensation_args
            if policy_spec.compensation_args is not None
            else getattr(tool_def, "compensation_args", None)
        ),
        on_rollback=getattr(tool_def, "on_rollback", None),
        enabled=policy_spec.enabled,
        risk_level=policy_spec.risk_level or getattr(tool_def, "risk_level", "LOW"),
        max_calls_per_minute=policy_spec.max_calls_per_minute,
        max_cumulative_amount=policy_spec.max_cumulative_amount,
        amount_arg=policy_spec.amount_arg,
        global_scope=policy_spec.global_scope,
        allow_secrets=policy_spec.allow_secrets,
        allow_private_urls=policy_spec.allow_private_urls,
        allow_sensitive_paths=policy_spec.allow_sensitive_paths,
        allow_destructive_sql=policy_spec.allow_destructive_sql,
        allow_shell=policy_spec.allow_shell,
    )


class CentralPolicyRegistry:
    """
    Thread-safe, hot-reloadable central policy registry for Gatekeep Control Plane.
    Enforces policy validation upfront so bad rules cannot slip into production.

    When `session_store` is provided, all policy mutations persist atomically via
    `save_control_doc("central_policy_registry", ...)` so policies survive worker
    restarts and synchronize across horizontally scaled replicas.
    """

    _CONTROL_NAMESPACE = "central_policy_registry"

    def __init__(
        self,
        specs: Optional[List[ToolPolicySpec]] = None,
        session_store: Optional[Any] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._store = session_store
        self._policies: Dict[str, ToolPolicySpec] = {}
        self._version: int = 1
        loaded = self._load_from_store()
        if not loaded and specs:
            for spec in specs:
                self._policies[spec.tool_name] = spec
            self._save_to_store()

    def _load_from_store(self) -> bool:
        if self._store is None or not hasattr(self._store, "load_control_doc"):
            return False
        doc = self._store.load_control_doc(self._CONTROL_NAMESPACE)
        if not doc or not isinstance(doc, dict):
            return False
        tools = doc.get("tools", {})
        parsed: Dict[str, ToolPolicySpec] = {}
        for tool_name, item in tools.items():
            payload = dict(item)
            payload.setdefault("tool_name", str(tool_name))
            parsed[str(tool_name)] = ToolPolicySpec.from_dict(payload)
        self._policies = parsed
        self._version = int(doc.get("version", 1))
        return True

    def _save_to_store(self) -> None:
        if self._store is None or not hasattr(self._store, "save_control_doc"):
            return
        self._store.save_control_doc(
            self._CONTROL_NAMESPACE,
            {
                "version": self._version,
                "tools": {k: v.to_dict() for k, v in sorted(self._policies.items())},
            },
        )

    @property
    def version(self) -> int:
        with self._lock:
            self._load_from_store()
            return self._version

    def set_policy(self, spec: ToolPolicySpec) -> int:
        with self._lock:
            self._load_from_store()
            self._policies[spec.tool_name] = spec
            self._version += 1
            self._save_to_store()
            return self._version

    def remove_policy(self, tool_name: str) -> bool:
        with self._lock:
            self._load_from_store()
            existed = tool_name in self._policies
            self._policies.pop(tool_name, None)
            if existed:
                self._version += 1
                self._save_to_store()
            return existed

    def get_policy(self, tool_name: str) -> Optional[ToolPolicySpec]:
        with self._lock:
            self._load_from_store()
            return self._policies.get(tool_name) or self._policies.get("*")

    def list_policies(self) -> List[ToolPolicySpec]:
        with self._lock:
            self._load_from_store()
            return [self._policies[k] for k in sorted(self._policies.keys())]

    def export_dict(self) -> Dict[str, Any]:
        with self._lock:
            self._load_from_store()
            return {
                "version": self._version,
                "tools": {k: v.to_dict() for k, v in sorted(self._policies.items())},
            }

    def load_dict(self, config: Dict[str, Any], replace: bool = False) -> int:
        """
        Load policies atomically from a dict of either:
          `{"tools": {"refund_order": {"policy": "amount <= 500", ...}}}`
        or `{ "refund_order": {...} }`.
        Validates all expressions before swapping state.
        """
        raw_tools = config.get("tools", config)
        if not isinstance(raw_tools, dict):
            raise ValueError("Policy configuration must map tool names to policy objects.")

        parsed: Dict[str, ToolPolicySpec] = {}
        for tool_name, item in raw_tools.items():
            if isinstance(item, ToolPolicySpec):
                parsed[tool_name] = item
                continue
            if not isinstance(item, dict):
                raise PolicySyntaxError(f"Invalid policy spec for '{tool_name}': expected dict.")
            payload = dict(item)
            payload.setdefault("tool_name", str(tool_name))
            spec = ToolPolicySpec.from_dict(payload)
            parsed[spec.tool_name] = spec

        with self._lock:
            self._load_from_store()
            if replace:
                self._policies = parsed
            else:
                self._policies.update(parsed)
            self._version += 1
            self._save_to_store()
            return self._version

    def load_json(self, raw_json: str, replace: bool = False) -> int:
        return self.load_dict(json.loads(raw_json), replace=replace)

    def load_file(self, path: str | Path, replace: bool = True) -> int:
        content = Path(path).read_text(encoding="utf-8")
        return self.load_json(content, replace=replace)


# ── Human-in-the-Loop Escalation Router ───────────────────────────────────────


@dataclass
class EscalationTicket:
    """Represents a paused tool call awaiting human operator decision."""

    ticket_id: str
    session_id: str
    tool_name: str
    arguments: Dict[str, Any]
    reason: str
    approval_token: str = ""
    approval_token_hash: str = ""
    action_fingerprint: str = ""
    requested_by: Optional[str] = None
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED, EXPIRED
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    decided_by: Optional[str] = None
    decided_at: Optional[float] = None
    decision_note: str = ""

    def to_dict(self, include_token: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "ticket_id": self.ticket_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "arguments": dict(self.arguments),
            "reason": self.reason,
            "approval_token_hash": self.approval_token_hash,
            "action_fingerprint": self.action_fingerprint,
            "requested_by": self.requested_by,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "decision_note": self.decision_note,
        }
        if include_token and self.approval_token:
            payload["approval_token"] = self.approval_token
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EscalationTicket":
        tok = str(data.get("approval_token", ""))
        tok_hash = str(data.get("approval_token_hash", "")) or (hash_secret_token(tok) if tok else "")
        return cls(
            ticket_id=str(data["ticket_id"]),
            session_id=str(data["session_id"]),
            tool_name=str(data["tool_name"]),
            arguments=dict(data.get("arguments") or {}),
            reason=str(data.get("reason", "")),
            approval_token=tok,
            approval_token_hash=tok_hash,
            action_fingerprint=str(data.get("action_fingerprint", "")),
            requested_by=str(data["requested_by"]) if data.get("requested_by") is not None else None,
            status=str(data.get("status", "PENDING")),
            created_at=float(data.get("created_at", time.time())),
            expires_at=float(data.get("expires_at", 0.0)),
            decided_by=data.get("decided_by"),
            decided_at=float(data["decided_at"]) if data.get("decided_at") is not None else None,
            decision_note=str(data.get("decision_note", "")),
        )


class EscalationRouter:
    """
    Coordinates `Verdict.ESCALATE` events with external reviewers (Slack, PagerDuty,
    custom webhooks) and issues single-use, action-bound approval tokens into Gatekeep sessions.

    Security & Compliance properties:
    - Never persists plaintext `approval_token` to `session_store` (stores only SHA-256 hash).
    - Enforces Separation of Duties (`requested_by != approver`).
    - Redacts sensitive PII/secrets on stored & notified ticket arguments when `redactor` is set,
      while preserving raw `action_fingerprint` for exact replay binding.
    """

    _CONTROL_NAMESPACE = "escalation_tickets"

    def __init__(
        self,
        default_ttl_seconds: float = 900.0,
        session_store: Optional[Any] = None,
        redactor: Optional[SensitiveDataRedactor] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._default_ttl = default_ttl_seconds
        self._store = session_store
        self.redactor: Optional[SensitiveDataRedactor] = redactor
        self._tickets: Dict[str, EscalationTicket] = {}
        self._listeners: List[Callable[[EscalationTicket], None]] = []
        self._load_from_store()

    def _load_from_store(self) -> None:
        if self._store is None or not hasattr(self._store, "load_control_doc"):
            return
        doc = self._store.load_control_doc(self._CONTROL_NAMESPACE)
        if not doc or not isinstance(doc, dict):
            return
        raw_tickets = doc.get("tickets", {})
        merged: Dict[str, EscalationTicket] = {}
        for tid, tdata in raw_tickets.items():
            ticket = EscalationTicket.from_dict(tdata)
            # Keep in-memory plaintext token on same worker if already generated & not stored on disk
            prev = self._tickets.get(str(tid))
            if prev and prev.approval_token and not ticket.approval_token:
                if not ticket.approval_token_hash or ticket.approval_token_hash == prev.approval_token_hash:
                    ticket.approval_token = prev.approval_token
            merged[str(tid)] = ticket
        self._tickets = merged

    def _save_to_store(self) -> None:
        if self._store is None or not hasattr(self._store, "save_control_doc"):
            return
        # Never persist plaintext approval_token at rest; store only approval_token_hash
        self._store.save_control_doc(
            self._CONTROL_NAMESPACE,
            {
                "tickets": {
                    tid: t.to_dict(include_token=False)
                    for tid, t in self._tickets.items()
                }
            },
        )

    def add_listener(self, handler: Callable[[EscalationTicket], None]) -> None:
        """Register a callback (Slack/webhook notifier) invoked on new escalations."""
        with self._lock:
            self._listeners.append(handler)

    def create_ticket(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        reason: str,
        ttl_seconds: Optional[float] = None,
        requested_by: Optional[str] = None,
    ) -> EscalationTicket:
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        raw_args = dict(arguments)
        action_fp = canonical_action_fingerprint(tool_name, raw_args)
        safe_args = self.redactor.redact_dict(raw_args) if self.redactor is not None else raw_args
        safe_reason = self.redactor.redact_string(reason) if self.redactor is not None else reason
        tok = secrets.token_urlsafe(24)

        ticket = EscalationTicket(
            ticket_id=f"esc_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            tool_name=tool_name,
            arguments=safe_args,
            reason=safe_reason,
            approval_token=tok,
            approval_token_hash=hash_secret_token(tok),
            action_fingerprint=action_fp,
            requested_by=requested_by,
            created_at=now,
            expires_at=now + ttl,
        )
        with self._lock:
            self._load_from_store()
            self._tickets[ticket.ticket_id] = ticket
            self._save_to_store()
            listeners = list(self._listeners)

        for handler in listeners:
            try:
                handler(ticket)
            except Exception as exc:
                logger.warning(f"[EscalationRouter] Listener raised error for {ticket.ticket_id}: {exc}")

        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[EscalationTicket]:
        with self._lock:
            self._load_from_store()
            return self._tickets.get(ticket_id)

    def list_pending(self, session_id: Optional[str] = None) -> List[EscalationTicket]:
        now = time.time()
        with self._lock:
            self._load_from_store()
            pending: List[EscalationTicket] = []
            expired_any = False
            for t in self._tickets.values():
                if t.status == "PENDING" and t.expires_at and now > t.expires_at:
                    t.status = "EXPIRED"
                    expired_any = True
                    continue
                if t.status == "PENDING" and (session_id is None or t.session_id == session_id):
                    pending.append(t)
            if expired_any:
                self._save_to_store()
            return pending

    def approve(
        self,
        ticket_id: str,
        approver: str,
        gate: Optional[Any] = None,
        session_store: Optional[Any] = None,
        note: str = "",
    ) -> EscalationTicket:
        """
        Approve a pending escalation ticket, verify Separation of Duties (`approver != requested_by`),
        and grant a single-use SHA-256 + action-fingerprint bound token on the target session.
        """
        now = time.time()
        with self._lock:
            self._load_from_store()
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise KeyError(f"Unknown escalation ticket: '{ticket_id}'.")
            if ticket.status == "PENDING" and ticket.expires_at and now > ticket.expires_at:
                ticket.status = "EXPIRED"
                self._save_to_store()
            if ticket.status != "PENDING":
                raise RuntimeError(
                    f"Cannot approve ticket '{ticket_id}' in status '{ticket.status}'."
                )
            if ticket.requested_by and approver:
                req_norm = ticket.requested_by.strip().lower()
                app_norm = approver.strip().lower()
                app_bare = app_norm.split(":", 1)[-1] if ":" in app_norm else app_norm
                if req_norm == app_norm or req_norm == app_bare:
                    raise PermissionError(
                        f"Separation of Duties violation: requester '{ticket.requested_by}' cannot self-approve ticket '{ticket_id}'."
                    )

            # On cross-worker approvals where plaintext token wasn't stored at rest,
            # mint a fresh one-time token whose SHA-256 hash is committed to the gate.
            if not ticket.approval_token:
                ticket.approval_token = secrets.token_urlsafe(24)
            ticket.approval_token_hash = hash_secret_token(ticket.approval_token)
            ticket.status = "APPROVED"
            ticket.decided_by = approver
            ticket.decided_at = now
            ticket.decision_note = note
            self._save_to_store()

        fp = ticket.action_fingerprint or canonical_action_fingerprint(ticket.tool_name, ticket.arguments)
        target_store = session_store if session_store is not None else self._store
        if gate is not None:
            gate.grant_approval(ticket.approval_token, action_fingerprint=fp)
        elif target_store is not None:
            from gatekeep.gate import PreExecutionGate

            with target_store.session_lock(ticket.session_id):
                loaded_gate = PreExecutionGate.from_store(
                    session_id=ticket.session_id,
                    session_store=target_store,
                )
                loaded_gate.grant_approval(ticket.approval_token, action_fingerprint=fp)
                loaded_gate.save()

        return ticket

    def reject(self, ticket_id: str, approver: str, reason: str = "") -> EscalationTicket:
        now = time.time()
        with self._lock:
            self._load_from_store()
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise KeyError(f"Unknown escalation ticket: '{ticket_id}'.")
            if ticket.status != "PENDING":
                raise RuntimeError(
                    f"Cannot reject ticket '{ticket_id}' in status '{ticket.status}'."
                )
            ticket.status = "REJECTED"
            ticket.decided_by = approver
            ticket.decided_at = now
            ticket.decision_note = reason
            self._save_to_store()
            return ticket


class WebhookEscalationNotifier:
    """
    Production HTTP webhook & Slack Block Kit notifier for `EscalationRouter`.

    Usage:
        notifier = WebhookEscalationNotifier(
            url="https://hooks.slack.com/services/...",
            signing_secret="whsec_...",
            payload_format="slack",
            approve_base_url="https://gatekeep.internal",
        )
        router.add_listener(notifier)
    """

    def __init__(
        self,
        url: str,
        signing_secret: Optional[str] = None,
        payload_format: str = "json",
        timeout_s: float = 5.0,
        approve_base_url: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        interactive_actions: bool = False,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"Webhook URL must start with http:// or https://, got '{url}'.")
        fmt = payload_format.lower().strip()
        if fmt not in ("json", "slack"):
            raise ValueError(f"Unsupported payload_format '{payload_format}'. Use 'json' or 'slack'.")

        self.url = url
        self.signing_secret = signing_secret
        self.payload_format = fmt
        self.timeout_s = float(timeout_s)
        self.approve_base_url = approve_base_url.rstrip("/") if approve_base_url else None
        self.extra_headers = dict(extra_headers or {})
        self.interactive_actions = bool(interactive_actions)

    @staticmethod
    def compute_signature(secret: str, body: bytes) -> str:
        """Compute `sha256=<hex>` HMAC signature header for webhook verification."""
        digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def build_payload(self, ticket: EscalationTicket) -> Dict[str, Any]:
        """Serialize an `EscalationTicket` into signed JSON or Slack Block Kit format."""
        actions: Dict[str, str] = {}
        if self.approve_base_url:
            actions = {
                "approve_url": f"{self.approve_base_url}/admin/escalations/{ticket.ticket_id}/approve",
                "reject_url": f"{self.approve_base_url}/admin/escalations/{ticket.ticket_id}/reject",
            }

        if self.payload_format == "slack":
            args_preview = json.dumps(ticket.arguments, default=str)
            if len(args_preview) > 400:
                args_preview = args_preview[:397] + "..."
            blocks: List[Dict[str, Any]] = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "Gatekeep Escalation Required"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Tool:*\n`{ticket.tool_name}`"},
                        {"type": "mrkdwn", "text": f"*Session:*\n`{ticket.session_id}`"},
                        {"type": "mrkdwn", "text": f"*Ticket:*\n`{ticket.ticket_id}`"},
                        {"type": "mrkdwn", "text": f"*Status:*\n`{ticket.status}`"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Reason:* {ticket.reason}\n*Arguments:* `{args_preview}`",
                    },
                },
            ]
            if self.interactive_actions:
                blocks.append(
                    {
                        "type": "actions",
                        "block_id": f"gatekeep_escalation_{ticket.ticket_id}",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "Approve"},
                                "style": "primary",
                                "action_id": "approve_escalation",
                                "value": ticket.ticket_id,
                            },
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "Reject"},
                                "style": "danger",
                                "action_id": "reject_escalation",
                                "value": ticket.ticket_id,
                            },
                        ],
                    }
                )
            if actions:
                blocks.append(
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": (
                                    f"Approve: `{actions['approve_url']}` | "
                                    f"Reject: `{actions['reject_url']}`"
                                ),
                            }
                        ],
                    }
                )
            return {
                "text": f"Gatekeep approval required for '{ticket.tool_name}' (ticket {ticket.ticket_id})",
                "blocks": blocks,
            }

        payload: Dict[str, Any] = {
            "event": "gatekeep.escalation.created",
            "ticket": ticket.to_dict(),
        }
        if actions:
            payload["actions"] = actions
        return payload

    def __call__(self, ticket: EscalationTicket) -> int:
        payload = self.build_payload(ticket)
        body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "slim-schema-gatekeep/0.2",
            "X-Slim-Timestamp": str(int(time.time())),
        }
        if self.signing_secret:
            headers["X-Slim-Signature"] = self.compute_signature(self.signing_secret, body)
        headers.update(self.extra_headers)

        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            return int(getattr(resp, "status", 200))


# ── Out-of-Band Saga Recovery Daemon ──────────────────────────────────────────


@dataclass
class SweepReport:
    """Result summary produced by a `SagaRecoveryDaemon` sweep pass."""

    scanned_sessions: int
    stale_sessions_found: int
    recovered_sessions: int
    failed_sessions: int
    details: List[Dict[str, Any]] = field(default_factory=list)


class SagaRecoveryDaemon:
    """
    Out-of-band Saga transaction monitor & crash sweeper.
    Detects abandoned sessions in `SessionStateStore` with uncommitted `SagaStep`s
    older than `stale_after_seconds` and triggers LIFO compensation rollbacks cleanly.
    """

    def __init__(
        self,
        session_store: Any,
        registry: Optional[Any] = None,
        policy_registry: Optional[CentralPolicyRegistry] = None,
        stale_after_seconds: float = 300.0,
        poll_interval_seconds: float = 15.0,
    ) -> None:
        self.session_store = session_store
        self.registry = registry
        self.policy_registry = policy_registry
        self.stale_after_seconds = stale_after_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def sweep_once(self, now: Optional[float] = None) -> SweepReport:
        """Scan stored sessions and roll back any stale uncommitted Saga stacks."""
        from gatekeep.gate import PreExecutionGate
        from gatekeep.registry import ToolRegistry

        current_time = now if now is not None else time.time()
        target_reg = self.registry if self.registry is not None else ToolRegistry.instance()
        session_ids = self.session_store.list_sessions()

        stale_found = 0
        recovered = 0
        failed = 0
        details: List[Dict[str, Any]] = []

        for sid in session_ids:
            snap = self.session_store.load(sid)
            if not isinstance(snap, dict):
                continue
            updated_at = float(snap.get("updated_at", current_time))
            saga_snap = (snap.get("ledger") or {}).get("saga", {})
            pending_stack = saga_snap.get("stack", [])
            pending_in_flight = saga_snap.get("in_flight", {})
            if (not pending_stack and not pending_in_flight) or (
                current_time - updated_at
            ) < self.stale_after_seconds:
                continue

            stale_found += 1
            try:
                with self.session_store.session_lock(sid, timeout_s=5.0):
                    # Re-check inside lock to avoid racing an active worker that just saved/committed
                    latest = self.session_store.load(sid)
                    if not isinstance(latest, dict):
                        continue
                    latest_updated = float(latest.get("updated_at", current_time))
                    latest_saga = (latest.get("ledger") or {}).get("saga", {})
                    latest_stack = latest_saga.get("stack", [])
                    latest_in_flight = latest_saga.get("in_flight", {})
                    if (not latest_stack and not latest_in_flight) or (
                        current_time - latest_updated
                    ) < self.stale_after_seconds:
                        continue

                    gate = PreExecutionGate.from_store(
                        session_id=sid,
                        session_store=self.session_store,
                        registry=target_reg,
                        policy_registry=self.policy_registry,
                    )
                    summary = gate.rollback()
                    if summary.success:
                        recovered += 1
                    else:
                        failed += 1
                    details.append({
                        "session_id": sid,
                        "success": summary.success,
                        "compensated_steps": summary.compensated_steps,
                        "failed_steps": summary.failed_steps,
                    })
            except Exception as exc:
                failed += 1
                logger.error(f"[SagaRecoveryDaemon] Failed recovering session '{sid}': {exc}")
                details.append({
                    "session_id": sid,
                    "success": False,
                    "error": str(exc),
                })

        return SweepReport(
            scanned_sessions=len(session_ids),
            stale_sessions_found=stale_found,
            recovered_sessions=recovered,
            failed_sessions=failed,
            details=details,
        )

    def _run_loop(self) -> None:
        while not self._stop_event.wait(timeout=self.poll_interval_seconds):
            try:
                self.sweep_once()
            except Exception as exc:
                logger.error(f"[SagaRecoveryDaemon] Sweep iteration failed: {exc}")

    def start(self) -> None:
        """Start background recovery sweeper thread (idempotent)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="slim-saga-recovery-daemon",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout_s: float = 5.0) -> None:
        """Signal background sweeper thread to exit cleanly."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout_s)
            self._thread = None


# ── Audit Vault Query & Verification ──────────────────────────────────────────


class AuditVault:
    """
    Searchable, tamper-evident compliance query & SHA-256 verification facade
    across all persisted Gatekeep sessions and append-only audit streams.
    """

    def __init__(self, session_store: Any) -> None:
        self.session_store = session_store

    @staticmethod
    def _verify_receipt_dicts(receipts: List[Dict[str, Any]]) -> bool:
        from gatekeep.gate import AuditReceipt, PreExecutionGate

        prev = "0" * 64
        for raw in receipts:
            r = AuditReceipt.from_dict(raw) if isinstance(raw, dict) else raw
            if r.prev_hash != prev:
                return False
            expected = PreExecutionGate._compute_hash(
                timestamp=r.timestamp,
                session_id=r.session_id,
                turn=r.turn,
                tool_name=r.tool_name,
                arguments=r.arguments,
                verdict=r.verdict,
                rule_triggered=r.rule_triggered,
                reason=r.reason,
                prev_hash=prev,
                actor_id=r.actor_id,
                shadow=r.shadow,
                would_verdict=r.would_verdict,
            )
            if r.receipt_hash != expected:
                return False
            prev = r.receipt_hash
        return True

    def verify_all_chains(self) -> Dict[str, bool]:
        """
        Verify SHA-256 hash-chain integrity across active sessions AND deleted/archived
        sessions preserved in the store's append-only audit log.
        """
        from gatekeep.gate import PreExecutionGate

        results: Dict[str, bool] = {}
        active_sids = self.session_store.list_sessions()
        for sid in active_sids:
            gate = PreExecutionGate.from_store(sid, self.session_store, auto_persist=False)
            results[sid] = gate.verify_audit_chain()

        if hasattr(self.session_store, "load_audit_receipts"):
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for item in self.session_store.load_audit_receipts(limit=100_000):
                sid = str(item.get("session_id", "default"))
                grouped.setdefault(sid, []).append(item)
            for sid, items in grouped.items():
                log_ok = self._verify_receipt_dicts(items)
                results[sid] = (results[sid] and log_ok) if sid in results else log_ok
        return results

    def query(
        self,
        session_id: Optional[str] = None,
        verdict: Optional[Any] = None,
        tool_name: Optional[str] = None,
        rule_triggered: Optional[str] = None,
        actor_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Any]:
        """Return matching `AuditReceipt` objects across append-only logs & persisted sessions."""
        from gatekeep.gate import AuditReceipt, Verdict

        target_verdict = (
            verdict.value if isinstance(verdict, Verdict) else (str(verdict).upper() if verdict else None)
        )
        if hasattr(self.session_store, "load_audit_receipts"):
            raw_items = self.session_store.load_audit_receipts(
                session_id=session_id,
                verdict=target_verdict,
                tool_name=tool_name,
                rule_triggered=rule_triggered,
                actor_id=actor_id,
                limit=limit,
            )
            if raw_items:
                return [AuditReceipt.from_dict(item) for item in raw_items]

        sids = [session_id] if session_id else self.session_store.list_sessions()
        matches: List[AuditReceipt] = []

        for sid in sids:
            snap = self.session_store.load(sid)
            if not isinstance(snap, dict):
                continue
            raw_receipts = (snap.get("gate") or {}).get("receipts", [])
            for item in raw_receipts:
                if not isinstance(item, dict):
                    continue
                if target_verdict and str(item.get("verdict", "")).upper() != target_verdict:
                    continue
                if tool_name and item.get("tool_name") != tool_name:
                    continue
                if rule_triggered and item.get("rule_triggered") != rule_triggered:
                    continue
                if actor_id and item.get("actor_id") != actor_id:
                    continue
                matches.append(AuditReceipt.from_dict(item))
                if len(matches) >= limit:
                    return matches
        return matches

    def export_jsonl(
        self,
        output_path: Optional[str | Path] = None,
        session_id: Optional[str] = None,
    ) -> str:
        """Export matching audit receipts as newline-delimited JSON."""
        receipts = self.query(session_id=session_id, limit=100_000)
        lines = "\n".join(r.to_json() for r in receipts)
        if output_path is not None:
            Path(output_path).write_text(lines + ("\n" if lines else ""), encoding="utf-8")
        return lines
