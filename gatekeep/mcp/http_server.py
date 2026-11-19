"""
gatekeep/mcp/http_server.py

Networked Streamable-HTTP, SSE, and ASGI 3.0 MCP Transaction Gateway + Control Plane API.

Zero mandatory external web-framework dependencies:
  - `MCPHttpGateway` implements the pure ASGI 3.0 protocol (`await app(scope, receive, send)`),
    ready for Uvicorn, Hypercorn, Starlette/FastAPI mounting, or `httpx.ASGITransport`.
  - `create_http_server` / `serve_http` wrap the exact same request handler in Python's
    stdlib `ThreadingHTTPServer` so `slim-mcp-proxy --http 0.0.0.0:8080` works out of the box.

Security & Control Plane Endpoints:
  - Multi-tenant Bearer / `X-API-Key` authentication with strict `tenant:session_id` isolation
  - `GET  /healthz`                         Liveness / readiness probe
  - `POST /mcp`                             Streamable-HTTP MCP JSON-RPC 2.0 (single & batch)
  - `GET  /sse`  +  `POST /messages`        Classic MCP HTTP + Server-Sent Events transport
  - `GET|POST /admin/policies`              Live `CentralPolicyRegistry` inspection & hot-reload
  - `GET  /admin/escalations`               Pending HITL `EscalationTicket` queue
  - `POST /admin/escalations/{id}/approve`  Approve escalation & grant one-time token to store
  - `POST /admin/escalations/{id}/reject`   Reject escalation ticket
  - `GET  /admin/audit`                     Query tamper-evident `AuditVault` receipts
  - `GET  /admin/audit/verify`              Verify cryptographic SHA-256 hash-chain integrity
  - `POST /admin/recovery/sweep`            Trigger `SagaRecoveryDaemon.sweep_once()`
  - `GET  /dashboard`                       Self-contained Dark-Mode Control Plane Console
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac
import json
import logging
import queue as thread_queue
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

from gatekeep.control_plane import (
    AuditVault,
    CentralPolicyRegistry,
    SagaRecoveryDaemon,
    ToolPolicySpec,
)
from gatekeep.policy import PolicySyntaxError
from gatekeep.mcp.onboarding import simulate_policy_against_traces
from gatekeep.mcp.proxy import MCP_PROTOCOL_VERSION, MCPTransactionProxy

logger = logging.getLogger("gatekeep.mcp.http")


@dataclass
class _HttpResponse:
    status: int
    headers: Dict[str, str]
    body: bytes


VALID_ROLES = frozenset({"agent", "policy_admin", "approver", "auditor", "admin"})

_SCOPE_ROLES: Dict[str, frozenset[str]] = {
    "mcp": frozenset({"admin", "agent"}),
    "policies_read": frozenset({"admin", "policy_admin", "approver", "auditor"}),
    "policies_write": frozenset({"admin", "policy_admin"}),
    "escalations_read": frozenset({"admin", "approver", "auditor", "policy_admin"}),
    "escalations_decide": frozenset({"admin", "approver"}),
    "audit_read": frozenset({"admin", "auditor", "approver", "policy_admin"}),
    "recovery_sweep": frozenset({"admin", "policy_admin"}),
}


@dataclass(frozen=True)
class ApiPrincipal:
    """Role-scoped static credential bound to a tenant and optional actor identity."""

    tenant: str
    role: str = "admin"
    actor_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.role not in VALID_ROLES:
            raise ValueError(
                f"Invalid Gatekeep role {self.role!r}; expected one of {sorted(VALID_ROLES)}."
            )


@dataclass(frozen=True)
class AuthContext:
    """Verified caller identity extracted from API key or bearer JWT."""

    tenant: str
    role: str = "admin"
    actor_id: Optional[str] = None
    auth_method: str = "api_key"


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _verify_hs256_jwt(
    token: str,
    secret: str,
    *,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    max_skew_s: float = 30.0,
) -> Optional[AuthContext]:
    """Verify an HS256 JWT using pure Python stdlib HMAC-SHA256 and extract tenant/role/actor."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    hdr_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(hdr_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        sig_bytes = _b64url_decode(sig_b64)
    except Exception:
        return None

    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    if header.get("alg") != "HS256":
        return None

    signing_input = f"{hdr_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_sig, sig_bytes):
        return None

    now = time.time()
    exp = payload.get("exp")
    if exp is not None:
        try:
            if now > float(exp) + max_skew_s:
                return None
        except (TypeError, ValueError):
            return None
    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            if now < float(nbf) - max_skew_s:
                return None
        except (TypeError, ValueError):
            return None

    if issuer and payload.get("iss") != issuer:
        return None
    if audience:
        aud = payload.get("aud")
        valid_aud = (isinstance(aud, str) and aud == audience) or (
            isinstance(aud, list) and audience in aud
        )
        if not valid_aud:
            return None

    raw_role = payload.get("role")
    if raw_role is None and isinstance(payload.get("roles"), list) and payload["roles"]:
        raw_role = payload["roles"][0]
    role = str(raw_role) if raw_role is not None else "agent"
    if role not in VALID_ROLES:
        return None

    tenant = str(payload.get("tenant") or payload.get("org_id") or payload.get("tid") or "default")
    raw_actor = payload.get("sub") if payload.get("sub") is not None else payload.get("actor_id")
    actor_id = str(raw_actor) if raw_actor not in (None, "") else None
    return AuthContext(tenant=tenant, role=role, actor_id=actor_id, auth_method="jwt")


def parse_api_principals(
    specs: Optional[List[str]],
    *,
    default_role: str = "admin",
) -> Dict[str, ApiPrincipal]:
    """
    Parse credential specs into `ApiPrincipal` mappings.

    Supported formats:
      - `secret`
      - `tenant=secret`
      - `tenant:role=secret`
      - `tenant:role:actor_id=secret`
    """
    if default_role not in VALID_ROLES:
        raise ValueError(f"Invalid default_role {default_role!r}.")
    out: Dict[str, ApiPrincipal] = {}
    for idx, raw in enumerate(specs or []):
        item = raw.strip()
        if not item:
            continue
        if "=" in item:
            lhs, secret = item.split("=", 1)
            lhs_parts = [p.strip() for p in lhs.split(":")]
            tenant = lhs_parts[0] if lhs_parts and lhs_parts[0] else f"tenant_{idx + 1}"
            role = lhs_parts[1] if len(lhs_parts) >= 2 and lhs_parts[1] else default_role
            actor_id = lhs_parts[2] if len(lhs_parts) >= 3 and lhs_parts[2] else None
            token = secret.strip()
        else:
            tenant, role, actor_id, token = f"tenant_{idx + 1}", default_role, None, item
        if not token:
            raise ValueError(f"Empty API secret in credential spec: {raw!r}")
        out[token] = ApiPrincipal(tenant=tenant, role=role, actor_id=actor_id)
    return out


def _json_response(
    status: int,
    payload: Any,
    extra_headers: Optional[Dict[str, str]] = None,
) -> _HttpResponse:
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if extra_headers:
        headers.update(extra_headers)
    body = json.dumps(payload, default=str).encode("utf-8")
    return _HttpResponse(status=status, headers=headers, body=body)


def _text_response(
    status: int,
    text: str,
    content_type: str = "text/plain; charset=utf-8",
    extra_headers: Optional[Dict[str, str]] = None,
) -> _HttpResponse:
    headers = {"Content-Type": content_type}
    if extra_headers:
        headers.update(extra_headers)
    return _HttpResponse(status=status, headers=headers, body=text.encode("utf-8"))


class _GatewayMetrics:
    """Thread-safe Prometheus text-format (v0.0.4) counter registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.http_requests: Dict[Tuple[str, str, int], int] = {}
        self.tool_outcomes: Dict[str, int] = {
            "allowed": 0,
            "blocked": 0,
            "escalated": 0,
            "error": 0,
        }
        self.escalations: Dict[str, int] = {
            "created": 0,
            "approved": 0,
            "rejected": 0,
        }
        self.saga_rollbacks_total: int = 0
        self.recovery_sweeps_total: int = 0
        self.recovery_rolled_back_total: int = 0
        self.shadow_would_block: int = 0

    def inc_http(self, method: str, path: str, status: int) -> None:
        key = (method, path, int(status))
        with self._lock:
            self.http_requests[key] = self.http_requests.get(key, 0) + 1

    def observe_tool_response(self, rpc_frame: Dict[str, Any], rpc_resp: Optional[Dict[str, Any]]) -> None:
        if rpc_frame.get("method") != "tools/call" or not isinstance(rpc_resp, dict):
            return
        result = rpc_resp.get("result")
        if not isinstance(result, dict):
            with self._lock:
                self.tool_outcomes["error"] += 1
            return

        structured = result.get("structuredContent") if isinstance(result.get("structuredContent"), dict) else {}
        verdict = str(structured.get("verdict", "")).upper()
        rb = structured.get("rollback") or structured.get("auto_rollback")
        rolled_back = bool(isinstance(rb, dict) and rb.get("compensated_steps"))
        is_err = bool(result.get("isError"))

        with self._lock:
            if verdict == "BLOCK":
                self.tool_outcomes["blocked"] += 1
            elif verdict == "ESCALATE":
                self.tool_outcomes["escalated"] += 1
                self.escalations["created"] += 1
            elif is_err:
                self.tool_outcomes["error"] += 1
            else:
                self.tool_outcomes["allowed"] += 1
            if isinstance(result.get("_shadow"), dict):
                self.shadow_would_block += 1
            if rolled_back:
                self.saga_rollbacks_total += 1

    def inc_escalation(self, action: str) -> None:
        with self._lock:
            self.escalations[action] = self.escalations.get(action, 0) + 1

    def record_sweep(self, rolled_back: int) -> None:
        with self._lock:
            self.recovery_sweeps_total += 1
            self.recovery_rolled_back_total += int(rolled_back)

    def render_prometheus(
        self,
        active_sessions: int,
        pending_escalations: int,
        quarantined_tools: int = 0,
    ) -> str:
        with self._lock:
            lines: List[str] = [
                "# HELP slim_gateway_active_sessions Number of stored Gatekeep sessions.",
                "# TYPE slim_gateway_active_sessions gauge",
                f"slim_gateway_active_sessions {active_sessions}",
                "# HELP slim_gateway_pending_escalations Number of pending HITL escalation tickets.",
                "# TYPE slim_gateway_pending_escalations gauge",
                f"slim_gateway_pending_escalations {pending_escalations}",
                "# HELP slim_gateway_quarantined_tools Number of MCP tools quarantined for poisoning or schema rug-pull.",
                "# TYPE slim_gateway_quarantined_tools gauge",
                f"slim_gateway_quarantined_tools {quarantined_tools}",
                "# HELP slim_gateway_mcp_tool_calls_total MCP tool calls partitioned by Gatekeep outcome.",
                "# TYPE slim_gateway_mcp_tool_calls_total counter",
            ]
            for outcome, val in sorted(self.tool_outcomes.items()):
                lines.append(f'slim_gateway_mcp_tool_calls_total{{outcome="{outcome}"}} {val}')
            lines.extend(
                [
                    "# HELP slim_gateway_escalations_total Escalation lifecycle events.",
                    "# TYPE slim_gateway_escalations_total counter",
                ]
            )
            for action, val in sorted(self.escalations.items()):
                lines.append(f'slim_gateway_escalations_total{{action="{action}"}} {val}')
            lines.extend(
                [
                    "# HELP slim_gateway_saga_rollbacks_total Automatic Saga rollbacks triggered by tool errors/blocks.",
                    "# TYPE slim_gateway_saga_rollbacks_total counter",
                    f"slim_gateway_saga_rollbacks_total {self.saga_rollbacks_total}",
                    "# HELP slim_gateway_shadow_would_block_total Tool calls flagged by shadow mode that passed through.",
                    "# TYPE slim_gateway_shadow_would_block_total counter",
                    f"slim_gateway_shadow_would_block_total {self.shadow_would_block}",
                    "# HELP slim_gateway_recovery_sweeps_total Recovery sweeps executed.",
                    "# TYPE slim_gateway_recovery_sweeps_total counter",
                    f"slim_gateway_recovery_sweeps_total {self.recovery_sweeps_total}",
                    "# HELP slim_gateway_recovery_rolled_back_total Orphaned sagas rolled back by recovery sweeps.",
                    "# TYPE slim_gateway_recovery_rolled_back_total counter",
                    f"slim_gateway_recovery_rolled_back_total {self.recovery_rolled_back_total}",
                    "# HELP slim_gateway_http_requests_total Total HTTP requests handled by gateway.",
                    "# TYPE slim_gateway_http_requests_total counter",
                ]
            )
            for (method, path, status), val in sorted(self.http_requests.items()):
                safe_path = path.replace('"', "")
                lines.append(
                    f'slim_gateway_http_requests_total{{method="{method}",path="{safe_path}",status="{status}"}} {val}'
                )
        return "\n".join(lines) + "\n"


_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Gatekeep Control Plane</title>
<style>
  :root {
    --bg: #0b0f17; --card: #131a26; --border: #232d40;
    --text: #e6edf7; --muted: #8b9bb4; --accent: #38bdf8;
    --ok: #22c55e; --warn: #f59e0b; --err: #ef4444;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.5; }
  header { padding: 18px 28px; border-bottom: 1px solid var(--border);
           display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  h1 { margin: 0; font-size: 18px; letter-spacing: 0.2px; }
  .badge { font-size: 12px; padding: 3px 10px; border-radius: 999px;
           background: #172538; color: var(--accent); border: 1px solid #264163; }
  .badge.ok { color: var(--ok); border-color: #1f4d34; background: #0f291c; }
  .badge.err { color: var(--err); border-color: #5c1f24; background: #2c1215; }
  main { max-width: 1200px; margin: 0 auto; padding: 24px 28px; display: grid;
         grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 18px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
          padding: 18px; display: flex; flex-direction: column; gap: 12px; }
  .card.wide { grid-column: 1 / -1; }
  h2 { margin: 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  input, button { font: inherit; border-radius: 6px; border: 1px solid var(--border);
                  background: #0d131d; color: var(--text); padding: 7px 11px; }
  button { background: #1a273b; cursor: pointer; font-weight: 500; }
  button:hover { border-color: var(--accent); }
  button.ok { background: #133923; border-color: #216e43; }
  button.err { background: #3b151a; border-color: #7c262d; }
  pre { margin: 0; background: #090d14; padding: 12px; border-radius: 8px; overflow: auto;
        font-size: 12px; max-height: 280px; border: 1px solid var(--border); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
</style>
</head>
<body>
<header>
  <div class="row">
    <h1>Gatekeep Control Plane</h1>
    <span id="healthBadge" class="badge">Connecting...</span>
    <span id="auditBadge" class="badge">Audit Chain: Pending</span>
  </div>
  <div class="row">
    <input id="apiKey" type="password" placeholder="Optional Bearer API Key" size="26" />
    <button onclick="refreshAll()">Refresh</button>
    <button onclick="runSweep()">Sweep Stale Sagas</button>
  </div>
</header>
<main>
  <section class="card wide">
    <h2>Pending Human-in-the-Loop Escalations</h2>
    <div id="escalationsBody" class="mono">No pending escalations.</div>
  </section>
  <section class="card">
    <h2>Central Policy Registry</h2>
    <pre id="policiesPre">{}</pre>
  </section>
  <section class="card">
    <h2>Recent Audit Vault Receipts</h2>
    <pre id="auditPre">[]</pre>
  </section>
</main>
<script>
function authHeaders(extra) {
  const h = Object.assign({}, extra || {});
  const tok = document.getElementById('apiKey').value.trim();
  if (tok) h['Authorization'] = 'Bearer ' + tok;
  return h;
}
async function api(path, opts) {
  const res = await fetch(path, Object.assign({ headers: authHeaders(opts && opts.headers) }, opts));
  const txt = await res.text();
  try { return { ok: res.ok, status: res.status, data: JSON.parse(txt) }; }
  catch (_) { return { ok: res.ok, status: res.status, data: txt }; }
}
async function refreshAll() {
  const h = await api('/healthz');
  const hb = document.getElementById('healthBadge');
  hb.textContent = h.ok ? ('Online (' + h.data.sessions + ' sessions)') : 'Error ' + h.status;
  hb.className = 'badge ' + (h.ok ? 'ok' : 'err');

  const v = await api('/admin/audit/verify');
  const ab = document.getElementById('auditBadge');
  if (v.ok) {
    ab.textContent = v.data.valid ? 'Audit Chain: Verified' : 'Audit Chain: TAMPERED';
    ab.className = 'badge ' + (v.data.valid ? 'ok' : 'err');
  }

  const p = await api('/admin/policies');
  document.getElementById('policiesPre').textContent = JSON.stringify(p.data, null, 2);

  const a = await api('/admin/audit?limit=40');
  document.getElementById('auditPre').textContent = JSON.stringify(a.data, null, 2);

  const e = await api('/admin/escalations');
  const box = document.getElementById('escalationsBody');
  if (!e.ok) { box.textContent = JSON.stringify(e.data); return; }
  const tickets = e.data.tickets || [];
  if (!tickets.length) { box.textContent = 'No pending escalations.'; return; }
  box.innerHTML = '<table><tr><th>Ticket</th><th>Tool</th><th>Session</th><th>Reason</th><th>Action</th></tr>' +
    tickets.map(t => `<tr>
      <td class="mono">${t.ticket_id}</td>
      <td class="mono">${t.tool_name}</td>
      <td class="mono">${t.session_id}</td>
      <td>${t.reason}</td>
      <td class="row">
        <button class="ok" onclick="decide('${t.ticket_id}','approve')">Approve</button>
        <button class="err" onclick="decide('${t.ticket_id}','reject')">Reject</button>
      </td>
    </tr>`).join('') + '</table>';
}
async function decide(id, action) {
  await api(`/admin/escalations/${encodeURIComponent(id)}/${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approver: 'dashboard-operator' }),
  });
  await refreshAll();
}
async function runSweep() {
  const res = await api('/admin/recovery/sweep', { method: 'POST', body: '{}' });
  alert('Sweep complete: ' + JSON.stringify(res.data));
  await refreshAll();
}
refreshAll();
</script>
</body>
</html>
"""


class MCPHttpGateway:
    """
    Pure ASGI 3.0 HTTP / SSE / Streamable-HTTP MCP Gateway & Control Plane API.

    Wraps an `MCPTransactionProxy` with:
      - Bearer / `X-API-Key` multi-tenant authentication & session isolation
      - MCP Streamable-HTTP (`POST /mcp`) and SSE (`GET /sse` + `POST /messages`)
      - Live policy reload, escalation approval/rejection, audit query/verify,
        Saga recovery sweep, and a dark-mode Control Plane Dashboard.
    """

    def __init__(
        self,
        proxy: MCPTransactionProxy,
        *,
        api_keys: Optional[Dict[str, str]] = None,
        principals: Optional[Dict[str, ApiPrincipal]] = None,
        strict_rbac: Optional[bool] = None,
        jwt_secret: Optional[str] = None,
        jwt_issuer: Optional[str] = None,
        jwt_audience: Optional[str] = None,
        audit_vault: Optional[AuditVault] = None,
        recovery_daemon: Optional[SagaRecoveryDaemon] = None,
        dashboard_enabled: bool = True,
        cors_origins: Optional[str] = "*",
        slack_signing_secret: Optional[str] = None,
        slack_max_clock_skew_s: float = 300.0,
    ) -> None:
        self.proxy = proxy
        merged_principals: Dict[str, ApiPrincipal] = {
            token: ApiPrincipal(tenant=tenant, role="admin")
            for token, tenant in (api_keys or {}).items()
        }
        if principals:
            merged_principals.update(principals)
        self.principals: Dict[str, ApiPrincipal] = merged_principals
        self.api_keys: Dict[str, str] = {
            token: p.tenant for token, p in self.principals.items()
        }
        self.jwt_secret = jwt_secret
        self.jwt_issuer = jwt_issuer
        self.jwt_audience = jwt_audience
        self._auth_enabled = bool(self.principals or self.jwt_secret)
        has_scoped_roles = any(p.role != "admin" for p in self.principals.values())
        self.strict_rbac: bool = (
            bool(strict_rbac)
            if strict_rbac is not None
            else (has_scoped_roles or bool(self.jwt_secret))
        )
        self.audit_vault = audit_vault or AuditVault(proxy.session_store)
        self.recovery_daemon = recovery_daemon or SagaRecoveryDaemon(
            session_store=proxy.session_store,
            registry=proxy.registry,
            policy_registry=proxy.policy_registry,
        )
        self.dashboard_enabled = dashboard_enabled
        self.cors_origins = cors_origins
        self.slack_signing_secret = slack_signing_secret
        self.slack_max_clock_skew_s = float(slack_max_clock_skew_s)
        self.metrics = _GatewayMetrics()

        # Optional background recovery loop
        self._recovery_stop: Optional[threading.Event] = None
        self._recovery_thread: Optional[threading.Thread] = None

        # SSE channel registry: channel_key -> list of (loop_or_None, queue)
        self._sse_lock = threading.RLock()
        self._sse_channels: Dict[str, List[Tuple[Optional[asyncio.AbstractEventLoop], Any]]] = {}

    def start_recovery_daemon(self, interval_seconds: float = 30.0) -> None:
        """Start a background thread running `recovery_daemon.sweep_once()` periodically."""
        interval = max(0.05, float(interval_seconds))
        if self._recovery_thread is not None and self._recovery_thread.is_alive():
            return
        stop_event = threading.Event()
        self._recovery_stop = stop_event

        def _loop() -> None:
            while not stop_event.wait(interval):
                try:
                    report = self.recovery_daemon.sweep_once()
                    self.metrics.record_sweep(report.recovered_sessions)
                except Exception as exc:
                    logger.warning(f"[MCPHttpGateway] Background recovery sweep failed: {exc}")

        self._recovery_thread = threading.Thread(
            target=_loop,
            name="slim-saga-recovery-daemon",
            daemon=True,
        )
        self._recovery_thread.start()

    def stop_recovery_daemon(self, timeout_s: float = 3.0) -> None:
        """Stop the background recovery loop if running."""
        if self._recovery_stop is not None:
            self._recovery_stop.set()
        if self._recovery_thread is not None and self._recovery_thread.is_alive():
            self._recovery_thread.join(timeout=timeout_s)
        self._recovery_thread = None
        self._recovery_stop = None

    # ── Tenant Auth & Scoping Helpers ──────────────────────────────────────────

    @staticmethod
    def _normalize_headers(raw_headers: Any) -> Dict[str, str]:
        if isinstance(raw_headers, dict):
            return {str(k).lower(): str(v) for k, v in raw_headers.items()}
        out: Dict[str, str] = {}
        for k, v in raw_headers:
            k_str = k.decode("latin-1") if isinstance(k, bytes) else str(k)
            v_str = v.decode("latin-1") if isinstance(v, bytes) else str(v)
            out[k_str.lower()] = v_str
        return out

    def _authenticate(
        self,
        headers: Dict[str, str],
        query_params: Dict[str, List[str]],
    ) -> Tuple[Optional[AuthContext], Optional[_HttpResponse]]:
        if not self._auth_enabled:
            return AuthContext(tenant="default", role="admin", auth_method="anonymous"), None

        token = ""
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        elif "x-api-key" in headers:
            token = headers["x-api-key"].strip()
        elif "token" in query_params and query_params["token"]:
            token = query_params["token"][0].strip()

        if token:
            for configured_key, principal in self.principals.items():
                if hmac.compare_digest(token, configured_key):
                    return (
                        AuthContext(
                            tenant=principal.tenant,
                            role=principal.role,
                            actor_id=principal.actor_id,
                            auth_method="api_key",
                        ),
                        None,
                    )
            if self.jwt_secret:
                jwt_ctx = _verify_hs256_jwt(
                    token,
                    self.jwt_secret,
                    issuer=self.jwt_issuer,
                    audience=self.jwt_audience,
                )
                if jwt_ctx is not None:
                    return jwt_ctx, None

        return None, _json_response(
            401,
            {"error": "Unauthorized: invalid or missing credentials."},
            extra_headers={"WWW-Authenticate": "Bearer"},
        )

    def _authorize_role(self, auth_ctx: AuthContext, scope: str) -> Optional[_HttpResponse]:
        if not self.strict_rbac:
            return None
        allowed = _SCOPE_ROLES.get(scope)
        if allowed is not None and auth_ctx.role in allowed:
            return None
        return _json_response(
            403,
            {
                "error": (
                    f"Forbidden: role '{auth_ctx.role}' is not permitted for scope '{scope}'."
                )
            },
        )

    def _authenticate_for_scope(
        self,
        headers: Dict[str, str],
        query_params: Dict[str, List[str]],
        scope: str,
    ) -> Tuple[Optional[AuthContext], Optional[_HttpResponse]]:
        auth_ctx, auth_err = self._authenticate(headers, query_params)
        if auth_err is not None or auth_ctx is None:
            return None, auth_err or _json_response(401, {"error": "Unauthorized"})
        role_err = self._authorize_role(auth_ctx, scope)
        if role_err is not None:
            return None, role_err
        return auth_ctx, None

    def _scope_session_id(self, tenant: str, raw_session_id: Optional[str]) -> str:
        sid = str(raw_session_id or self.proxy.default_session_id)
        if not self._auth_enabled:
            return sid
        prefix = f"{tenant}:"
        return sid if sid.startswith(prefix) else f"{prefix}{sid}"

    def _tenant_owns_session(self, tenant: str, session_id: str) -> bool:
        if not self._auth_enabled:
            return True
        return session_id.startswith(f"{tenant}:")

    def _scope_jsonrpc_frame(
        self,
        tenant: str,
        frame: Dict[str, Any],
        header_session_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return a deep-copied JSON-RPC frame whose session_id & actor_id are bound to auth context."""
        scoped = copy.deepcopy(frame)
        params = scoped.get("params")
        if not isinstance(params, dict):
            return scoped

        meta = params.get("_meta")
        raw_sid: Optional[str] = None
        if isinstance(meta, dict) and meta.get("session_id"):
            raw_sid = str(meta["session_id"])
        elif params.get("session_id"):
            raw_sid = str(params["session_id"])
        elif header_session_id:
            raw_sid = header_session_id

        scoped_sid = self._scope_session_id(tenant, raw_sid)
        if isinstance(meta, dict) and ("session_id" in meta or header_session_id or self._auth_enabled):
            meta["session_id"] = scoped_sid
        elif "session_id" in params or header_session_id or self._auth_enabled:
            if scoped.get("method") in ("tools/call", "resources/read"):
                params.setdefault("_meta", {})["session_id"] = scoped_sid
            else:
                params["session_id"] = scoped_sid

        if actor_id and scoped.get("method") in ("tools/call", "resources/read"):
            params.setdefault("_meta", {})["actor_id"] = actor_id
        if idempotency_key and scoped.get("method") == "tools/call":
            params.setdefault("_meta", {}).setdefault("idempotency_key", idempotency_key)
        return scoped

    # ── SSE Fan-out ────────────────────────────────────────────────────────────

    def _register_sse_queue(
        self,
        keys: List[str],
        loop: Optional[asyncio.AbstractEventLoop],
        q: Any,
    ) -> None:
        with self._sse_lock:
            for key in keys:
                self._sse_channels.setdefault(key, []).append((loop, q))

    def _unregister_sse_queue(self, keys: List[str], q: Any) -> None:
        with self._sse_lock:
            for key in keys:
                items = self._sse_channels.get(key)
                if not items:
                    continue
                self._sse_channels[key] = [(lp, qq) for lp, qq in items if qq is not q]
                if not self._sse_channels[key]:
                    self._sse_channels.pop(key, None)

    def _publish_sse(self, keys: List[str], event_name: str, data: Any) -> None:
        payload = f"event: {event_name}\ndata: {json.dumps(data, default=str)}\n\n"
        with self._sse_lock:
            targets: List[Tuple[Optional[asyncio.AbstractEventLoop], Any]] = []
            seen: set[int] = set()
            for key in keys:
                for lp, qq in self._sse_channels.get(key, []):
                    if id(qq) not in seen:
                        seen.add(id(qq))
                        targets.append((lp, qq))

        for lp, qq in targets:
            if lp is not None:
                try:
                    lp.call_soon_threadsafe(qq.put_nowait, payload)
                except Exception:
                    pass
            else:
                try:
                    qq.put_nowait(payload)
                except Exception:
                    pass

    # ── Core Shared HTTP Router ────────────────────────────────────────────────

    def _with_cors(self, resp: _HttpResponse) -> _HttpResponse:
        if self.cors_origins:
            resp.headers.setdefault("Access-Control-Allow-Origin", self.cors_origins)
            resp.headers.setdefault(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization, X-API-Key, Mcp-Session-Id, Idempotency-Key",
            )
            resp.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        return resp

    @staticmethod
    def _parse_json_body(body: bytes) -> Tuple[Optional[Any], Optional[_HttpResponse]]:
        if not body.strip():
            return {}, None
        try:
            return json.loads(body.decode("utf-8")), None
        except Exception as exc:
            return None, _json_response(400, {"error": f"Invalid JSON body: {exc}"})

    async def _handle_jsonrpc_http(
        self,
        tenant: str,
        body: bytes,
        headers: Dict[str, str],
        publish_keys: Optional[List[str]] = None,
        actor_id: Optional[str] = None,
    ) -> _HttpResponse:
        data, err = self._parse_json_body(body)
        if err is not None:
            return err

        header_sid = headers.get("mcp-session-id")
        header_idem = headers.get("idempotency-key")
        if isinstance(data, list):
            if not data:
                return _json_response(400, {"error": "Empty JSON-RPC batch."})
            responses: List[Dict[str, Any]] = []
            for item in data:
                if not isinstance(item, dict):
                    responses.append(
                        {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
                    )
                    continue
                scoped = self._scope_jsonrpc_frame(
                    tenant,
                    item,
                    header_session_id=header_sid,
                    actor_id=actor_id,
                    idempotency_key=header_idem,
                )
                res = await self.proxy.ahandle_jsonrpc(scoped)
                self.metrics.observe_tool_response(scoped, res)
                if res is not None:
                    responses.append(res)
                    if publish_keys:
                        self._publish_sse(publish_keys, "message", res)
            return _json_response(200, responses)

        if not isinstance(data, dict):
            return _json_response(400, {"error": "JSON-RPC payload must be an object or array."})

        scoped = self._scope_jsonrpc_frame(
            tenant,
            data,
            header_session_id=header_sid,
            actor_id=actor_id,
            idempotency_key=header_idem,
        )
        res = await self.proxy.ahandle_jsonrpc(scoped)
        self.metrics.observe_tool_response(scoped, res)
        if res is None:
            return _HttpResponse(status=202, headers={"Content-Length": "0"}, body=b"")
        if publish_keys:
            self._publish_sse(publish_keys, "message", res)
        return _json_response(200, res)

    def _verify_slack_signature(self, headers: Dict[str, str], body: bytes) -> Optional[_HttpResponse]:
        if not self.slack_signing_secret:
            return _json_response(
                503,
                {"error": "Slack interactive actions disabled: no slack_signing_secret configured."},
            )
        ts_raw = headers.get("x-slack-request-timestamp", "").strip()
        sig = headers.get("x-slack-signature", "").strip()
        if not ts_raw or not sig:
            return _json_response(401, {"error": "Missing Slack signature headers."})
        try:
            ts = float(ts_raw)
        except ValueError:
            return _json_response(401, {"error": "Invalid X-Slack-Request-Timestamp."})
        if abs(time.time() - ts) > self.slack_max_clock_skew_s:
            return _json_response(401, {"error": "Expired Slack request timestamp."})

        basestring = f"v0:{ts_raw}:{body.decode('utf-8', errors='replace')}".encode("utf-8")
        expected = "v0=" + hmac.new(
            self.slack_signing_secret.encode("utf-8"),
            basestring,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return _json_response(401, {"error": "Invalid Slack signature."})
        return None

    def _handle_slack_actions(self, headers: Dict[str, str], body: bytes) -> _HttpResponse:
        sig_err = self._verify_slack_signature(headers, body)
        if sig_err is not None:
            return sig_err

        raw_str = body.decode("utf-8", errors="replace")
        content_type = headers.get("content-type", "").lower()
        payload_obj: Optional[Dict[str, Any]] = None

        if "application/x-www-form-urlencoded" in content_type or raw_str.startswith("payload="):
            form = urllib.parse.parse_qs(raw_str, keep_blank_values=False)
            raw_payload = (form.get("payload") or [""])[0]
            try:
                payload_obj = json.loads(raw_payload) if raw_payload else None
            except json.JSONDecodeError as exc:
                return _json_response(400, {"error": f"Invalid Slack form payload JSON: {exc}"})
        else:
            parsed, err = self._parse_json_body(body)
            if err is not None:
                return err
            payload_obj = parsed if isinstance(parsed, dict) else None

        if not isinstance(payload_obj, dict):
            return _json_response(400, {"error": "Expected Slack interactive payload JSON object."})

        actions = payload_obj.get("actions") or []
        if not actions or not isinstance(actions[0], dict):
            return _json_response(400, {"error": "Slack payload missing 'actions[0]'."})

        action = actions[0]
        action_id = str(action.get("action_id") or "")
        ticket_id = str(action.get("value") or "")
        user_info = payload_obj.get("user") or {}
        approver = str(
            user_info.get("username")
            or user_info.get("name")
            or user_info.get("id")
            or "slack-operator"
        )

        try:
            if action_id in ("approve_escalation", "approve"):
                updated = self.proxy.escalation_router.approve(
                    ticket_id=ticket_id,
                    approver=f"slack:{approver}",
                    session_store=self.proxy.session_store,
                    note="Approved via Slack interactive callback",
                )
                self.metrics.inc_escalation("approved")
                status_text = (
                    f"Approved ticket `{updated.ticket_id}` for `{updated.tool_name}` "
                    f"(session `{updated.session_id}`) by `{updated.decided_by}`."
                )
            elif action_id in ("reject_escalation", "reject"):
                updated = self.proxy.escalation_router.reject(
                    ticket_id=ticket_id,
                    approver=f"slack:{approver}",
                    reason="Rejected via Slack interactive callback",
                )
                self.metrics.inc_escalation("rejected")
                status_text = (
                    f"Rejected ticket `{updated.ticket_id}` for `{updated.tool_name}` "
                    f"(session `{updated.session_id}`) by `{updated.decided_by}`."
                )
            else:
                return _json_response(400, {"error": f"Unsupported Slack action_id '{action_id}'."})
        except PermissionError as exc:
            return _json_response(403, {"error": str(exc)})
        except KeyError as exc:
            return _json_response(404, {"error": str(exc)})
        except RuntimeError as exc:
            return _json_response(409, {"error": str(exc)})

        return _json_response(
            200,
            {
                "response_type": "in_channel",
                "replace_original": False,
                "text": status_text,
                "ticket": updated.to_dict(),
            },
        )

    async def handle_http_request(
        self,
        method: str,
        path: str,
        query_string: str,
        raw_headers: Any,
        body: bytes,
    ) -> _HttpResponse:
        resp = await self._route_http_request(method, path, query_string, raw_headers, body)
        self.metrics.inc_http(method.upper(), path, resp.status)
        return self._with_cors(resp)

    async def _route_http_request(
        self,
        method: str,
        path: str,
        query_string: str,
        raw_headers: Any,
        body: bytes,
    ) -> _HttpResponse:
        """
        Unified non-streaming HTTP request handler invoked by both ASGI 3.0
        and stdlib `ThreadingHTTPServer`.
        """
        method = method.upper()
        headers = self._normalize_headers(raw_headers)
        query_params = urllib.parse.parse_qs(query_string, keep_blank_values=False)

        if method == "OPTIONS":
            return _HttpResponse(status=204, headers={}, body=b"")

        if method == "GET" and path == "/healthz":
            return _json_response(
                200,
                {
                    "status": "ok",
                    "protocol": MCP_PROTOCOL_VERSION,
                    "sessions": len(self.proxy.session_store.list_sessions()),
                },
            )

        if method == "GET" and path == "/metrics":
            quarantined_count = len(getattr(self.proxy, "_compromised_tools", {}) or {})
            prom_text = self.metrics.render_prometheus(
                active_sessions=len(self.proxy.session_store.list_sessions()),
                pending_escalations=len(self.proxy.escalation_router.list_pending()),
                quarantined_tools=quarantined_count,
            )
            return _text_response(
                200,
                prom_text,
                content_type="text/plain; version=0.0.4; charset=utf-8",
            )

        if method == "POST" and path == "/integrations/slack/actions":
            return self._handle_slack_actions(headers, body)

        if method == "GET" and path == "/dashboard" and self.dashboard_enabled:
            return _text_response(200, _DASHBOARD_HTML, content_type="text/html; charset=utf-8")

        auth_ctx, auth_err = self._authenticate(headers, query_params)
        if auth_err is not None or auth_ctx is None:
            return self._with_cors(auth_err or _json_response(401, {"error": "Unauthorized"}))
        tenant = auth_ctx.tenant

        # MCP endpoints
        if method == "POST" and path == "/mcp":
            role_err = self._authorize_role(auth_ctx, "mcp")
            if role_err is not None:
                return self._with_cors(role_err)
            resp = await self._handle_jsonrpc_http(
                tenant, body, headers, actor_id=auth_ctx.actor_id
            )
            return self._with_cors(resp)

        if method == "POST" and path == "/messages":
            role_err = self._authorize_role(auth_ctx, "mcp")
            if role_err is not None:
                return self._with_cors(role_err)
            raw_sid = (query_params.get("session_id") or [None])[0] or headers.get("mcp-session-id")
            channel = (query_params.get("channel") or [None])[0]
            scoped_sid = self._scope_session_id(tenant, raw_sid)
            pub_keys = [scoped_sid]
            if channel:
                pub_keys.append(channel)
            resp = await self._handle_jsonrpc_http(
                tenant, body, headers, publish_keys=pub_keys, actor_id=auth_ctx.actor_id
            )
            return self._with_cors(resp)

        # Control Plane: Policies & Replay Simulation
        if method == "POST" and path == "/admin/policies/simulate":
            role_err = self._authorize_role(auth_ctx, "policies_read")
            if role_err is not None:
                return self._with_cors(role_err)
            data, err = self._parse_json_body(body)
            if err is not None:
                return self._with_cors(err)
            if not isinstance(data, dict):
                return self._with_cors(_json_response(400, {"error": "Expected JSON object."}))
            candidate = data.get("policy") if isinstance(data.get("policy"), dict) else data
            raw_sid = data.get("session_id")
            scoped_sid = self._scope_session_id(tenant, str(raw_sid)) if raw_sid else None
            catalog = [schema for _, (_, _, schema) in sorted(self.proxy._tool_routes.items())]
            try:
                report = simulate_policy_against_traces(
                    self.proxy.session_store,
                    candidate,
                    tools=catalog,
                    session_id=scoped_sid,
                    session_prefix=f"{tenant}:" if self._auth_enabled else None,
                )
            except (PolicySyntaxError, ValueError, KeyError) as exc:
                return self._with_cors(_json_response(400, {"error": str(exc)}))
            return self._with_cors(_json_response(200, report))

        if path == "/admin/policies":
            if method == "GET":
                role_err = self._authorize_role(auth_ctx, "policies_read")
                if role_err is not None:
                    return self._with_cors(role_err)
                return self._with_cors(_json_response(200, self.proxy.policy_registry.export_dict()))
            if method == "POST":
                role_err = self._authorize_role(auth_ctx, "policies_write")
                if role_err is not None:
                    return self._with_cors(role_err)
                data, err = self._parse_json_body(body)
                if err is not None:
                    return self._with_cors(err)
                if not isinstance(data, dict):
                    return self._with_cors(_json_response(400, {"error": "Expected JSON object."}))
                try:
                    replace = bool(data.get("replace", False))
                    if "tool_name" in data and "tools" not in data:
                        spec = ToolPolicySpec.from_dict(data)
                        version = self.proxy.policy_registry.set_policy(spec)
                    else:
                        version = self.proxy.policy_registry.load_dict(data, replace=replace)
                except (PolicySyntaxError, ValueError, KeyError) as exc:
                    return self._with_cors(_json_response(400, {"error": str(exc)}))
                return self._with_cors(
                    _json_response(
                        200,
                        {"version": version, "policies": self.proxy.policy_registry.export_dict()},
                    )
                )

        # Control Plane: Quarantined MCP Tools (Poisoning / Rug-Pull Management)
        if method == "GET" and path == "/admin/tools/quarantined":
            role_err = self._authorize_role(auth_ctx, "policies_read")
            if role_err is not None:
                return self._with_cors(role_err)
            comp = dict(getattr(self.proxy, "_compromised_tools", {}) or {})
            pinned = dict(getattr(self.proxy, "_pinned_tool_hashes", {}) or {})
            return self._with_cors(
                _json_response(
                    200,
                    {
                        "count": len(comp),
                        "pinned_count": len(pinned),
                        "tools": {
                            name: {"rule_triggered": val[0], "reason": val[1]}
                            for name, val in comp.items()
                        },
                    },
                )
            )

        if method == "POST" and path == "/admin/tools/trust":
            role_err = self._authorize_role(auth_ctx, "policies_write")
            if role_err is not None:
                return self._with_cors(role_err)
            data, err = self._parse_json_body(body)
            if err is not None:
                return self._with_cors(err)
            tool_name = str((data or {}).get("tool_name") or "").strip() if isinstance(data, dict) else ""
            if not tool_name:
                return self._with_cors(_json_response(400, {"error": "Expected 'tool_name' string."}))
            trusted = self.proxy.trust_updated_tool(tool_name)
            if not trusted:
                return self._with_cors(_json_response(404, {"error": f"Unknown tool '{tool_name}'."}))
            return self._with_cors(_json_response(200, {"trusted": True, "tool_name": tool_name}))

        # Control Plane: Escalations
        if method == "GET" and path == "/admin/escalations":
            role_err = self._authorize_role(auth_ctx, "escalations_read")
            if role_err is not None:
                return self._with_cors(role_err)
            filter_sid = (query_params.get("session_id") or [None])[0]
            scoped_filter = self._scope_session_id(tenant, filter_sid) if filter_sid else None
            tickets = [
                t.to_dict()
                for t in self.proxy.escalation_router.list_pending(session_id=scoped_filter)
                if self._tenant_owns_session(tenant, t.session_id)
            ]
            return self._with_cors(_json_response(200, {"count": len(tickets), "tickets": tickets}))

        if method == "POST" and path.startswith("/admin/escalations/"):
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[3] in ("approve", "reject"):
                role_err = self._authorize_role(auth_ctx, "escalations_decide")
                if role_err is not None:
                    return self._with_cors(role_err)
                ticket_id, action = parts[2], parts[3]
                existing = self.proxy.escalation_router.get_ticket(ticket_id)
                if existing is None:
                    return self._with_cors(
                        _json_response(404, {"error": f"Unknown escalation ticket: '{ticket_id}'."})
                    )
                if not self._tenant_owns_session(tenant, existing.session_id):
                    return self._with_cors(
                        _json_response(403, {"error": "Forbidden for current tenant."})
                    )

                data, err = self._parse_json_body(body)
                if err is not None:
                    return self._with_cors(err)
                payload = data if isinstance(data, dict) else {}
                approver = auth_ctx.actor_id or str(payload.get("approver") or tenant)
                note = str(payload.get("note") or payload.get("reason") or "")
                try:
                    if action == "approve":
                        updated = self.proxy.escalation_router.approve(
                            ticket_id=ticket_id,
                            approver=approver,
                            session_store=self.proxy.session_store,
                            note=note,
                        )
                        self.metrics.inc_escalation("approved")
                    else:
                        updated = self.proxy.escalation_router.reject(
                            ticket_id=ticket_id,
                            approver=approver,
                            reason=note,
                        )
                        self.metrics.inc_escalation("rejected")
                except PermissionError as exc:
                    return self._with_cors(_json_response(403, {"error": str(exc)}))
                except (KeyError, RuntimeError) as exc:
                    return self._with_cors(_json_response(409, {"error": str(exc)}))
                return self._with_cors(
                    _json_response(200, updated.to_dict(include_token=(action == "approve")))
                )

        # Control Plane: Audit Vault
        if method == "GET" and path == "/admin/audit":
            role_err = self._authorize_role(auth_ctx, "audit_read")
            if role_err is not None:
                return self._with_cors(role_err)
            raw_sid = (query_params.get("session_id") or [None])[0]
            tool = (query_params.get("tool") or [None])[0]
            verdict = (query_params.get("verdict") or [None])[0]
            rule = (query_params.get("rule") or [None])[0]
            actor = (query_params.get("actor_id") or [None])[0]
            limit_str = (query_params.get("limit") or ["200"])[0]
            try:
                limit = max(1, min(int(limit_str), 5000))
            except ValueError:
                return self._with_cors(_json_response(400, {"error": "Invalid 'limit' integer."}))

            scoped_sid = self._scope_session_id(tenant, raw_sid) if raw_sid else None
            receipts = self.audit_vault.query(
                session_id=scoped_sid,
                verdict=verdict,
                tool_name=tool,
                rule_triggered=rule,
                actor_id=actor,
                limit=limit,
            )
            filtered = [r.to_dict() for r in receipts if self._tenant_owns_session(tenant, r.session_id)]
            return self._with_cors(_json_response(200, {"count": len(filtered), "receipts": filtered}))

        if method == "GET" and path == "/admin/audit/verify":
            role_err = self._authorize_role(auth_ctx, "audit_read")
            if role_err is not None:
                return self._with_cors(role_err)
            all_chains = self.audit_vault.verify_all_chains()
            scoped_chains = {
                sid: ok for sid, ok in all_chains.items() if self._tenant_owns_session(tenant, sid)
            }
            return self._with_cors(
                _json_response(200, {"valid": all(scoped_chains.values()), "sessions": scoped_chains})
            )

        # Control Plane: Recovery Sweep
        if method == "POST" and path == "/admin/recovery/sweep":
            role_err = self._authorize_role(auth_ctx, "recovery_sweep")
            if role_err is not None:
                return self._with_cors(role_err)
            data, err = self._parse_json_body(body)
            if err is not None:
                return self._with_cors(err)
            stale_override = (
                float(data["stale_after_seconds"])
                if isinstance(data, dict) and "stale_after_seconds" in data
                else None
            )

            def _run_sweep() -> Any:
                orig_stale = self.recovery_daemon.stale_after_seconds
                if stale_override is not None:
                    self.recovery_daemon.stale_after_seconds = stale_override
                try:
                    return self.recovery_daemon.sweep_once()
                finally:
                    self.recovery_daemon.stale_after_seconds = orig_stale

            report = await asyncio.to_thread(_run_sweep)
            self.metrics.record_sweep(report.recovered_sessions)

            details = [
                d
                for d in report.details
                if self._tenant_owns_session(tenant, str(d.get("session_id", "")))
            ]
            return self._with_cors(
                _json_response(
                    200,
                    {
                        "scanned_sessions": report.scanned_sessions,
                        "stale_sessions_found": report.stale_sessions_found,
                        "recovered_sessions": report.recovered_sessions,
                        "failed_sessions": report.failed_sessions,
                        "details": details,
                    },
                )
            )

        return self._with_cors(_json_response(404, {"error": f"Not found: {method} {path}"}))

    # ── ASGI 3.0 Entrypoint ────────────────────────────────────────────────────

    async def __call__(
        self,
        scope: Dict[str, Any],
        receive: Callable[[], Awaitable[Dict[str, Any]]],
        send: Callable[[Dict[str, Any]], Awaitable[None]],
    ) -> None:
        """Pure Python ASGI 3.0 application entrypoint."""
        if scope.get("type") != "http":
            return

        method = str(scope.get("method", "GET")).upper()
        path = str(scope.get("path", "/"))
        qs_bytes = scope.get("query_string") or b""
        query_string = qs_bytes.decode("latin-1") if isinstance(qs_bytes, bytes) else str(qs_bytes)
        raw_headers = scope.get("headers") or []

        if method == "GET" and path == "/sse":
            await self._handle_asgi_sse(query_string, raw_headers, receive, send)
            return

        chunks: List[bytes] = []
        while True:
            event = await receive()
            if event.get("type") == "http.disconnect":
                return
            chunk = event.get("body") or b""
            if chunk:
                chunks.append(chunk)
            if not event.get("more_body", False):
                break

        resp = await self.handle_http_request(
            method=method,
            path=path,
            query_string=query_string,
            raw_headers=raw_headers,
            body=b"".join(chunks),
        )
        await send(
            {
                "type": "http.response.start",
                "status": resp.status,
                "headers": [
                    (k.lower().encode("latin-1"), v.encode("latin-1"))
                    for k, v in resp.headers.items()
                ],
            }
        )
        await send({"type": "http.response.body", "body": resp.body, "more_body": False})

    async def _handle_asgi_sse(
        self,
        query_string: str,
        raw_headers: Any,
        receive: Callable[[], Awaitable[Dict[str, Any]]],
        send: Callable[[Dict[str, Any]], Awaitable[None]],
    ) -> None:
        headers = self._normalize_headers(raw_headers)
        query_params = urllib.parse.parse_qs(query_string, keep_blank_values=False)
        auth_ctx, auth_err = self._authenticate_for_scope(headers, query_params, "mcp")
        if auth_err is not None or auth_ctx is None:
            resp = self._with_cors(auth_err or _json_response(401, {"error": "Unauthorized"}))
            await send(
                {
                    "type": "http.response.start",
                    "status": resp.status,
                    "headers": [
                        (k.lower().encode("latin-1"), v.encode("latin-1"))
                        for k, v in resp.headers.items()
                    ],
                }
            )
            await send({"type": "http.response.body", "body": resp.body, "more_body": False})
            return

        tenant = auth_ctx.tenant

        raw_sid = (query_params.get("session_id") or [None])[0]
        scoped_sid = self._scope_session_id(tenant, raw_sid)
        channel_id = f"sse_{uuid.uuid4().hex[:12]}"
        keys = [scoped_sid, channel_id]
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[str] = asyncio.Queue()
        self._register_sse_queue(keys, loop, q)

        endpoint_qs = urllib.parse.urlencode(
            {"session_id": raw_sid or self.proxy.default_session_id, "channel": channel_id}
        )
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/event-stream; charset=utf-8"),
                    (b"cache-control", b"no-cache"),
                    (b"connection", b"keep-alive"),
                ],
            }
        )
        initial = f"event: endpoint\ndata: /messages?{endpoint_qs}\n\n".encode("utf-8")
        await send({"type": "http.response.body", "body": initial, "more_body": True})

        once = (query_params.get("once") or [""])[0] in ("1", "true", "yes")
        if once:
            self._unregister_sse_queue(keys, q)
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return

        disconnect_task = asyncio.create_task(receive())
        try:
            while True:
                queue_task = asyncio.create_task(q.get())
                done, _pending = await asyncio.wait(
                    {disconnect_task, queue_task},
                    timeout=15.0,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if disconnect_task in done:
                    queue_task.cancel()
                    break
                if queue_task in done:
                    msg = queue_task.result()
                    await send(
                        {"type": "http.response.body", "body": msg.encode("utf-8"), "more_body": True}
                    )
                else:
                    queue_task.cancel()
                    await send({"type": "http.response.body", "body": b": keepalive\n\n", "more_body": True})
        except asyncio.CancelledError:
            pass
        finally:
            if not disconnect_task.done():
                disconnect_task.cancel()
            self._unregister_sse_queue(keys, q)


# ── Zero-Dependency Stdlib ThreadingHTTPServer Wrapper ────────────────────────


def create_http_server(
    gateway: MCPHttpGateway,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> ThreadingHTTPServer:
    """Create a stdlib multi-threaded HTTP server backed by `MCPHttpGateway`."""

    class _SlimRequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            logger.debug(format, *args)

        def _dispatch(self, method: str) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            if method == "GET" and parsed.path == "/sse":
                self._serve_sse(parsed.query)
                return

            content_len = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(content_len) if content_len > 0 else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}

            resp = asyncio.run(
                gateway.handle_http_request(
                    method=method,
                    path=parsed.path,
                    query_string=parsed.query,
                    raw_headers=hdrs,
                    body=body,
                )
            )
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() != "content-length":
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            if resp.body:
                self.wfile.write(resp.body)

        def _serve_sse(self, query_string: str) -> None:
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            query_params = urllib.parse.parse_qs(query_string, keep_blank_values=False)
            auth_ctx, auth_err = gateway._authenticate_for_scope(hdrs, query_params, "mcp")
            if auth_err is not None or auth_ctx is None:
                resp = gateway._with_cors(auth_err or _json_response(401, {"error": "Unauthorized"}))
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(resp.body)))
                self.end_headers()
                self.wfile.write(resp.body)
                return

            tenant = auth_ctx.tenant

            raw_sid = (query_params.get("session_id") or [None])[0]
            scoped_sid = gateway._scope_session_id(tenant, raw_sid)
            channel_id = f"sse_{uuid.uuid4().hex[:12]}"
            keys = [scoped_sid, channel_id]
            q: thread_queue.Queue[str] = thread_queue.Queue()
            gateway._register_sse_queue(keys, None, q)

            endpoint_qs = urllib.parse.urlencode(
                {"session_id": raw_sid or gateway.proxy.default_session_id, "channel": channel_id}
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()

            once = (query_params.get("once") or [""])[0] in ("1", "true", "yes")
            try:
                self.wfile.write(f"event: endpoint\ndata: /messages?{endpoint_qs}\n\n".encode("utf-8"))
                self.wfile.flush()
                if once:
                    return
                while True:
                    try:
                        msg = q.get(timeout=15.0)
                        self.wfile.write(msg.encode("utf-8"))
                    except thread_queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                gateway._unregister_sse_queue(keys, q)

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_OPTIONS(self) -> None:
            self._dispatch("OPTIONS")

    return ThreadingHTTPServer((host, port), _SlimRequestHandler)


def serve_http(
    proxy: Union[MCPTransactionProxy, MCPHttpGateway],
    host: str = "127.0.0.1",
    port: int = 8080,
    api_keys: Optional[Dict[str, str]] = None,
    recovery_interval_s: Optional[float] = None,
) -> None:
    """Block and serve `MCPHttpGateway` over HTTP/SSE until interrupted."""
    gateway = (
        proxy
        if isinstance(proxy, MCPHttpGateway)
        else MCPHttpGateway(proxy, api_keys=api_keys)
    )
    if recovery_interval_s is not None and recovery_interval_s > 0:
        gateway.start_recovery_daemon(recovery_interval_s)
    server = create_http_server(gateway, host=host, port=port)
    try:
        server.serve_forever()
    finally:
        gateway.stop_recovery_daemon()
        server.server_close()
