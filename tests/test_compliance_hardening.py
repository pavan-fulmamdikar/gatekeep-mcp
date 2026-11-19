"""
tests/test_compliance_hardening.py

End-to-end verification of all 5 enterprise compliance & security hardening controls:
  1. PII & secret redaction before AuditReceipt hashing/persistence & EscalationTicket previewing
  2. Hashed-at-rest & action-fingerprint-bound one-time HITL approval tokens
  3. Immutable append-only AuditLog persistence surviving session deletion (SQLite/Memory/Redis/Postgres)
  4. Strict Role-Based Separation of Duties (agent / policy_admin / approver / auditor) + SoD self-approval block
  5. Verified HS256 JWT & static principal actor_id attribution into AuditReceipts and EscalationTickets
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import sqlite3
import sys
import time
from typing import Any, Dict, List

import pytest

from gatekeep import (
    ApiPrincipal,
    AuditVault,
    CallableMCPUpstream,
    CentralPolicyRegistry,
    EscalationRouter,
    InMemorySessionStore,
    MCPHttpGateway,
    MCPTransactionProxy,
    PostgresSessionStore,
    PreExecutionGate,
    RedisSessionStore,
    SQLiteSessionStore,
    SensitiveDataRedactor,
    ToolPolicySpec,
    canonical_action_fingerprint,
    hash_secret_token,
)
from gatekeep.mcp.cli import _build_principals_from_args, build_parser, build_proxy_from_args


class _LocalFakeRedis:
    def __init__(self) -> None:
        self._kv: Dict[str, str] = {}
        self._lists: Dict[str, List[str]] = {}

    def get(self, key: str) -> str | None:
        return self._kv.get(key)

    def set(self, key: str, value: str, nx: bool = False) -> bool:
        if nx and key in self._kv:
            return False
        self._kv[key] = value
        return True

    def delete(self, key: str) -> int:
        return 1 if self._kv.pop(key, None) is not None else 0

    def keys(self, pattern: str = "*") -> List[str]:
        prefix = pattern[:-1] if pattern.endswith("*") else pattern
        return [k for k in self._kv if k.startswith(prefix)]

    def rpush(self, key: str, value: str) -> int:
        lst = self._lists.setdefault(key, [])
        lst.append(value)
        return len(lst)

    def lrange(self, key: str, start: int, stop: int) -> List[str]:
        lst = self._lists.get(key, [])
        return lst[start:] if stop == -1 else lst[start : stop + 1]


class _LocalFakePGConn:
    def __init__(self, owner: "_LocalFakePGPool") -> None:
        self._owner = owner
        self.autocommit = False

    def cursor(self) -> "_LocalFakePGCursor":
        return _LocalFakePGCursor(self._owner)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


class _LocalFakePGCursor:
    def __init__(self, owner: "_LocalFakePGPool") -> None:
        self._owner = owner
        self._rows: List[tuple[Any, ...]] = []
        self.rowcount = 0

    def execute(self, sql: str, params: Any = None) -> None:
        norm = " ".join(sql.split()).lower()
        params = params or ()
        self._rows = []
        self.rowcount = 0
        if any(
            norm.startswith(p)
            for p in ("create table", "create index", "begin", "commit", "rollback")
        ):
            return
        if "_audit_log" in norm and norm.startswith("insert into"):
            sid, ts, verdict, tool, rule, actor, payload = params
            self._owner.audit_rows.append(
                {
                    "session_id": sid,
                    "timestamp": ts,
                    "verdict": verdict,
                    "tool_name": tool,
                    "rule_triggered": rule,
                    "actor_id": actor,
                    "payload": payload,
                }
            )
            self.rowcount = 1
            return
        if "_audit_log" in norm and norm.startswith("select payload"):
            matched = []
            for row in self._owner.audit_rows:
                idx = 0
                ok = True
                for field in ("session_id", "verdict", "tool_name", "rule_triggered", "actor_id"):
                    if f"{field} = %s" in norm:
                        if row[field] != params[idx]:
                            ok = False
                            break
                        idx += 1
                if ok:
                    matched.append((row["payload"],))
            self._rows = matched
            return
        if norm.startswith("select version from"):
            row = self._owner.sessions.get(str(params[0]))
            self._rows = [(row[0],)] if row else []
        elif norm.startswith("select payload from"):
            row = self._owner.sessions.get(str(params[0]))
            self._rows = [(row[1],)] if row else []
        elif norm.startswith("insert into"):
            sid, ver, payload, _now = params
            self._owner.sessions[str(sid)] = (int(ver), str(payload))
            self.rowcount = 1
        elif norm.startswith("delete from"):
            existed = self._owner.sessions.pop(str(params[0]), None) is not None
            self.rowcount = 1 if existed else 0
        elif norm.startswith("select session_id from"):
            self._rows = [(k,) for k in sorted(self._owner.sessions)]

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def close(self) -> None:
        pass


class _LocalFakePGPool:
    def __init__(self) -> None:
        self.sessions: Dict[str, tuple[int, str]] = {}
        self.audit_rows: List[Dict[str, Any]] = []

    def connection(self):
        conn = _LocalFakePGConn(self)

        class _Ctx:
            def __enter__(self_inner):
                return conn

            def __exit__(self_inner, *args):
                pass

        return _Ctx()

    def close(self) -> None:
        pass


def _make_hs256_jwt(payload: Dict[str, Any], secret: str) -> str:
    def _b64(obj: Dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    hdr_b64 = _b64({"alg": "HS256", "typ": "JWT"})
    payload_b64 = _b64(payload)
    sig = hmac.new(
        secret.encode("utf-8"),
        f"{hdr_b64}.{payload_b64}".encode("ascii"),
        hashlib.sha256,
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    return f"{hdr_b64}.{payload_b64}.{sig_b64}"


async def _asgi_request(
    app: MCPHttpGateway,
    method: str,
    path: str,
    *,
    headers: Dict[str, str] | None = None,
    body: Any = None,
    query_string: str = "",
) -> tuple[int, Dict[str, Any]]:
    raw_body = b""
    hdr_list: List[tuple[bytes, bytes]] = []
    if body is not None:
        raw_body = json.dumps(body).encode("utf-8")
        hdr_list.append((b"content-type", b"application/json"))
    for k, v in (headers or {}).items():
        hdr_list.append((k.lower().encode("latin-1"), v.encode("latin-1")))

    sent = False

    async def receive() -> Dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": raw_body, "more_body": False}
        return {"type": "http.disconnect"}

    captured: Dict[str, Any] = {"status": 0, "body": bytearray()}

    async def send(event: Dict[str, Any]) -> None:
        if event["type"] == "http.response.start":
            captured["status"] = event["status"]
        elif event["type"] == "http.response.body":
            captured["body"].extend(event.get("body") or b"")

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query_string.encode("utf-8"),
        "headers": hdr_list,
    }
    await app(scope, receive, send)
    text = captured["body"].decode("utf-8") if captured["body"] else "{}"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = {"raw": text}
    return captured["status"], parsed


def test_pii_redaction_protects_audit_and_escalations_while_forwarding_raw_args(tmp_path) -> None:
    db_path = tmp_path / "pii_redact.db"
    store = SQLiteSessionStore(str(db_path))
    upstream_seen: List[Dict[str, Any]] = []

    def dispatch(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        upstream_seen.append({"name": name, "args": args})
        return {"ok": True}

    upstream = CallableMCPUpstream(
        tools=[
            {
                "name": "verify_customer",
                "description": "Verify identity (DESTRUCTIVE)",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ],
        executor=dispatch,
    )
    policies = CentralPolicyRegistry(session_store=store)
    policies.set_policy(
        ToolPolicySpec(
            tool_name="verify_customer",
            mode="DESTRUCTIVE",
            requires_approval=True,
        )
    )
    proxy = MCPTransactionProxy(
        upstream=upstream,
        session_store=store,
        policy_registry=policies,
        escalation_router=EscalationRouter(session_store=store),
        strict_provenance=False,
    )

    secret_pan = "4111-1111-1111-1111"
    secret_ssn = "123-45-6789"
    secret_email = "alice.smith@example.com"
    secret_bearer = "Bearer sk_live_supersecret_999999999999"
    secret_pw = "CorrectHorseBattery99!"

    try:
        # 1) Escalated call stores ticket preview + audit receipt with PII redacted
        resp = proxy.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "verify_customer",
                    "arguments": {
                        "email": secret_email,
                        "ssn": secret_ssn,
                        "card_number": secret_pan,
                        "password": secret_pw,
                        "auth_header": secret_bearer,
                        "note": f"Reach {secret_email} with {secret_bearer}",
                    },
                    "_meta": {"session_id": "pii-sess", "actor_id": "agent-1"},
                },
            }
        )
        assert resp is not None and resp["result"]["isError"] is True
        sc = resp["result"]["structuredContent"]
        assert sc["verdict"] == "ESCALATE"
        ticket_id = sc["ledger_facts"]["escalation_ticket_id"]

        # Approve and run again so raw args reach upstream cleanly
        ticket = proxy.escalation_router.approve(
            ticket_id, approver="compliance-lead", session_store=store
        )
        assert ticket.approval_token is not None

        ok_resp = proxy.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "verify_customer",
                    "arguments": {
                        "email": secret_email,
                        "ssn": secret_ssn,
                        "card_number": secret_pan,
                        "password": secret_pw,
                        "auth_header": secret_bearer,
                        "note": f"Reach {secret_email} with {secret_bearer}",
                    },
                    "_meta": {
                        "session_id": "pii-sess",
                        "actor_id": "agent-1",
                        "approval_token": ticket.approval_token,
                    },
                },
            }
        )
        assert ok_resp is not None and "result" in ok_resp
        assert len(upstream_seen) == 1
        assert upstream_seen[0]["args"]["ssn"] == secret_ssn
        assert upstream_seen[0]["args"]["email"] == secret_email

        # Confirm ZERO plaintext secrets/PII exist anywhere in SQLite database rows
        conn = sqlite3.connect(str(db_path))
        rows = conn.execute("SELECT ledger_json, gate_json FROM gatekeep_sessions").fetchall()
        audit_rows = conn.execute("SELECT payload_json FROM gatekeep_audit_log").fetchall()
        cp_rows = conn.execute("SELECT payload_json FROM gatekeep_control_plane").fetchall()
        conn.close()

        all_stored = "\n".join(
            [*(str(col) for r in rows for col in r), *(str(r[0]) for r in audit_rows + cp_rows)]
        )
        for sensitive in (secret_pan, secret_ssn, secret_email, "sk_live_supersecret", secret_pw, ticket.approval_token):
            assert sensitive not in all_stored, f"Unredacted sensitive value leaked at rest: {sensitive}"
        assert "[REDACTED:" in all_stored

        # Hash chain still verifies valid on redacted receipts
        vault = AuditVault(store)
        assert vault.verify_all_chains() == {"pii-sess": True}

        # Deterministic pseudonymization produces consistent tokens for identical PII values
        redactor = SensitiveDataRedactor()
        assert redactor.redact_string(secret_email) == redactor.redact_string(secret_email)
        assert redactor.redact_string("bob@example.com") != redactor.redact_string(secret_email)
    finally:
        store.close()


def test_hashed_and_action_bound_approval_token_prevents_payload_tampering(tmp_path) -> None:
    db_path = tmp_path / "action_bind.db"
    store1 = SQLiteSessionStore(str(db_path))
    executed: List[Dict[str, Any]] = []

    upstream = CallableMCPUpstream(
        tools=[
            {
                "name": "wire_funds",
                "description": "Transfer funds (DESTRUCTIVE)",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ],
        executor=lambda name, args: executed.append({"name": name, "args": args}) or {"transferred": True},
    )
    policies = CentralPolicyRegistry(session_store=store1)
    policies.set_policy(ToolPolicySpec(tool_name="wire_funds", mode="DESTRUCTIVE", requires_approval=True))

    proxy1 = MCPTransactionProxy(
        upstream=upstream,
        session_store=store1,
        policy_registry=policies,
        escalation_router=EscalationRouter(session_store=store1),
        strict_provenance=False,
    )

    try:
        esc = proxy1.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "wire_funds",
                    "arguments": {"to": "vendor-a", "amount": 500},
                    "_meta": {"session_id": "wire-1", "actor_id": "agent-alice"},
                },
            }
        )
        assert esc is not None and esc["result"]["isError"] is True
        ticket_id = esc["result"]["structuredContent"]["ledger_facts"]["escalation_ticket_id"]

        # Approve from a completely fresh worker (store2) — forces token re-minting & hashing
        store2 = SQLiteSessionStore(str(db_path))
        try:
            router2 = EscalationRouter(session_store=store2)
            approved = router2.approve(ticket_id, approver="cfo-bob", session_store=store2)
            assert approved.approval_token is not None
            token = approved.approval_token
            expected_fp = canonical_action_fingerprint("wire_funds", {"amount": 500, "to": "vendor-a"})
            assert approved.action_fingerprint == expected_fp
            assert approved.approval_token_hash == hash_secret_token(token)
        finally:
            store2.close()

        # Tampered payload attack with valid token MUST be blocked
        tampered = proxy1.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "wire_funds",
                    "arguments": {"to": "attacker-acct", "amount": 99000},
                    "_meta": {"session_id": "wire-1", "approval_token": token},
                },
            }
        )
        assert tampered is not None and tampered["result"]["isError"] is True
        assert tampered["result"]["structuredContent"]["rule_triggered"] == "approval_token_scope_mismatch"
        assert executed == []

        # Original untouched payload with the same token MUST succeed (one-time)
        valid = proxy1.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "wire_funds",
                    "arguments": {"amount": 500, "to": "vendor-a"},
                    "_meta": {"session_id": "wire-1", "approval_token": token},
                },
            }
        )
        assert valid is not None and "result" in valid
        assert len(executed) == 1
        assert executed[0]["args"] == {"amount": 500, "to": "vendor-a"}
    finally:
        store1.close()


def test_immutable_append_only_audit_survives_session_deletion(tmp_path) -> None:
    stores = [
        InMemorySessionStore(),
        SQLiteSessionStore(str(tmp_path / "worm.db")),
        RedisSessionStore(client=_LocalFakeRedis()),
        PostgresSessionStore(pool=_LocalFakePGPool()),
    ]
    try:
        for idx, store in enumerate(stores):
            sid = f"tenant-x:sess-{idx}"
            gate = PreExecutionGate.from_store(sid, store, redactor=SensitiveDataRedactor())
            d = gate.evaluate("list_invoices", {"email": "priv@corp.io"}, actor_id="svc-worker")
            assert d.receipt is not None
            gate.save()

            # Deleting operational session state must NOT erase compliance AuditVault records
            store.delete(sid)
            assert store.load(sid) is None

            vault = AuditVault(store)
            chains = vault.verify_all_chains()
            assert chains.get(sid) is True

            queried = vault.query(session_id=sid, actor_id="svc-worker")
            assert len(queried) == 1
            assert queried[0].actor_id == "svc-worker"
            assert "priv@corp.io" not in json.dumps(queried[0].arguments)
    finally:
        for s in stores:
            if hasattr(s, "close"):
                s.close()


def test_strict_rbac_jwt_attribution_and_sod_self_approval_block(tmp_path) -> None:
    store = SQLiteSessionStore(str(tmp_path / "rbac.db"))
    jwt_secret = "super-secret-hs256-signing-key-2026"
    audit_jsonl = tmp_path / "worm_audit.jsonl"

    upstream = CallableMCPUpstream(
        tools=[
            {
                "name": "delete_records",
                "description": "Delete rows (DESTRUCTIVE)",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ],
        executor=lambda name, args: {"deleted": True},
    )
    policies = CentralPolicyRegistry(session_store=store)
    policies.set_policy(
        ToolPolicySpec(tool_name="delete_records", mode="DESTRUCTIVE", requires_approval=True)
    )

    from gatekeep.mcp.cli import _make_jsonl_audit_sink

    proxy = MCPTransactionProxy(
        upstream=upstream,
        session_store=store,
        policy_registry=policies,
        escalation_router=EscalationRouter(session_store=store),
        strict_provenance=False,
        audit_sink=_make_jsonl_audit_sink(str(audit_jsonl)),
    )

    gateway = MCPHttpGateway(
        proxy,
        principals={
            "tok_agent": ApiPrincipal("acme", "agent", "bot-1"),
            "tok_policy": ApiPrincipal("acme", "policy_admin", "sec-arch"),
            "tok_approver": ApiPrincipal("acme", "approver", "oncall-bob"),
            "tok_auditor": ApiPrincipal("acme", "auditor", "audit-carol"),
        },
        jwt_secret=jwt_secret,
        jwt_issuer="https://idp.acme.internal",
        jwt_audience="gatekeep-mcp",
    )

    async def _run() -> None:
        # 1) Role enforcement checks
        # Agent cannot read/write admin endpoints
        for m, p in (
            ("GET", "/admin/policies"),
            ("POST", "/admin/policies"),
            ("GET", "/admin/escalations"),
            ("GET", "/admin/audit"),
            ("GET", "/admin/audit/verify"),
            ("POST", "/admin/recovery/sweep"),
        ):
            st, _ = await _asgi_request(gateway, m, p, headers={"Authorization": "Bearer tok_agent"})
            assert st == 403, f"Expected 403 for agent on {m} {p}, got {st}"

        # Auditor is strictly read-only on control plane and blocked on /mcp & /sse
        st, _ = await _asgi_request(gateway, "GET", "/admin/audit", headers={"Authorization": "Bearer tok_auditor"})
        assert st == 200
        st, _ = await _asgi_request(gateway, "POST", "/admin/policies", headers={"Authorization": "Bearer tok_auditor"}, body={})
        assert st == 403
        st, _ = await _asgi_request(gateway, "POST", "/mcp", headers={"Authorization": "Bearer tok_auditor"}, body={})
        assert st == 403
        st, _ = await _asgi_request(gateway, "GET", "/sse", query_string="once=1", headers={"Authorization": "Bearer tok_auditor"})
        assert st == 403
        st, _ = await _asgi_request(gateway, "GET", "/sse", query_string="once=1", headers={"Authorization": "Bearer tok_agent"})
        assert st == 200

        # Policy admin can update policies, cannot approve escalations or invoke /mcp
        st, _ = await _asgi_request(gateway, "GET", "/admin/policies", headers={"Authorization": "Bearer tok_policy"})
        assert st == 200
        st, _ = await _asgi_request(gateway, "POST", "/mcp", headers={"Authorization": "Bearer tok_policy"}, body={})
        assert st == 403

        # Expired JWT & bad signature JWT get 401
        expired_jwt = _make_hs256_jwt(
            {
                "sub": "alice",
                "tenant": "acme",
                "role": "agent",
                "iss": "https://idp.acme.internal",
                "aud": "gatekeep-mcp",
                "exp": int(time.time()) - 120,
            },
            jwt_secret,
        )
        st, _ = await _asgi_request(gateway, "POST", "/mcp", headers={"Authorization": f"Bearer {expired_jwt}"}, body={})
        assert st == 401

        bad_sig_jwt = _make_hs256_jwt(
            {"sub": "alice", "tenant": "acme", "role": "admin", "exp": int(time.time()) + 300},
            "wrong-secret",
        )
        st, _ = await _asgi_request(gateway, "POST", "/mcp", headers={"Authorization": f"Bearer {bad_sig_jwt}"}, body={})
        assert st == 401

        # 2) Verified agent JWT executes MCP tool call; server overrides spoofed _meta.actor_id
        alice_agent_jwt = _make_hs256_jwt(
            {
                "sub": "alice@acme.com",
                "tenant": "acme",
                "role": "agent",
                "iss": "https://idp.acme.internal",
                "aud": "gatekeep-mcp",
                "exp": int(time.time()) + 300,
            },
            jwt_secret,
        )
        st, rpc_esc = await _asgi_request(
            gateway,
            "POST",
            "/mcp",
            headers={"Authorization": f"Bearer {alice_agent_jwt}"},
            body={
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "delete_records",
                    "arguments": {"table": "invoices", "api_key": "sk_test_12345"},
                    "_meta": {"session_id": "s-jwt", "actor_id": "spoofed-eve"},
                },
            },
        )
        assert st == 200
        assert rpc_esc["result"]["isError"] is True
        ticket_id = rpc_esc["result"]["structuredContent"]["ledger_facts"]["escalation_ticket_id"]
        pending_ticket = proxy.escalation_router.get_ticket(ticket_id)
        assert pending_ticket is not None
        assert pending_ticket.requested_by == "alice@acme.com"

        # 3) Alice (even if holding approver role JWT) MUST be blocked from approving her own request (SoD)
        alice_approver_jwt = _make_hs256_jwt(
            {
                "sub": "alice@acme.com",
                "tenant": "acme",
                "role": "approver",
                "iss": "https://idp.acme.internal",
                "aud": "gatekeep-mcp",
                "exp": int(time.time()) + 300,
            },
            jwt_secret,
        )
        st, sod_body = await _asgi_request(
            gateway,
            "POST",
            f"/admin/escalations/{ticket_id}/approve",
            headers={"Authorization": f"Bearer {alice_approver_jwt}"},
            body={"approver": "spoofed-bob"},
        )
        assert st == 403
        assert "Separation of Duties" in sod_body["error"]

        # 4) Independent approver 'oncall-bob' approves successfully
        st, ok_app = await _asgi_request(
            gateway,
            "POST",
            f"/admin/escalations/{ticket_id}/approve",
            headers={"Authorization": "Bearer tok_approver"},
            body={},
        )
        assert st == 200
        assert ok_app["decided_by"] == "oncall-bob"
        assert ok_app["requested_by"] == "alice@acme.com"
        assert ok_app["approval_token"]

        # 5) Auditor queries AuditVault filtered by actor_id=alice@acme.com
        st, audit_q = await _asgi_request(
            gateway,
            "GET",
            "/admin/audit",
            query_string="actor_id=alice%40acme.com",
            headers={"Authorization": "Bearer tok_auditor"},
        )
        assert st == 200
        assert audit_q["count"] == 1
        assert audit_q["receipts"][0]["actor_id"] == "alice@acme.com"

    try:
        asyncio.run(_run())
        lines = audit_jsonl.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        parsed_line = json.loads(lines[0])
        assert parsed_line["actor_id"] == "alice@acme.com"
        assert "sk_test_12345" not in lines[0]
    finally:
        store.close()


def test_cli_compliance_flags_build_principals_and_worm_sink(tmp_path) -> None:
    fake_srv = tmp_path / "echo_mcp.py"
    fake_srv.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    req = json.loads(line)\n"
        "    m = req.get('method')\n"
        "    if m == 'initialize':\n"
        "        res = {'protocolVersion': '2024-11-05', 'capabilities': {}}\n"
        "    elif m == 'tools/list':\n"
        "        res = {'tools': [{'name': 'ping', 'description': 'Ping', 'inputSchema': {'type': 'object'}}]}\n"
        "    else:\n"
        "        res = {}\n"
        "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req.get('id'), 'result': res}) + '\\n')\n"
        "    sys.stdout.flush()\n",
        encoding="utf-8",
    )
    parser = build_parser()
    jsonl_path = tmp_path / "cli_worm.jsonl"
    args = parser.parse_args(
        [
            "--upstream",
            f'"{sys.executable}" "{fake_srv}"',
            "--agent-key",
            "acme:bot-a=sec_agent",
            "--policy-admin-key",
            "acme:arch=sec_policy",
            "--approver-key",
            "acme:bob=sec_approver",
            "--auditor-key",
            "acme:carol=sec_auditor",
            "--jwt-secret",
            "jwt-k",
            "--strict-rbac",
            "--audit-jsonl",
            str(jsonl_path),
        ]
    )
    principals = _build_principals_from_args(args)
    assert principals["sec_agent"].role == "agent"
    assert principals["sec_agent"].actor_id == "bot-a"
    assert principals["sec_policy"].role == "policy_admin"
    assert principals["sec_approver"].role == "approver"
    assert principals["sec_auditor"].role == "auditor"

    proxy, store, clients = build_proxy_from_args(args)
    try:
        assert proxy.redactor is not None
        assert proxy.audit_sink is not None
    finally:
        for c in clients:
            c.close()
        if hasattr(store, "close"):
            store.close()
