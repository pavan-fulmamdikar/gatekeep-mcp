"""
Tests for Phase 6 Enterprise Hardening:
  - `PostgresSessionStore` (FOR UPDATE CAS, advisory locks, missing driver guard)
  - `WebhookEscalationNotifier` (signed JSON & Slack Block Kit HTTP delivery)
  - Async `MCPTransactionProxy` (`AsyncCallableMCPUpstream` + `ahandle_jsonrpc`)
  - `MCPHttpGateway` ASGI 3.0 & stdlib `ThreadingHTTPServer` (multi-tenant auth,
    Streamable-HTTP `/mcp`, `/sse`, `/admin/policies`, `/admin/escalations`,
    `/admin/audit`, `/admin/recovery/sweep`, `/dashboard`)
  - CLI flags `--http`, `--api-key`, `--pg-dsn`
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

import httpx
import pytest

from gatekeep.control_plane import (
    CentralPolicyRegistry,
    EscalationRouter,
    ToolPolicySpec,
    WebhookEscalationNotifier,
)
from gatekeep.persistence import (
    ConcurrencyConflictError,
    InMemorySessionStore,
    PostgresSessionStore,
)
from gatekeep.mcp.cli import build_parser, parse_api_keys, parse_http_bind
from gatekeep.mcp.http_server import MCPHttpGateway, create_http_server
from gatekeep.mcp.proxy import (
    AsyncCallableMCPUpstream,
    CallableMCPUpstream,
    MCPTransactionProxy,
)


# ── Fake Postgres DB-API 2.0 Connection ────────────────────────────────────────


class _FakePgCursor:
    def __init__(self, conn: "_FakePgConnection") -> None:
        self._conn = conn
        self._rows: List[Tuple[Any, ...]] = []
        self.rowcount: int = 0

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        normalized = " ".join(sql.strip().split())
        self._conn.executed_sql.append(normalized)
        upper = normalized.upper()
        self._rows = []
        self.rowcount = 0

        if upper.startswith("CREATE TABLE"):
            return
        if upper in ("BEGIN", "COMMIT", "ROLLBACK"):
            return

        if "SELECT PG_TRY_ADVISORY_LOCK" in upper:
            key = int(params[0])
            if self._conn.force_lock_busy:
                self._rows = [(False,)]
                return
            if key in self._conn.advisory_locks:
                self._rows = [(False,)]
            else:
                self._conn.advisory_locks.add(key)
                self._rows = [(True,)]
            return

        if "SELECT PG_ADVISORY_UNLOCK" in upper:
            key = int(params[0])
            self._conn.advisory_locks.discard(key)
            self._rows = [(True,)]
            return

        if upper.startswith("SELECT VERSION FROM") and "FOR UPDATE" in upper:
            sid = str(params[0])
            rec = self._conn.rows.get(sid)
            self._rows = [(rec[0],)] if rec is not None else []
            return

        if upper.startswith("INSERT INTO"):
            sid, version, payload, updated_at = params
            self._conn.rows[str(sid)] = (int(version), str(payload), float(updated_at))
            self.rowcount = 1
            return

        if upper.startswith("SELECT PAYLOAD FROM"):
            sid = str(params[0])
            rec = self._conn.rows.get(sid)
            self._rows = [(rec[1],)] if rec is not None else []
            return

        if upper.startswith("DELETE FROM"):
            sid = str(params[0])
            if sid in self._conn.rows:
                del self._conn.rows[sid]
                self.rowcount = 1
            return

        if upper.startswith("SELECT SESSION_ID FROM"):
            self._rows = [(sid,) for sid in sorted(self._conn.rows.keys())]
            return

        raise AssertionError(f"Unexpected SQL in fake Postgres connection: {normalized}")

    def fetchone(self) -> Optional[Tuple[Any, ...]]:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> List[Tuple[Any, ...]]:
        return list(self._rows)

    def close(self) -> None:
        pass


class _FakePgConnection:
    def __init__(self) -> None:
        self.autocommit = False
        self.rows: Dict[str, Tuple[int, str, float]] = {}
        self.advisory_locks: set[int] = set()
        self.executed_sql: List[str] = []
        self.force_lock_busy: bool = False
        self.commits: int = 0
        self.rollbacks: int = 0
        self.closed: bool = False

    def cursor(self) -> _FakePgCursor:
        return _FakePgCursor(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


# ── Shared MCP Upstream Fixture Builder ────────────────────────────────────────


def _build_gateway(api_keys: Optional[Dict[str, str]] = None):
    calls: List[Tuple[str, Dict[str, Any]]] = []
    fail_on: Dict[str, bool] = {"charge": False}

    tools = [
        {
            "name": "read_order",
            "description": "Lookup customer order details",
            "inputSchema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
            "_slim_meta": {"mode": "READ", "provides": ["order_verified", "order_id"]},
        },
        {
            "name": "reserve_inventory",
            "description": "Reserve inventory units for an order",
            "inputSchema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
            "_slim_meta": {
                "mode": "WRITE",
                "requires": ["order_verified"],
                "compensates_with": "release_inventory",
                "compensation_args": {"reservation_id": "{result.reservation_id}"},
            },
        },
        {
            "name": "release_inventory",
            "description": "Release reserved inventory",
            "inputSchema": {
                "type": "object",
                "properties": {"reservation_id": {"type": "string"}},
                "required": ["reservation_id"],
            },
            "_slim_meta": {"mode": "WRITE"},
        },
        {
            "name": "charge_card",
            "description": "Charge customer payment card",
            "inputSchema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}, "amount": {"type": "number"}},
                "required": ["order_id", "amount"],
            },
            "_slim_meta": {"mode": "WRITE", "requires": ["order_verified"]},
        },
    ]

    async def async_executor(name: str, args: Dict[str, Any]) -> Any:
        await asyncio.sleep(0)
        calls.append((name, dict(args)))
        if name == "read_order":
            return {"order_id": args["order_id"], "order_verified": True}
        if name == "reserve_inventory":
            return {"reservation_id": f"RES-{args['order_id']}"}
        if name == "release_inventory":
            return {"released": args["reservation_id"]}
        if name == "charge_card":
            if fail_on["charge"]:
                raise RuntimeError("Gateway timeout")
            return {"charged": args["amount"], "order_id": args["order_id"]}
        return {}

    upstream = AsyncCallableMCPUpstream(tools=tools, executor=async_executor)
    store = InMemorySessionStore()
    policies = CentralPolicyRegistry()
    router = EscalationRouter()
    proxy = MCPTransactionProxy(
        upstream=upstream,
        session_store=store,
        policy_registry=policies,
        escalation_router=router,
        strict_provenance=False,
    )
    gateway = MCPHttpGateway(proxy, api_keys=api_keys)
    return gateway, proxy, calls, fail_on


# ── 1. PostgresSessionStore Tests ──────────────────────────────────────────────


def test_postgres_session_store_cas_and_advisory_locks():
    conn = _FakePgConnection()
    store = PostgresSessionStore(conn=conn, table_name="custom_sessions")

    v1 = store.save("sess_1", {"ledger": {"turn": 1}, "gate": {"receipts": []}})
    assert v1 == 1
    assert any("FOR UPDATE" in q for q in conn.executed_sql)

    loaded = store.load("sess_1")
    assert loaded is not None
    assert loaded["version"] == 1
    assert loaded["ledger"]["turn"] == 1

    v2 = store.save("sess_1", {"ledger": {"turn": 2}, "gate": {}}, expected_version=1)
    assert v2 == 2

    with pytest.raises(ConcurrencyConflictError):
        store.save("sess_1", {"ledger": {"turn": 3}, "gate": {}}, expected_version=1)

    with store.session_lock("sess_1", timeout_s=1.0):
        assert len(conn.advisory_locks) == 1
    assert len(conn.advisory_locks) == 0

    conn.force_lock_busy = True
    with pytest.raises(TimeoutError):
        with store.session_lock("sess_1", timeout_s=0.05):
            pass
    conn.force_lock_busy = False

    assert store.list_sessions() == ["sess_1"]
    assert store.delete("sess_1") is True
    assert store.load("sess_1") is None


def test_postgres_session_store_validation_and_missing_driver(monkeypatch):
    with pytest.raises(ValueError):
        PostgresSessionStore(conn=_FakePgConnection(), table_name="bad; DROP TABLE x")

    with pytest.raises(ValueError):
        PostgresSessionStore(dsn=None, conn=None)

    monkeypatch.setitem(sys.modules, "psycopg", None)
    monkeypatch.setitem(sys.modules, "psycopg2", None)
    with pytest.raises(ImportError, match="psycopg"):
        PostgresSessionStore(dsn="postgresql://user:pass@localhost:5432/db")


# ── 2. WebhookEscalationNotifier Tests ─────────────────────────────────────────


def test_webhook_escalation_notifier_hmac_and_slack():
    received: List[Dict[str, Any]] = []

    class _WebhookHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            received.append(
                {
                    "path": self.path,
                    "sig": self.headers.get("X-Slim-Signature"),
                    "raw": body,
                    "json": json.loads(body.decode("utf-8")),
                }
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), _WebhookHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        secret = "whsec_super_secret"
        json_notifier = WebhookEscalationNotifier(
            url=f"http://127.0.0.1:{port}/json",
            signing_secret=secret,
            payload_format="json",
            approve_base_url="https://gatekeep.example.com",
        )
        slack_notifier = WebhookEscalationNotifier(
            url=f"http://127.0.0.1:{port}/slack",
            payload_format="slack",
            approve_base_url="https://gatekeep.example.com",
        )

        router = EscalationRouter()
        router.add_listener(json_notifier)
        router.add_listener(slack_notifier)

        ticket = router.create_ticket(
            session_id="acme:order_42",
            tool_name="charge_card",
            arguments={"order_id": "ORD-42", "amount": 2500},
            reason="Amount exceeds $500 threshold",
        )

        assert len(received) == 2
        json_evt, slack_evt = received[0], received[1]

        expected_sig = WebhookEscalationNotifier.compute_signature(secret, json_evt["raw"])
        assert json_evt["sig"] == expected_sig
        assert json_evt["json"]["event"] == "gatekeep.escalation.created"
        assert json_evt["json"]["ticket"]["ticket_id"] == ticket.ticket_id
        assert f"/admin/escalations/{ticket.ticket_id}/approve" in json_evt["json"]["actions"]["approve_url"]

        assert slack_evt["json"]["blocks"][0]["type"] == "header"
        assert "charge_card" in slack_evt["json"]["text"]
    finally:
        server.shutdown()
        server.server_close()


# ── 3. Async Proxy + Auto-Rollback Tests ───────────────────────────────────────


def test_async_proxy_saga_auto_rollback():
    async def _run() -> None:
        _gateway, proxy, calls, fail_on = _build_gateway()

        await proxy.ahandle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_order", "arguments": {"order_id": "O-99"}},
            }
        )
        await proxy.ahandle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "reserve_inventory", "arguments": {"order_id": "O-99"}},
            }
        )

        fail_on["charge"] = True
        resp = await proxy.ahandle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "charge_card",
                    "arguments": {"order_id": "O-99", "amount": 90},
                },
            }
        )
        assert resp is not None
        sc = resp["result"]["structuredContent"]
        assert resp["result"]["isError"] is True
        assert sc["auto_rollback"]["success"] is True
        assert sc["auto_rollback"]["compensated_steps"] == 1
        assert calls[-1] == ("release_inventory", {"reservation_id": "RES-O-99"})

    asyncio.run(_run())


# ── 4. ASGI HTTP / SSE / Control Plane Tests ───────────────────────────────────


def test_asgi_http_gateway_auth_isolation_escalation_audit_and_dashboard():
    async def _run() -> None:
        gateway, proxy, calls, _fail_on = _build_gateway(
            api_keys={"key_acme": "acme", "key_globex": "globex"}
        )
        transport = httpx.ASGITransport(app=gateway)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # 1. Healthz & Dashboard are reachable
            h = await client.get("/healthz")
            assert h.status_code == 200
            assert h.json()["status"] == "ok"

            dash = await client.get("/dashboard")
            assert dash.status_code == 200
            assert "Gatekeep Control Plane" in dash.text

            # 2. Missing/invalid Bearer key -> 401
            unauth = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
            assert unauth.status_code == 401

            bad_auth = await client.post(
                "/mcp",
                headers={"Authorization": "Bearer wrong"},
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert bad_auth.status_code == 401

            acme_hdrs = {"Authorization": "Bearer key_acme"}
            globex_hdrs = {"Authorization": "Bearer key_globex"}

            # 3. Hot-reload policy requiring approval over $500
            pol_resp = await client.post(
                "/admin/policies",
                headers=acme_hdrs,
                json={
                    "tools": {
                        "charge_card": {
                            "requires_approval": True,
                            "policy": "amount <= 5000",
                        }
                    }
                },
            )
            assert pol_resp.status_code == 200
            assert "charge_card" in pol_resp.json()["policies"]["tools"]

            # 4. Acme executes read_order then attempts charge_card -> ESCALATE
            r1 = await client.post(
                "/mcp",
                headers=acme_hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "read_order",
                        "arguments": {"order_id": "ORD-1"},
                        "_meta": {"session_id": "checkout"},
                    },
                },
            )
            assert r1.status_code == 200
            assert r1.json()["result"].get("isError", False) is False

            r2 = await client.post(
                "/mcp",
                headers=acme_hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {
                        "name": "charge_card",
                        "arguments": {"order_id": "ORD-1", "amount": 900},
                        "_meta": {"session_id": "checkout"},
                    },
                },
            )
            sc2 = r2.json()["result"]["structuredContent"]
            assert sc2["verdict"] == "ESCALATE"

            # 5. Escalation queue visible to Acme, hidden from Globex
            esc_acme = await client.get("/admin/escalations", headers=acme_hdrs)
            assert esc_acme.status_code == 200
            assert esc_acme.json()["count"] == 1
            ticket = esc_acme.json()["tickets"][0]
            assert ticket["session_id"] == "acme:checkout"
            assert "approval_token" not in ticket
            ticket_id = ticket["ticket_id"]

            esc_globex = await client.get("/admin/escalations", headers=globex_hdrs)
            assert esc_globex.status_code == 200
            assert esc_globex.json()["count"] == 0

            # Globex cannot approve Acme's ticket (403)
            forbid = await client.post(
                f"/admin/escalations/{ticket_id}/approve",
                headers=globex_hdrs,
                json={"approver": "mallory"},
            )
            assert forbid.status_code == 403

            # Acme approves -> replay succeeds with issued approval_token
            app_resp = await client.post(
                f"/admin/escalations/{ticket_id}/approve",
                headers=acme_hdrs,
                json={"approver": "alice@acme.com"},
            )
            assert app_resp.status_code == 200
            approved_ticket = app_resp.json()
            assert approved_ticket["status"] == "APPROVED"

            r3 = await client.post(
                "/mcp",
                headers=acme_hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 12,
                    "method": "tools/call",
                    "params": {
                        "name": "charge_card",
                        "arguments": {"order_id": "ORD-1", "amount": 900},
                        "_meta": {
                            "session_id": "checkout",
                            "approval_token": approved_ticket["approval_token"],
                        },
                    },
                },
            )
            assert r3.status_code == 200
            assert ("charge_card", {"order_id": "ORD-1", "amount": 900}) in calls

            # 6. Audit query + SHA-256 verification scoped by tenant
            audit_acme = await client.get("/admin/audit", headers=acme_hdrs)
            assert audit_acme.status_code == 200
            assert audit_acme.json()["count"] >= 3

            audit_globex = await client.get("/admin/audit", headers=globex_hdrs)
            assert audit_globex.status_code == 200
            assert audit_globex.json()["count"] == 0

            verify_acme = await client.get("/admin/audit/verify", headers=acme_hdrs)
            assert verify_acme.status_code == 200
            assert verify_acme.json()["valid"] is True
            assert verify_acme.json()["sessions"] == {"acme:checkout": True}

            # 7. SSE endpoint stream check (?once=1 closes immediately after initial endpoint frame)
            sse_resp = await client.get("/sse?session_id=checkout&once=1", headers=acme_hdrs)
            assert sse_resp.status_code == 200
            assert "text/event-stream" in sse_resp.headers["content-type"]
            assert "event: endpoint" in sse_resp.text
            assert "/messages?session_id=checkout" in sse_resp.text

            # 8. Recovery sweep rolls back stale uncommitted Saga session
            await client.post(
                "/mcp",
                headers=acme_hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 13,
                    "method": "tools/call",
                    "params": {
                        "name": "reserve_inventory",
                        "arguments": {"order_id": "ORD-1"},
                        "_meta": {"session_id": "abandoned"},
                    },
                },
            )
            # First satisfy order_verified inside abandoned session:
            await client.post(
                "/mcp",
                headers=acme_hdrs,
                json=[
                    {
                        "jsonrpc": "2.0",
                        "id": 14,
                        "method": "tools/call",
                        "params": {
                            "name": "read_order",
                            "arguments": {"order_id": "ORD-7"},
                            "_meta": {"session_id": "abandoned"},
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 15,
                        "method": "tools/call",
                        "params": {
                            "name": "reserve_inventory",
                            "arguments": {"order_id": "ORD-7"},
                            "_meta": {"session_id": "abandoned"},
                        },
                    },
                ],
            )
            # Backdate snapshot timestamp in store to simulate crash older than 10s
            snap = proxy.session_store.load("acme:abandoned")
            assert snap is not None
            # Directly invoke sweep with stale_after_seconds=0
            sweep = await client.post(
                "/admin/recovery/sweep",
                headers=acme_hdrs,
                json={"stale_after_seconds": 0},
            )
            assert sweep.status_code == 200
            assert sweep.json()["recovered_sessions"] >= 1
            assert ("release_inventory", {"reservation_id": "RES-ORD-7"}) in calls

    asyncio.run(_run())


# ── 5. Stdlib ThreadingHTTPServer + CLI Parsing Tests ──────────────────────────


def test_stdlib_tcp_http_server_and_cli_flags():
    gateway, _proxy, _calls, _fail_on = _build_gateway()
    server = create_http_server(gateway, host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3.0) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode("utf-8"))["status"] == "ok"

        rpc_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/mcp",
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(rpc_req, timeout=3.0) as resp:
            assert resp.status == 200
            payload = json.loads(resp.read().decode("utf-8"))
            assert len(payload["result"]["tools"]) == 4
    finally:
        server.shutdown()
        server.server_close()

    assert parse_http_bind("0.0.0.0:9090") == ("0.0.0.0", 9090)
    assert parse_http_bind(":8081") == ("127.0.0.1", 8081)
    assert parse_http_bind("7777") == ("127.0.0.1", 7777)
    assert parse_api_keys(["acme=tok1", "tok2"]) == {"tok1": "acme", "tok2": "tenant_2"}

    parsed = build_parser().parse_args(
        [
            "--upstream",
            "python -m my_srv",
            "--http",
            "0.0.0.0:8080",
            "--api-key",
            "acme=secret1",
            "--pg-dsn",
            "postgresql://postgres:pw@localhost:5432/slim",
        ]
    )
    assert parsed.http == "0.0.0.0:8080"
    assert parsed.api_key == ["acme=secret1"]
    assert parsed.pg_dsn == "postgresql://postgres:pw@localhost:5432/slim"
