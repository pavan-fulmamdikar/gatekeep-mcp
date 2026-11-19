"""
Tests for Phase 4: Enterprise Control Plane & Framework-Agnostic MCP Transaction Proxy:
  - CentralPolicyRegistry (hot reload, fail-fast AST validation, dynamic overlays, disable switch)
  - Declarative Saga `{result.*}` / `{args.*}` compensation templates
  - EscalationRouter (HITL listener, one-time token approval directly against SQLite store, expiry/reject)
  - SagaRecoveryDaemon (out-of-band sweeper + background thread lifecycle)
  - AuditVault (multi-session query, JSONL export, tamper detection)
  - MCPTransactionProxy (JSON-RPC 2.0, federated upstreams, auto-rollback on error, stdio loop, StdioMCPUpstream)
"""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from gatekeep import (
    AuditVault,
    CallableMCPUpstream,
    CentralPolicyRegistry,
    EscalationRouter,
    MCPTransactionProxy,
    PreExecutionGate,
    RegistryMCPUpstream,
    SQLiteSessionStore,
    SagaRecoveryDaemon,
    StdioMCPUpstream,
    ToolPolicySpec,
    ToolRegistry,
    Verdict,
    slim_tool,
)
from gatekeep.policy import PolicySyntaxError


def test_central_policy_registry_validation_and_hot_reload(tmp_path: Path) -> None:
    # Unsafe expression fails fast at policy registration
    with pytest.raises(PolicySyntaxError):
        ToolPolicySpec(tool_name="refund_order", policy="__import__('os').system('ls')")

    reg = ToolRegistry()

    @slim_tool(mode="read", provides=["order"], description="Read order info", registry=reg)
    def get_order(order_id: str) -> Dict[str, Any]:
        return {"order_id": order_id, "amount": 400}

    @slim_tool(mode="write", description="Refund an order", registry=reg)
    def refund_order(order_id: str, amount: float) -> Dict[str, Any]:
        return {"order_id": order_id, "refunded": amount}

    policy_file = tmp_path / "policies.json"
    policy_file.write_text(
        json.dumps(
            {
                "tools": {
                    "refund_order": {
                        "mode": "write",
                        "requires": ["order"],
                        "policy": "amount <= 500",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    policy_reg = CentralPolicyRegistry()
    v1 = policy_reg.load_file(policy_file)
    assert v1 >= 2

    gate = PreExecutionGate(registry=reg, policy_registry=policy_reg)
    gate.ledger.observe_user_input("Refund ORD-10 for 250")
    gate.ledger.absorb_tool_return("get_order", {"order_id": "ORD-10"}, {"order_id": "ORD-10", "amount": 400}, mode="read", provides=["order"])

    # Allowed under initial <= 500 policy
    d1 = gate.evaluate("refund_order", {"order_id": "ORD-10", "amount": 250})
    assert d1.allowed is True

    # Hot-reload tighter limit <= 100 without touching Python tool decorators
    policy_reg.load_dict({"tools": {"refund_order": {"requires": ["order"], "policy": "amount <= 100"}}})
    d2 = gate.evaluate("refund_order", {"order_id": "ORD-10", "amount": 250})
    assert d2.verdict == Verdict.REVISE
    assert d2.rule_triggered == "central_declarative_policy_violation"

    # Central emergency kill-switch disables tool immediately
    policy_reg.set_policy(ToolPolicySpec(tool_name="refund_order", enabled=False))
    d3 = gate.evaluate("refund_order", {"order_id": "ORD-10", "amount": 50})
    assert d3.verdict == Verdict.BLOCK
    assert d3.rule_triggered == "central_policy_disabled"


def test_escalation_router_hitl_approval_and_sqlite_persistence(tmp_path: Path) -> None:
    db_path = tmp_path / "hitl.db"
    reg = ToolRegistry()
    notifications: List[str] = []

    @slim_tool(
        mode="write",
        requires_approval=True,
        description="Delete production database table",
        registry=reg,
    )
    def drop_table(table_name: str) -> Dict[str, Any]:
        return {"dropped": table_name}

    router = EscalationRouter(default_ttl_seconds=60.0)
    router.add_listener(lambda t: notifications.append(f"{t.ticket_id}:{t.tool_name}"))

    with SQLiteSessionStore(str(db_path)) as store:
        gate = PreExecutionGate.from_store(
            session_id="hitl-sess-1",
            session_store=store,
            registry=reg,
            escalation_router=router,
        )
        gate.ledger.observe_user_input("Drop table temp_logs")

        d1 = gate.evaluate("drop_table", {"table_name": "temp_logs"})
        assert d1.verdict == Verdict.ESCALATE
        ticket_id = d1.ledger_facts["escalation_ticket_id"]
        assert len(notifications) == 1
        assert notifications[0].startswith(ticket_id)

        # Approver clicks Approve in Slack/dashboard -> grants token directly to durable SQLite session
        approved = router.approve(ticket_id, approver="sec-oncall@corp.io", session_store=store)
        assert approved.status == "APPROVED"

        # New worker instance picks up the persisted approval token
        gate_reloaded = PreExecutionGate.from_store(
            session_id="hitl-sess-1",
            session_store=store,
            registry=reg,
            escalation_router=router,
        )
        d2 = gate_reloaded.evaluate(
            "drop_table",
            {"table_name": "temp_logs"},
            approval_token=approved.approval_token,
        )
        assert d2.verdict == Verdict.ALLOW
        assert gate_reloaded.verify_audit_chain() is True

        # Replay of single-use token must escalate again
        d3 = gate_reloaded.evaluate(
            "drop_table",
            {"table_name": "temp_logs"},
            approval_token=approved.approval_token,
        )
        assert d3.verdict == Verdict.ESCALATE


def test_saga_recovery_daemon_and_audit_vault(tmp_path: Path) -> None:
    db_path = tmp_path / "daemon.db"
    rollbacks: List[str] = []
    reg = ToolRegistry()

    @slim_tool(mode="write", description="Delete reserved IP", registry=reg)
    def release_ip(ip_id: str) -> Dict[str, Any]:
        rollbacks.append(ip_id)
        return {"released": ip_id}

    policy_reg = CentralPolicyRegistry(
        specs=[
            ToolPolicySpec(
                tool_name="allocate_ip",
                mode="write",
                compensates_with="release_ip",
                compensation_args={"ip_id": "{result.ip_id}"},
            )
        ]
    )

    @slim_tool(mode="write", description="Allocate elastic IP", registry=reg)
    def allocate_ip(region: str) -> Dict[str, Any]:
        return {"ip_id": f"eip-{region}-99"}

    with SQLiteSessionStore(str(db_path)) as store:
        # Stale crashed session
        g_stale = PreExecutionGate.from_store(
            "stale-worker-1", store, registry=reg, policy_registry=policy_reg
        )
        g_stale.ledger.observe_user_input("Allocate IP in us-east")
        assert g_stale.evaluate("allocate_ip", {"region": "us-east"}).allowed
        g_stale.ledger.absorb_tool_return("allocate_ip", {"region": "us-east"}, {"ip_id": "eip-us-east-99"}, mode="write")
        assert g_stale.saga.pending_count == 1

        # Daemon sweep 600s in the future triggers out-of-band rollback
        daemon = SagaRecoveryDaemon(
            session_store=store,
            registry=reg,
            policy_registry=policy_reg,
            stale_after_seconds=300.0,
            poll_interval_seconds=0.05,
        )
        # Active check right now (0s elapsed) skips recovery
        report_early = daemon.sweep_once(now=time.time())
        assert report_early.stale_sessions_found == 0
        assert rollbacks == []

        # Future sweep triggers automated recovery
        report_stale = daemon.sweep_once(now=time.time() + 400.0)
        assert report_stale.stale_sessions_found == 1
        assert report_stale.recovered_sessions == 1
        assert report_stale.failed_sessions == 0
        assert rollbacks == ["eip-us-east-99"]

        # Verify background daemon start/stop exits cleanly
        daemon.start()
        daemon.stop()

        # Verify AuditVault compliance queries, chain check, and JSONL export
        vault = AuditVault(store)
        chains = vault.verify_all_chains()
        assert chains == {"stale-worker-1": True}

        rb_receipts = vault.query(verdict=Verdict.ROLLBACK)
        assert len(rb_receipts) == 1
        assert rb_receipts[0].tool_name == "release_ip"

        export_path = tmp_path / "audit_export.jsonl"
        jsonl = vault.export_jsonl(output_path=export_path)
        assert export_path.exists()
        assert len(jsonl.strip().splitlines()) == 2  # ALLOW + ROLLBACK


def test_mcp_proxy_central_policies_and_auto_rollback_on_error(tmp_path: Path) -> None:
    """
    End-to-end MCP gateway scenario without Python decorators:
      1. Upstream exposes plain MCP tools (`db_insert`, `db_delete`, `charge_card`, `secret_drop`).
      2. CentralPolicyRegistry attaches Saga template (`db_insert` -> `db_delete(row_id="{result.row_id}")`)
         and disables `secret_drop`.
      3. `db_insert` succeeds, then `charge_card` fails -> MCPTransactionProxy automatically rolls back
         the database insert over MCP and persists tamper-evident audit receipts to SQLite.
    """
    db_path = tmp_path / "mcp_proxy.db"
    db_rows: Dict[str, Dict[str, Any]] = {}

    mcp_tools = [
        {
            "name": "db_insert",
            "description": "Insert order row into database",
            "inputSchema": {"type": "object", "properties": {"order_id": {"type": "string"}}},
        },
        {
            "name": "db_delete",
            "description": "Delete order row by row_id",
            "inputSchema": {"type": "object", "properties": {"row_id": {"type": "string"}}},
        },
        {
            "name": "charge_card",
            "description": "Charge customer payment card",
            "inputSchema": {"type": "object", "properties": {"order_id": {"type": "string"}, "amount": {"type": "number"}}},
        },
        {
            "name": "secret_drop",
            "description": "Disabled admin tool",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]

    def mcp_executor(name: str, args: Dict[str, Any]) -> Any:
        if name == "db_insert":
            rid = f"row-{args['order_id']}"
            db_rows[rid] = dict(args)
            return {"row_id": rid, "status": "inserted"}
        if name == "db_delete":
            db_rows.pop(args["row_id"], None)
            return {"deleted": args["row_id"]}
        if name == "charge_card":
            raise RuntimeError("Upstream 502 payment gateway timeout")
        return {"ok": True}

    policy_reg = CentralPolicyRegistry()
    policy_reg.load_dict(
        {
            "tools": {
                "db_insert": {
                    "mode": "write",
                    "provides": ["row"],
                    "compensates_with": "db_delete",
                    "compensation_args": {"row_id": "{result.row_id}"},
                },
                "db_delete": {"mode": "write"},
                "charge_card": {"mode": "write", "requires": ["row"], "policy": "amount <= 1000"},
                "secret_drop": {"enabled": False},
            }
        }
    )

    upstream = CallableMCPUpstream(mcp_tools, mcp_executor)
    with SQLiteSessionStore(str(db_path)) as store:
        proxy = MCPTransactionProxy(
            upstream=upstream,
            session_store=store,
            policy_registry=policy_reg,
            auto_rollback_on_error=True,
        )

        # tools/list omits disabled tool `secret_drop`
        list_resp = proxy.handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        assert list_resp is not None
        names = [t["name"] for t in list_resp["result"]["tools"]]
        assert "db_insert" in names
        assert "secret_drop" not in names

        # Observe user intent
        proxy.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "slim/observe_user",
            "params": {"session_id": "checkout-9", "text": "Insert order ORD-9 and charge 200"},
        })

        # Step 1 succeeds and populates db_rows
        r1 = proxy.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "db_insert",
                "arguments": {"order_id": "ORD-9"},
                "_meta": {"session_id": "checkout-9"},
            },
        })
        assert r1["result"]["isError"] is False
        assert "row-ORD-9" in db_rows

        # Policy gate blocks card charge > 1000 cleanly before hitting upstream
        r_pol = proxy.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "charge_card",
                "arguments": {"order_id": "ORD-9", "amount": 5000},
                "_meta": {"session_id": "checkout-9"},
            },
        })
        assert r_pol["result"]["isError"] is True
        assert r_pol["result"]["structuredContent"]["verdict"] == "REVISE"
        assert "row-ORD-9" in db_rows  # Recoverable REVISE did not roll back yet

        # Valid amount fails upstream with 502 -> triggers automated LIFO Saga rollback (`db_delete`)!
        r2 = proxy.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "charge_card",
                "arguments": {"order_id": "ORD-9", "amount": 200},
                "_meta": {"session_id": "checkout-9"},
            },
        })
        assert r2["result"]["isError"] is True
        assert r2["result"]["structuredContent"]["auto_rollback"]["success"] is True
        assert r2["result"]["structuredContent"]["auto_rollback"]["compensated_steps"] == 1
        assert "row-ORD-9" not in db_rows

        # Verify cryptographic audit chain via JSON-RPC extension
        audit = proxy.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "slim/audit_verify",
            "params": {"session_id": "checkout-9"},
        })
        assert audit["result"]["chain_valid"] is True
        assert audit["result"]["receipt_count"] >= 4


def test_mcp_proxy_stdio_loop_and_federated_upstreams() -> None:
    reg_a = ToolRegistry()

    @slim_tool(mode="read", provides=["user"], description="Get user profile", registry=reg_a)
    def get_user(user_id: str) -> Dict[str, Any]:
        return {"user_id": user_id, "tier": "pro"}

    up_b = CallableMCPUpstream(
        [{"name": "ping_db", "description": "Ping SQL database", "inputSchema": {"type": "object", "properties": {}}}],
        lambda name, args: {"alive": True},
    )

    proxy = MCPTransactionProxy(upstream={"auth": RegistryMCPUpstream(reg_a), "sql": up_b})

    stdin_lines = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json.dumps({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "auth.get_user", "arguments": {"user_id": "u-42"}, "_meta": {"session_id": "stdio-1"}},
            }),
        ]
    ) + "\n"

    stdout_buf = io.StringIO()
    proxy.serve_stdio(stdin=io.StringIO(stdin_lines), stdout=stdout_buf)

    responses = [json.loads(line) for line in stdout_buf.getvalue().strip().splitlines()]
    # notification produces no response -> 3 responses
    assert len(responses) == 3
    assert responses[0]["id"] == 1
    assert responses[0]["result"]["serverInfo"]["name"] == "slim-schema-mcp-proxy"
    tool_names = {t["name"] for t in responses[1]["result"]["tools"]}
    assert tool_names == {"auth.get_user", "sql.ping_db"}
    assert responses[2]["result"]["structuredContent"] == {"user_id": "u-42", "tier": "pro"}


def test_stdio_mcp_upstream_subprocess_end_to_end() -> None:
    """Spawn a real child MCP stdio server subprocess and connect via StdioMCPUpstream + MCPTransactionProxy."""
    child_code = (
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "  req = json.loads(line)\n"
        "  m = req.get('method')\n"
        "  if m == 'notifications/initialized':\n"
        "    continue\n"
        "  if m == 'initialize':\n"
        "    res = {'protocolVersion': '2024-11-05', 'capabilities': {}, 'serverInfo': {'name': 'echo-mcp'}}\n"
        "  elif m == 'tools/list':\n"
        "    res = {'tools': [{'name': 'echo_val', 'description': 'Echo text value', 'inputSchema': {'type': 'object', 'properties': {'msg': {'type': 'string'}}}}]}\n"
        "  elif m == 'tools/call':\n"
        "    args = req['params']['arguments']\n"
        "    res = {'content': [{'type': 'text', 'text': json.dumps({'echo': args['msg']})}]}\n"
        "  else:\n"
        "    res = {}\n"
        "  sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': res}) + '\\n')\n"
        "  sys.stdout.flush()\n"
    )

    with StdioMCPUpstream([sys.executable, "-c", child_code]) as child_upstream:
        proxy = MCPTransactionProxy(upstream=child_upstream)
        list_res = proxy.handle_jsonrpc({"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}})
        assert [t["name"] for t in list_res["result"]["tools"]] == ["echo_val"]

        call_res = proxy.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "echo_val", "arguments": {"msg": "hello-mcp"}, "_meta": {"session_id": "sub-1"}},
        })
        assert call_res["result"]["isError"] is False
        assert json.loads(call_res["result"]["content"][0]["text"]) == {"echo": "hello-mcp"}
