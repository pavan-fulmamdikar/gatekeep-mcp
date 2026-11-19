"""Pytest verification for Multi-Agent Coordinator + Sub-Agents running through Gatekeep telemetry."""

from examples.multi_agent_gatekeep_runner import run_multi_agent_session


def test_multi_agent_coordinator_and_subagents_session_telemetry() -> None:
    res = run_multi_agent_session(live=False, verbose=False)
    tel = res["telemetry"]

    assert tel["total_tool_calls"] >= 15
    assert tel["verdict_counts"]["ALLOW"] >= 9
    assert tel["verdict_counts"]["BLOCK"] >= 5
    assert tel["verdict_counts"]["ESCALATE"] == 1

    # Verify Gatekeep caught every attack category across the 3 sub-agents
    rules = tel["rules_triggered"]
    assert "sensitive_path_access" in rules
    assert "ssrf_blocked_target" in rules
    assert "cumulative_spend_limit_exceeded" in rules
    assert "outbound_secret_dlp" in rules
    assert "human_approval_required" in rules

    # Verify per-actor telemetry separation & unbroken AuditVault chain
    assert set(tel["by_actor"].keys()) == {
        "subagent-research",
        "subagent-finance",
        "subagent-comms",
    }
    assert tel["audit_vault"]["chain_valid"] is True
    assert tel["audit_vault"]["receipt_count"] >= 15
    assert tel["gatekeep_latency_ms"]["p95"] >= 0.0

    # Verify real SQLite end-state (503 rolled back first attempt, final clean reconciliation committed)
    by_id = {r["order_id"]: r for r in res["orders"]}
    assert by_id["ORD-701"]["rebate_paid"] == 45.0
    assert by_id["ORD-702"]["rebate_paid"] == 80.0
    assert by_id["ORD-703"]["rebate_paid"] == 600.0


def test_read_circuit_breaker_and_multiagent_postmortem_scoping() -> None:
    """Blocked reads on bad paths must not brick safe reads, and comms actors can report aborted sagas."""
    from gatekeep import slim_tool
    from gatekeep.gate import PreExecutionGate, Verdict
    from gatekeep.ledger import ToolReturnLedger
    from gatekeep.mcp.proxy import CallableMCPUpstream, MCPTransactionProxy
    from gatekeep.registry import ToolRegistry

    reg = ToolRegistry()

    @slim_tool(description="Read workspace file.", mode="read", registry=reg)
    def read_doc(path: str) -> dict:
        return {"content": "ok"}

    gate = PreExecutionGate(
        ledger=ToolReturnLedger(session_id="scoping-1"),
        registry=reg,
        max_tool_retries=2,
    )
    # Two failed attempts on .env.secrets trip breaker specifically for .env.secrets...
    assert gate.evaluate("read_doc", {"path": ".env.secrets"}, actor_id="research").verdict == Verdict.BLOCK
    assert gate.evaluate("read_doc", {"path": ".env.secrets"}, actor_id="research").verdict == Verdict.BLOCK
    d_bad = gate.evaluate("read_doc", {"path": ".env.secrets"}, actor_id="research")
    assert d_bad.rule_triggered == "retry_spiral_circuit_breaker"

    # ...yet safe reads on the exact same tool continue working across actors!
    assert gate.evaluate("read_doc", {"path": "compliance_notes.md"}, actor_id="research").allowed is True
    assert gate.evaluate("read_doc", {"path": "compliance_notes.md"}, actor_id="finance").allowed is True

    # Multi-agent Saga abort scoping: finance aborts, finance is locked, comms can report outage
    tools = [
        {
            "name": "payout",
            "description": "Issue payout",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
            "_slim_meta": {
                "mode": "write",
                "compensates_with": "void_payout",
                "compensation_args": {"id": "{args.id}"},
                "provenance_args": [],
            },
        },
        {
            "name": "void_payout",
            "description": "Void payout",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
            "_slim_meta": {"mode": "write", "provenance_args": []},
        },
        {
            "name": "sync_erp",
            "description": "Sync ERP",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
            "_slim_meta": {"mode": "write", "provenance_args": []},
        },
        {
            "name": "write_report",
            "description": "Write incident summary",
            "inputSchema": {"type": "object", "properties": {"body": {"type": "string"}}},
            "_slim_meta": {"mode": "write", "provenance_args": []},
        },
    ]
    events: list[str] = []

    def _exec(name: str, args: dict) -> dict:
        events.append(name)
        if name == "sync_erp":
            return {"isError": True, "error": "503"}
        return {"ok": True}

    proxy = MCPTransactionProxy(
        upstream=CallableMCPUpstream(tools=tools, executor=_exec),
        auto_rollback_on_error=True,
    )
    prompt = "Run payouts and report status"
    assert (
        proxy.handle_tools_call(
            {
                "name": "payout",
                "arguments": {"id": "O1"},
                "_meta": {"session_id": "ma-1", "actor_id": "subagent-finance", "user_prompt": prompt},
            }
        )["isError"]
        is False
    )
    crash = proxy.handle_tools_call(
        {
            "name": "sync_erp",
            "arguments": {"id": "O1"},
            "_meta": {"session_id": "ma-1", "actor_id": "subagent-finance", "user_prompt": prompt},
        }
    )
    assert crash["isError"] is True
    assert "void_payout" in events

    # Retrying financial mutation or same actor in same aborted turn stays blocked
    fin_retry = proxy.handle_tools_call(
        {
            "name": "payout",
            "arguments": {"id": "O1"},
            "_meta": {"session_id": "ma-1", "actor_id": "subagent-finance", "user_prompt": prompt},
        }
    )
    assert fin_retry["structuredContent"]["rule_triggered"] == "saga_transaction_aborted"

    # Comms sub-agent writing a non-rolled-back outage report succeeds cleanly
    comms_ok = proxy.handle_tools_call(
        {
            "name": "write_report",
            "arguments": {"body": "ERP 503 outage rolled back O1 cleanly."},
            "_meta": {"session_id": "ma-1", "actor_id": "subagent-comms", "user_prompt": prompt},
        }
    )
    assert comms_ok["isError"] is False
