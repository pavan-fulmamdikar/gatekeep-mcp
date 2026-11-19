"""
examples/http_gateway_hitl_demo.py

End-to-end demo of Gatekeep's multi-tenant HTTP / Control Plane Gateway:
  1. Multi-tenant Bearer API-key authentication & strict session scoping
  2. Live policy hot-reload via `POST /admin/policies`
  3. HITL escalation pause (`Verdict.ESCALATE`) -> approval via `/admin/escalations/{id}/approve`
     -> replay with single-use `approval_token`

Requires `httpx` (`pip install httpx`). Run:
    python examples/http_gateway_hitl_demo.py
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict

import httpx

from gatekeep import (
    AsyncCallableMCPUpstream,
    CentralPolicyRegistry,
    EscalationRouter,
    InMemorySessionStore,
    MCPHttpGateway,
    MCPTransactionProxy,
)


async def main() -> None:
    tools = [
        {
            "name": "refund_order",
            "description": "Issue a customer refund",
            "inputSchema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}, "amount": {"type": "number"}},
                "required": ["order_id", "amount"],
            },
            "_slim_meta": {"mode": "write"},
        }
    ]

    async def executor(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return {"refunded": True, "order_id": args["order_id"], "amount": args["amount"]}

    proxy = MCPTransactionProxy(
        upstream=AsyncCallableMCPUpstream(tools=tools, executor=executor),
        session_store=InMemorySessionStore(),
        policy_registry=CentralPolicyRegistry(),
        escalation_router=EscalationRouter(),
        strict_provenance=False,
    )
    gateway = MCPHttpGateway(proxy, api_keys={"demo_acme_key": "acme"})

    headers = {"Authorization": "Bearer demo_acme_key"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gateway),
        base_url="http://slim-gateway.local",
    ) as client:
        # 1. Hot-reload policy requiring human sign-off for refunds
        await client.post(
            "/admin/policies",
            headers=headers,
            json={"tools": {"refund_order": {"requires_approval": True, "policy": "amount <= 5000"}}},
        )

        # 2. Agent attempts refund -> paused with Verdict.ESCALATE
        first_try = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "refund_order",
                    "arguments": {"order_id": "ORD-42", "amount": 750},
                    "_meta": {"session_id": "support-ticket-9"},
                },
            },
        )
        print("Initial call (paused for approval):")
        print(json.dumps(first_try.json()["result"]["structuredContent"], indent=2))

        # 3. Operator inspects pending escalations and approves
        esc_list = (await client.get("/admin/escalations", headers=headers)).json()
        ticket_id = esc_list["tickets"][0]["ticket_id"]
        approved = (
            await client.post(
                f"/admin/escalations/{ticket_id}/approve",
                headers=headers,
                json={"approver": "finance-lead@acme.com"},
            )
        ).json()

        # 4. Replay with granted single-use approval token
        replay = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "refund_order",
                    "arguments": {"order_id": "ORD-42", "amount": 750},
                    "_meta": {
                        "session_id": "support-ticket-9",
                        "approval_token": approved["approval_token"],
                    },
                },
            },
        )
        print("\nApproved replay result:")
        print(json.dumps(replay.json()["result"]["structuredContent"], indent=2))

        # 5. Audit Chain Verification
        verified = (await client.get("/admin/audit/verify", headers=headers)).json()
        print("\nAudit Chain Verify:", verified)


if __name__ == "__main__":
    asyncio.run(main())
