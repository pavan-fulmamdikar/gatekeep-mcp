#!/usr/bin/env python3
"""
examples/ha_demo_upstream.py

Minimal zero-dependency MCP stdio server used by `docker-compose.ha.yml`
to exercise multi-replica Gatekeep ASGI pods behind PostgreSQL 16 + Redis 7.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

TOOLS = [
    {
        "name": "read_order",
        "description": "Read an order record by order_id.",
        "inputSchema": {
            "type": "object",
            "properties": {"order_id": {"type": "string"}},
            "required": ["order_id"],
        },
    },
    {
        "name": "charge_vendor",
        "description": "Transfer funds for an order.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "string"},
                "amount": {"type": "number"},
            },
            "required": ["order_id", "amount"],
        },
    },
]


def _handle(req: Dict[str, Any]) -> Dict[str, Any] | None:
    req_id = req.get("id")
    method = str(req.get("method") or "")
    params = req.get("params") or {}
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "gatekeep-ha-demo-upstream", "version": "0.1.0"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        if name == "read_order":
            res = {"order_id": args.get("order_id", "ORD-1"), "status": "verified"}
        elif name == "charge_vendor":
            res = {"charged": True, "order_id": args.get("order_id"), "amount": args.get("amount")}
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {name}"}]},
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": json.dumps(res)}]},
        }
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = _handle(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            sys.stdout.write(
                json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(exc)}})
                + "\n"
            )
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
