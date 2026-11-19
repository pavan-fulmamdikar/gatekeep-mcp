#!/usr/bin/env python3
"""
examples/field_test_postgres_mcp.py

Real Off-the-Shelf Third-Party MCP Server Field Test (Zero Mocks):
Wraps `@modelcontextprotocol/server-postgres` over real `npx` stdio connected to a
live PostgreSQL 16 database (`GATEKEEP_LIVE_PG_DSN`, default port 5439 from
`docker-compose.ha.yml`) behind `gatekeep.MCPTransactionProxy`.

Exercises:
  1. Real tool catalog discovery & `generate_starter_policy()` auto-classification
  2. Legitimate `SELECT` queries returning real PostgreSQL 16 rows
  3. Live destructive SQL attacks (`DROP TABLE`, un-WHERE'd `DELETE`, `WHERE 1=1`
     `UPDATE`, comment-obfuscated stacked `; DROP`, `TRUNCATE`) blocked BEFORE
     reaching `@modelcontextprotocol/server-postgres`
  4. Direct PostgreSQL table integrity verification + SHA-256 audit chain proof

Requirements: Node.js (`npx`), running PostgreSQL (e.g. `docker compose -f docker-compose.ha.yml up -d postgres`).
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from gatekeep import (
    MCPTransactionProxy,
    SQLiteSessionStore,
    StdioMCPUpstream,
    generate_starter_policy,
)

DEFAULT_PG_DSN = "postgresql://gatekeep:gatekeep_dev@127.0.0.1:5439/gatekeep"


def _resolve_npx_command(pg_dsn: str) -> List[str]:
    npx_bin = shutil.which("npx.cmd") or shutil.which("npx")
    if not npx_bin:
        raise RuntimeError("Node.js `npx` not found on PATH.")
    return [npx_bin, "-y", "@modelcontextprotocol/server-postgres", pg_dsn]


def _seed_postgres(pg_dsn: str, table: str) -> None:
    import psycopg

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                CREATE TABLE {table} (
                    id INT PRIMARY KEY,
                    name TEXT NOT NULL,
                    tier TEXT NOT NULL,
                    balance NUMERIC(10, 2) NOT NULL
                )
                """
            )
            cur.execute(
                f"""
                INSERT INTO {table} (id, name, tier, balance) VALUES
                (1, 'Acme Corp', 'enterprise', 12500.00),
                (2, 'Globex LLC', 'growth', 4200.00),
                (3, 'Initech Inc', 'starter', 850.00)
                """
            )


def _verify_and_drop_postgres(pg_dsn: str, table: str) -> int:
    import psycopg

    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            count = int(cur.fetchone()[0])
            cur.execute(f"DROP TABLE IF EXISTS {table}")
            return count


def _call(
    proxy: MCPTransactionProxy, tool_name: str, arguments: Dict[str, Any], session_id: str
) -> tuple[Dict[str, Any], float]:
    t0 = time.perf_counter()
    resp = proxy.handle_tools_call(
        {
            "name": tool_name,
            "arguments": arguments,
            "_meta": {"session_id": session_id},
        }
    )
    return resp, (time.perf_counter() - t0) * 1000.0


def run_field_test() -> Dict[str, Any]:
    pg_dsn = os.environ.get("GATEKEEP_LIVE_PG_DSN", DEFAULT_PG_DSN).strip()
    table = f"gk_field_cust_{uuid.uuid4().hex[:8]}"
    _seed_postgres(pg_dsn, table)

    with tempfile.TemporaryDirectory(prefix="gatekeep_pg_field_") as tmp:
        cmd = _resolve_npx_command(pg_dsn)
        print(f"[1/4] Launching real @modelcontextprotocol/server-postgres against {pg_dsn}")
        t_boot = time.perf_counter()
        upstream = StdioMCPUpstream(cmd)
        store = SQLiteSessionStore(str(Path(tmp) / "pg_field.db"))
        try:
            catalog = upstream.list_tools()
            boot_ms = (time.perf_counter() - t_boot) * 1000.0
            tool_map = {str(t["name"]): t for t in catalog if isinstance(t, dict) and "name" in t}
            starter = generate_starter_policy(catalog)
            print(
                f"      Connected in {boot_ms:.0f}ms | Discovered {len(tool_map)} real tool(s): "
                f"{', '.join(sorted(tool_map))}"
            )
            print(f"      Starter policy: {json.dumps(starter.get('tools', {}))}")

            query_tool = "query" if "query" in tool_map else next(iter(tool_map))
            # Inspect the SQL parameter name from the real upstream JSON schema
            schema_props = (tool_map[query_tool].get("inputSchema") or {}).get("properties") or {}
            sql_arg = "sql" if "sql" in schema_props else next(iter(schema_props), "sql")

            proxy = MCPTransactionProxy(
                upstream,
                session_store=store,
                strict_provenance=True,
                block_outbound_secrets=True,
                block_ssrf_and_sensitive_paths=True,
            )
            sid = "pg-field-enforcing-1"

            print(f"[2/4] Running legitimate SELECT queries via '{query_tool}({sql_arg}=...)'...")
            benign_cases = [
                ("select_all_customers", f"SELECT id, name, tier FROM {table} ORDER BY id"),
                ("count_customers", f"SELECT COUNT(*) AS total FROM {table}"),
            ]
            benign_results: List[Dict[str, Any]] = []
            for label, sql in benign_cases:
                resp, ms = _call(proxy, query_tool, {sql_arg: sql}, sid)
                benign_results.append(
                    {
                        "label": label,
                        "allowed": not bool(resp.get("isError")),
                        "latency_ms": round(ms, 2),
                    }
                )

            print("[3/4] Firing destructive SQL attacks (must be blocked BEFORE Node.js / Postgres)...")
            attack_cases = [
                ("drop_table", f"DROP TABLE {table};"),
                ("unwhered_delete", f"DELETE FROM {table};"),
                ("tautological_update", f"UPDATE {table} SET balance = 0 WHERE 1=1;"),
                (
                    "comment_obfuscated_stacked_drop",
                    f"SELECT * FROM {table}; /* ignore */ DROP TABLE {table};",
                ),
                ("truncate_table", f"TRUNCATE TABLE {table};"),
            ]
            attack_results: List[Dict[str, Any]] = []
            for label, sql in attack_cases:
                resp, ms = _call(proxy, query_tool, {sql_arg: sql}, sid)
                sc = resp.get("structuredContent") or {}
                attack_results.append(
                    {
                        "label": label,
                        "blocked": bool(resp.get("isError")),
                        "rule_triggered": sc.get("rule_triggered"),
                        "latency_ms": round(ms, 2),
                    }
                )

            print("[4/4] Verifying PostgreSQL 16 table integrity & SHA-256 audit chain...")
            surviving_rows = _verify_and_drop_postgres(pg_dsn, table)
            gate = proxy._load_gate(sid)
            chain_valid = gate.verify_audit_chain()
            gate_ms = [round(r.latency_ms, 3) for r in gate.receipts]

            benign_ok = sum(1 for r in benign_results if r["allowed"])
            attacks_ok = sum(
                1
                for r in attack_results
                if r["blocked"] and r["rule_triggered"] == "destructive_payload_blocked"
            )

            summary = {
                "upstream_server": "@modelcontextprotocol/server-postgres (real npx stdio + live PG 16)",
                "boot_ms": round(boot_ms, 1),
                "discovered_tools": sorted(tool_map.keys()),
                "sql_param_name": sql_arg,
                "benign_allowed": f"{benign_ok}/{len(benign_results)}",
                "attacks_blocked": f"{attacks_ok}/{len(attack_results)}",
                "benign_details": benign_results,
                "attack_details": attack_results,
                "postgres_surviving_rows": surviving_rows,
                "audit_chain_valid": chain_valid,
                "receipt_count": len(gate.receipts),
                "gatekeep_eval_latency_ms": {
                    "median": round(statistics.median(gate_ms), 3) if gate_ms else 0.0,
                    "max": round(max(gate_ms), 3) if gate_ms else 0.0,
                },
            }
            print("\n=== Real @modelcontextprotocol/server-postgres Field Test Summary ===")
            print(json.dumps(summary, indent=2))
            if (
                benign_ok != len(benign_results)
                or attacks_ok != len(attack_results)
                or surviving_rows != 3
                or not chain_valid
            ):
                raise SystemExit(1)
            return summary
        finally:
            upstream.close()
            store.close()
            try:
                _verify_and_drop_postgres(pg_dsn, table)
            except Exception:
                pass


if __name__ == "__main__":
    run_field_test()
