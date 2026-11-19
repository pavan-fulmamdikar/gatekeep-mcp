#!/usr/bin/env python3
"""
examples/field_test_third_party_mcp.py

Real Off-the-Shelf Third-Party MCP Server Field Test (Zero Mocks).

Launches Anthropic's official `@modelcontextprotocol/server-filesystem` over real stdio
via `npx -y @modelcontextprotocol/server-filesystem <sandbox_dir>` and wraps it behind
`gatekeep.MCPTransactionProxy` to exercise:
  1. Auto-onboarding (`generate_starter_policy`) against a real third-party tool catalog
  2. Shadow-mode dry run on legitimate filesystem workflows (measuring real Gatekeep overhead)
  3. Enforcing mode allowing legitimate reads/writes while blocking path traversal,
     `.env.production`, `.ssh/id_rsa`, and outbound DLP secret exfiltration before the
     upstream Node.js MCP server ever sees the request
  4. Tamper-evident SHA-256 audit chain verification across the live session

Requirements: Node.js / `npx` on PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

from gatekeep import (
    CentralPolicyRegistry,
    MCPTransactionProxy,
    SQLiteSessionStore,
    StdioMCPUpstream,
    ToolPolicySpec,
    generate_starter_policy,
)


def _resolve_npx_command(sandbox_dir: str) -> List[str]:
    npx_bin = shutil.which("npx.cmd") or shutil.which("npx")
    if not npx_bin:
        raise RuntimeError(
            "Node.js `npx` not found on PATH. Install Node.js 18+ to run this field test."
        )
    return [npx_bin, "-y", "@modelcontextprotocol/server-filesystem", sandbox_dir]


def _pick_tool(available: Dict[str, Any], *candidates: str) -> str:
    for name in candidates:
        if name in available:
            return name
    raise RuntimeError(
        f"None of expected filesystem MCP tools {candidates} found in catalog: {sorted(available)}"
    )


def _call(
    proxy: MCPTransactionProxy,
    tool_name: str,
    arguments: Dict[str, Any],
    *,
    session_id: str,
    user_prompt: str | None = None,
) -> tuple[Dict[str, Any], float]:
    params: Dict[str, Any] = {
        "name": tool_name,
        "arguments": arguments,
        "_meta": {"session_id": session_id},
    }
    if user_prompt:
        params["_meta"]["user_prompt"] = user_prompt
    t0 = time.perf_counter()
    resp = proxy.handle_tools_call(params)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return resp, elapsed_ms


def run_field_test() -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="gatekeep_fs_field_") as tmp:
        sandbox = Path(tmp) / "workspace"
        sandbox.mkdir(parents=True, exist_ok=True)
        (sandbox / "notes.txt").write_text(
            "Q4 engineering roadmap: zero-trust MCP proxy rollout.\n", encoding="utf-8"
        )
        (sandbox / "report.md").write_text("# Status Report\nStatus: DRAFT\n", encoding="utf-8")
        (sandbox / ".env.production").write_text(
            "DATABASE_URL=postgres://admin:prod_secret@db.internal:5432/app\n",
            encoding="utf-8",
        )
        ssh_dir = sandbox / ".ssh"
        ssh_dir.mkdir(exist_ok=True)
        (ssh_dir / "id_rsa").write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nDUMMY_TEST_KEY\n-----END OPENSSH PRIVATE KEY-----\n",
            encoding="utf-8",
        )

        db_path = str(Path(tmp) / "field_test.db")
        cmd = _resolve_npx_command(str(sandbox))
        print(f"[1/4] Launching real third-party MCP server: {' '.join(cmd)}")

        t_boot = time.perf_counter()
        upstream = StdioMCPUpstream(cmd)
        store = SQLiteSessionStore(db_path)

        try:
            # Phase 1: Discover real catalog & auto-generate starter policies
            raw_catalog = upstream.list_tools()
            boot_ms = (time.perf_counter() - t_boot) * 1000.0
            tool_map = {str(t["name"]): t for t in raw_catalog if isinstance(t, dict) and "name" in t}
            starter = generate_starter_policy(raw_catalog)
            print(
                f"      Connected in {boot_ms:.0f}ms | Discovered {len(tool_map)} real tools: "
                f"{', '.join(sorted(tool_map))}"
            )
            print(
                f"      generate_starter_policy() auto-classified {len(starter.get('tools', {}))} tools."
            )

            read_tool = _pick_tool(tool_map, "read_text_file", "read_file")
            list_tool = _pick_tool(tool_map, "list_directory")
            write_tool = _pick_tool(tool_map, "write_file")
            edit_tool = _pick_tool(tool_map, "edit_file")

            # Phase 2: Shadow-mode dry run on legitimate workflows
            print("[2/4] Running shadow-mode baseline (zero blocking, measuring friction & latency)...")
            shadow_proxy = MCPTransactionProxy(
                upstream,
                session_store=store,
                shadow_mode=True,
                strict_provenance=True,
            )
            shadow_sid = "field-shadow-1"
            shadow_calls = [
                (list_tool, {"path": str(sandbox)}),
                (read_tool, {"path": str(sandbox / "notes.txt")}),
                (
                    write_tool,
                    {
                        "path": str(sandbox / "shadow_draft.txt"),
                        "content": "Generated during shadow mode baseline.\n",
                    },
                ),
                (
                    edit_tool,
                    {
                        "path": str(sandbox / "report.md"),
                        "edits": [{"oldText": "Status: DRAFT", "newText": "Status: REVIEWED"}],
                    },
                ),
            ]
            shadow_flags: List[Dict[str, Any]] = []
            shadow_latencies: List[float] = []
            for tname, targs in shadow_calls:
                resp, ms = _call(
                    shadow_proxy,
                    tname,
                    targs,
                    session_id=shadow_sid,
                    user_prompt=f"Work with files in {sandbox}",
                )
                shadow_latencies.append(ms)
                if resp.get("isError"):
                    raise RuntimeError(
                        f"Shadow mode unexpectedly returned upstream error on {tname}: {resp}"
                    )
                if "_shadow" in resp:
                    shadow_flags.append({"tool": tname, **resp["_shadow"]})
            print(
                f"      Shadow run completed {len(shadow_calls)} real operations | "
                f"median e2e latency={statistics.median(shadow_latencies):.1f}ms | "
                f"would-block flags={len(shadow_flags)}"
            )
            for flag in shadow_flags:
                print(f"        [shadow flag] {flag['tool']}: {flag['rule_triggered']} -> {flag['reason']}")

            # Phase 3: Enforcing mode (benign allowed, attacks blocked before Node.js server)
            print("[3/4] Running ENFORCING mode (benign ops + live attack attempts)...")
            policy_registry = CentralPolicyRegistry(session_store=store)
            policy_registry.set_policy(ToolPolicySpec(tool_name=list_tool, mode="read"))
            policy_registry.set_policy(ToolPolicySpec(tool_name=read_tool, mode="read"))
            policy_registry.set_policy(ToolPolicySpec(tool_name=write_tool, mode="write"))
            policy_registry.set_policy(ToolPolicySpec(tool_name=edit_tool, mode="write"))

            enforcing_proxy = MCPTransactionProxy(
                upstream,
                session_store=store,
                policy_registry=policy_registry,
                shadow_mode=False,
                strict_provenance=True,
                block_outbound_secrets=True,
                block_ssrf_and_sensitive_paths=True,
            )
            enf_sid = "field-enforcing-1"
            benign_results: List[Dict[str, Any]] = []
            for label, tname, targs in [
                ("list_workspace", list_tool, {"path": str(sandbox)}),
                ("read_notes", read_tool, {"path": str(sandbox / "notes.txt")}),
                (
                    "write_clean_output",
                    write_tool,
                    {
                        "path": str(sandbox / "approved_summary.txt"),
                        "content": "Quarterly engineering update approved by team.\n",
                    },
                ),
            ]:
                resp, ms = _call(
                    enforcing_proxy,
                    tname,
                    targs,
                    session_id=enf_sid,
                    user_prompt=f"Read {sandbox / 'notes.txt'} and write {sandbox / 'approved_summary.txt'}",
                )
                benign_results.append(
                    {
                        "label": label,
                        "tool": tname,
                        "allowed": not bool(resp.get("isError")),
                        "latency_ms": round(ms, 2),
                        "response": resp,
                    }
                )

            assert (sandbox / "approved_summary.txt").exists(), (
                "Legitimate write_file did not materialize on disk!"
            )

            attack_results: List[Dict[str, Any]] = []
            for label, tname, targs in [
                ("path_traversal", read_tool, {"path": str(sandbox / ".." / ".." / "etc" / "passwd")}),
                ("read_dotenv_prod", read_tool, {"path": str(sandbox / ".env.production")}),
                ("read_ssh_private_key", read_tool, {"path": str(ssh_dir / "id_rsa")}),
                (
                    "outbound_dlp_aws_key",
                    write_tool,
                    {
                        "path": str(sandbox / "leaked_creds.txt"),
                        "content": "Exported key: AKIAIOSFODNN7EXAMPLE\n",
                    },
                ),
            ]:
                resp, ms = _call(enforcing_proxy, tname, targs, session_id=enf_sid)
                sc = resp.get("structuredContent") or {}
                attack_results.append(
                    {
                        "label": label,
                        "tool": tname,
                        "blocked": bool(resp.get("isError")),
                        "rule_triggered": sc.get("rule_triggered"),
                        "latency_ms": round(ms, 2),
                    }
                )

            assert not (sandbox / "leaked_creds.txt").exists(), (
                "DLP-blocked file was unexpectedly written to disk!"
            )

            # Phase 4: Audit chain verification & Gatekeep-only latency extraction
            print("[4/4] Verifying SHA-256 audit chain & extracting Gatekeep evaluation latency...")
            gate = enforcing_proxy._load_gate(enf_sid)
            chain_valid = gate.verify_audit_chain()
            gate_latencies_ms = [round(r.latency_ms, 3) for r in gate.receipts]

            benign_passed = sum(1 for r in benign_results if r["allowed"])
            attacks_blocked = sum(1 for r in attack_results if r["blocked"])

            summary = {
                "upstream_server": "@modelcontextprotocol/server-filesystem (real npx stdio)",
                "boot_ms": round(boot_ms, 1),
                "discovered_tools": sorted(tool_map.keys()),
                "shadow_mode": {
                    "calls": len(shadow_calls),
                    "would_block_flags": shadow_flags,
                    "median_e2e_ms": round(statistics.median(shadow_latencies), 2),
                },
                "enforcing_mode": {
                    "benign_allowed": f"{benign_passed}/{len(benign_results)}",
                    "attacks_blocked": f"{attacks_blocked}/{len(attack_results)}",
                    "benign_details": [
                        {k: v for k, v in item.items() if k != "response"} for item in benign_results
                    ],
                    "attack_details": attack_results,
                },
                "audit_chain_valid": chain_valid,
                "receipt_count": len(gate.receipts),
                "gatekeep_eval_latency_ms": {
                    "median": round(statistics.median(gate_latencies_ms), 3) if gate_latencies_ms else 0.0,
                    "max": round(max(gate_latencies_ms), 3) if gate_latencies_ms else 0.0,
                },
            }
            print("\n=== Real Third-Party MCP Field Test Summary ===")
            print(json.dumps(summary, indent=2))
            if (
                benign_passed != len(benign_results)
                or attacks_blocked != len(attack_results)
                or not chain_valid
            ):
                raise SystemExit(1)
            return summary
        finally:
            upstream.close()
            store.close()


if __name__ == "__main__":
    run_field_test()
