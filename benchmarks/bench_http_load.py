#!/usr/bin/env python3
"""
benchmarks/bench_http_load.py

Real Live HTTP Throughput, Latency & Memory Benchmark for Gatekeep (`MCPHttpGateway`).

Boots an actual `uvicorn` ASGI server bound to `127.0.0.1:<port>` and drives concurrent
`httpx.AsyncClient` traffic across mixed workloads:
  - Legitimate `POST /mcp` read & write tool calls
  - Adversarial `POST /mcp` attacks (outbound DLP secrets, SSRF IMDS, destructive SQL, path traversal)
  - High-frequency `GET /healthz` and `GET /metrics` control-plane probes

Measures sustained RPS, p50/p95/p99/max end-to-end HTTP latency, peak traced Python heap,
process RSS, and 100% security block accuracy.

Usage:
  python benchmarks/bench_http_load.py --store memory --requests 600 --concurrency 30
  python benchmarks/bench_http_load.py --store sqlite --requests 500 --concurrency 25
  python benchmarks/bench_http_load.py --store postgres --pg-dsn postgresql://...
  python benchmarks/bench_http_load.py --store redis --redis-url redis://localhost:6379/0
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from gatekeep import (
    AsyncCallableMCPUpstream,
    CentralPolicyRegistry,
    InMemorySessionStore,
    MCPHttpGateway,
    MCPTransactionProxy,
    PostgresSessionStore,
    RedisSessionStore,
    SQLiteSessionStore,
    ToolPolicySpec,
)


def _get_process_rss_mb() -> float:
    """Return current process RSS in MiB using stdlib only (Windows + POSIX)."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        k32 = ctypes.windll.kernel32
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.K32GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        k32.K32GetProcessMemoryInfo.restype = wintypes.BOOL
        handle = k32.GetCurrentProcess()
        if k32.K32GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return counters.WorkingSetSize / (1024 * 1024)
        return 0.0
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return (usage / (1024 * 1024)) if sys.platform == "darwin" else (usage / 1024.0)
    except Exception:
        return 0.0


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(round((pct / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


def _build_benchmark_gateway(
    store_kind: str,
    *,
    pg_dsn: Optional[str] = None,
    redis_url: Optional[str] = None,
) -> Tuple[MCPHttpGateway, Any, Optional[tempfile.TemporaryDirectory]]:
    tmp_dir: Optional[tempfile.TemporaryDirectory] = None
    if store_kind == "memory":
        store: Any = InMemorySessionStore()
    elif store_kind == "sqlite":
        tmp_dir = tempfile.TemporaryDirectory(prefix="gatekeep_bench_")
        store = SQLiteSessionStore(str(Path(tmp_dir.name) / "bench.db"))
    elif store_kind == "postgres":
        if not pg_dsn:
            raise ValueError("--pg-dsn is required when --store postgres")
        store = PostgresSessionStore(dsn=pg_dsn, pool_min_size=4, pool_max_size=24)
    elif store_kind == "redis":
        if not redis_url:
            raise ValueError("--redis-url is required when --store redis")
        store = RedisSessionStore(redis_url=redis_url)
    else:
        raise ValueError(f"Unsupported --store '{store_kind}'")

    tools = [
        {
            "name": "read_customer",
            "description": "Read customer profile by ID.",
            "inputSchema": {
                "type": "object",
                "properties": {"customer_id": {"type": "string"}},
                "required": ["customer_id"],
            },
        },
        {
            "name": "create_ticket",
            "description": "Create a customer support ticket.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "customer_id": {"type": "string"},
                    "note": {"type": "string"},
                    "webhook_url": {"type": "string"},
                    "file_path": {"type": "string"},
                    "sql": {"type": "string"},
                },
                "required": ["customer_id"],
            },
        },
    ]

    async def _executor(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name == "read_customer":
            return {
                "customer_id": args.get("customer_id", "CUST-1"),
                "tier": "enterprise",
                "status": "active",
            }
        return {
            "ticket_id": f"TKT-{args.get('customer_id', '0')}",
            "created": True,
        }

    policy_registry = CentralPolicyRegistry(session_store=store)
    policy_registry.set_policy(
        ToolPolicySpec(tool_name="read_customer", mode="read", provides=("customer_id",))
    )
    policy_registry.set_policy(
        ToolPolicySpec(
            tool_name="create_ticket",
            mode="write",
            requires=("customer_id",),
        )
    )

    upstream = AsyncCallableMCPUpstream(tools=tools, executor=_executor)
    proxy = MCPTransactionProxy(
        upstream,
        session_store=store,
        policy_registry=policy_registry,
        strict_provenance=True,
    )
    gateway = MCPHttpGateway(
        proxy,
        api_keys={"bench-secret-key": "acme"},
        sse_pubsub_client=False,
    )
    return gateway, store, tmp_dir


def _build_workload(total_requests: int, num_sessions: int) -> List[Dict[str, Any]]:
    attacks = [
        (
            "dlp_aws_key",
            {
                "customer_id": "CUST-000",
                "note": "Leaking AKIAIOSFODNN7EXAMPLE in outbound note",
            },
        ),
        (
            "ssrf_imds",
            {
                "customer_id": "CUST-000",
                "webhook_url": "http://169.254.169.254/latest/meta-data/",
            },
        ),
        (
            "destructive_sql",
            {
                "customer_id": "CUST-000",
                "sql": "DROP TABLE production_customers;",
            },
        ),
        (
            "path_traversal",
            {
                "customer_id": "CUST-000",
                "file_path": "../../../etc/passwd",
            },
        ),
    ]

    plan: List[Dict[str, Any]] = []
    for i in range(total_requests):
        sid = f"bench-sess-{i % num_sessions}"
        cid = f"CUST-{i % num_sessions:03d}"
        slot = i % 20
        if slot == 0:
            plan.append({"kind": "healthz"})
        elif slot == 1:
            plan.append({"kind": "metrics"})
        elif slot in (2, 3, 4, 5, 6):
            attack_label, attack_args = attacks[i % len(attacks)]
            args = dict(attack_args)
            args["customer_id"] = cid
            plan.append(
                {
                    "kind": "attack",
                    "attack_label": attack_label,
                    "session_id": sid,
                    "tool": "create_ticket",
                    "arguments": args,
                    "req_id": i + 1,
                }
            )
        elif slot in (7, 8, 9, 10):
            plan.append(
                {
                    "kind": "write_ok",
                    "session_id": sid,
                    "tool": "create_ticket",
                    "arguments": {"customer_id": cid, "note": f"Routine follow-up #{i}"},
                    "req_id": i + 1,
                }
            )
        else:
            plan.append(
                {
                    "kind": "read_ok",
                    "session_id": sid,
                    "tool": "read_customer",
                    "arguments": {"customer_id": cid},
                    "req_id": i + 1,
                }
            )
    return plan


async def _run_benchmark(
    *,
    store_kind: str,
    total_requests: int,
    concurrency: int,
    num_sessions: int,
    pg_dsn: Optional[str] = None,
    redis_url: Optional[str] = None,
    enable_tracemalloc: bool = False,
) -> Dict[str, Any]:
    import httpx
    import uvicorn

    gateway, store, tmp_dir = _build_benchmark_gateway(
        store_kind, pg_dsn=pg_dsn, redis_url=redis_url
    )
    port = _pick_free_port()
    config = uvicorn.Config(
        gateway,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)
    srv_thread = threading.Thread(target=server.run, name="gatekeep-bench-uvicorn", daemon=True)
    srv_thread.start()

    base_url = f"http://127.0.0.1:{port}"
    headers = {"X-API-Key": "bench-secret-key", "Content-Type": "application/json"}

    try:
        # Wait for live uvicorn socket readiness
        async with httpx.AsyncClient(
            base_url=base_url,
            timeout=15.0,
            limits=httpx.Limits(
                max_connections=max(64, concurrency * 2),
                max_keepalive_connections=max(32, concurrency),
            ),
        ) as client:
            ready = False
            for _ in range(100):
                try:
                    r = await client.get("/healthz")
                    if r.status_code == 200:
                        ready = True
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.05)
            if not ready:
                raise RuntimeError(f"uvicorn server on {base_url} failed to become ready.")

            # Warm up / prime every session with an initial `read_customer` so legitimate
            # writes satisfy Observe-Before-Write & provenance checks cleanly.
            await asyncio.gather(
                *[
                    client.post(
                        "/mcp",
                        headers={**headers, "Mcp-Session-Id": f"bench-sess-{s}"},
                        json={
                            "jsonrpc": "2.0",
                            "id": f"warm-{s}",
                            "method": "tools/call",
                            "params": {
                                "name": "read_customer",
                                "arguments": {"customer_id": f"CUST-{s:03d}"},
                            },
                        },
                    )
                    for s in range(num_sessions)
                ]
            )

            workload = _build_workload(total_requests, num_sessions)
            sem = asyncio.Semaphore(concurrency)

            latencies_all: List[float] = []
            latencies_by_kind: Dict[str, List[float]] = {
                "read_ok": [],
                "write_ok": [],
                "attack": [],
                "healthz": [],
                "metrics": [],
            }
            counters = {
                "http_errors": 0,
                "unexpected_allows": 0,
                "unexpected_blocks": 0,
                "attacks_total": 0,
                "attacks_blocked": 0,
                "benign_total": 0,
                "benign_allowed": 0,
            }

            async def _execute_one(item: Dict[str, Any]) -> None:
                kind = item["kind"]
                async with sem:
                    t0 = time.perf_counter()
                    if kind == "healthz":
                        resp = await client.get("/healthz")
                        dt_ms = (time.perf_counter() - t0) * 1000.0
                        latencies_all.append(dt_ms)
                        latencies_by_kind[kind].append(dt_ms)
                        if resp.status_code != 200:
                            counters["http_errors"] += 1
                        return

                    if kind == "metrics":
                        resp = await client.get("/metrics")
                        dt_ms = (time.perf_counter() - t0) * 1000.0
                        latencies_all.append(dt_ms)
                        latencies_by_kind[kind].append(dt_ms)
                        if resp.status_code != 200:
                            counters["http_errors"] += 1
                        return

                    resp = await client.post(
                        "/mcp",
                        headers={**headers, "Mcp-Session-Id": item["session_id"]},
                        json={
                            "jsonrpc": "2.0",
                            "id": item["req_id"],
                            "method": "tools/call",
                            "params": {
                                "name": item["tool"],
                                "arguments": item["arguments"],
                            },
                        },
                    )
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    latencies_all.append(dt_ms)
                    latencies_by_kind[kind].append(dt_ms)
                    if resp.status_code != 200:
                        counters["http_errors"] += 1
                        return

                    body = resp.json()
                    result = body.get("result") or {}
                    is_err = bool(result.get("isError"))
                    if kind == "attack":
                        counters["attacks_total"] += 1
                        if is_err:
                            counters["attacks_blocked"] += 1
                        else:
                            counters["unexpected_allows"] += 1
                    else:
                        counters["benign_total"] += 1
                        if not is_err:
                            counters["benign_allowed"] += 1
                        else:
                            counters["unexpected_blocks"] += 1

            rss_before_mb = _get_process_rss_mb()
            if enable_tracemalloc:
                tracemalloc.start()
            wall_t0 = time.perf_counter()
            await asyncio.gather(*[_execute_one(item) for item in workload])
            wall_s = time.perf_counter() - wall_t0
            if enable_tracemalloc:
                cur_heap, peak_heap = tracemalloc.get_traced_memory()
                tracemalloc.stop()
            else:
                cur_heap, peak_heap = 0, 0
            rss_after_mb = _get_process_rss_mb()

        lat_sorted = sorted(latencies_all)
        per_kind_summary = {}
        for k, vals in latencies_by_kind.items():
            svals = sorted(vals)
            per_kind_summary[k] = {
                "count": len(svals),
                "p50_ms": round(_percentile(svals, 50), 2),
                "p95_ms": round(_percentile(svals, 95), 2),
                "p99_ms": round(_percentile(svals, 99), 2),
            }

        return {
            "store": store_kind,
            "total_requests": total_requests,
            "concurrency": concurrency,
            "sessions": num_sessions,
            "wall_time_s": round(wall_s, 3),
            "throughput_rps": round(total_requests / max(wall_s, 1e-6), 1),
            "latency_ms": {
                "mean": round(statistics.mean(lat_sorted), 2) if lat_sorted else 0.0,
                "p50": round(_percentile(lat_sorted, 50), 2),
                "p95": round(_percentile(lat_sorted, 95), 2),
                "p99": round(_percentile(lat_sorted, 99), 2),
                "max": round(lat_sorted[-1], 2) if lat_sorted else 0.0,
            },
            "per_workload": per_kind_summary,
            "security_and_correctness": counters,
            "memory": {
                "peak_traced_heap_mb": round(peak_heap / (1024 * 1024), 2),
                "end_traced_heap_mb": round(cur_heap / (1024 * 1024), 2),
                "rss_before_mb": round(rss_before_mb, 2),
                "rss_after_mb": round(rss_after_mb, 2),
            },
        }
    finally:
        server.should_exit = True
        srv_thread.join(timeout=5.0)
        gateway.close()
        if hasattr(store, "close"):
            store.close()
        if tmp_dir is not None:
            tmp_dir.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="Gatekeep live uvicorn HTTP load benchmark")
    parser.add_argument(
        "--store",
        choices=("memory", "sqlite", "postgres", "redis"),
        default="sqlite",
        help="Session persistence backend to benchmark.",
    )
    parser.add_argument("--requests", type=int, default=500, help="Total HTTP requests to issue.")
    parser.add_argument("--concurrency", type=int, default=25, help="Concurrent in-flight HTTP clients.")
    parser.add_argument("--sessions", type=int, default=25, help="Distinct concurrent agent sessions.")
    parser.add_argument("--pg-dsn", default=None, help="PostgreSQL DSN (when --store postgres).")
    parser.add_argument("--redis-url", default=None, help="Redis URL (when --store redis).")
    parser.add_argument(
        "--tracemalloc",
        action="store_true",
        help="Enable Python tracemalloc heap profiling (adds interpreter overhead; omit for peak RPS).",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only.")
    args = parser.parse_args()

    result = asyncio.run(
        _run_benchmark(
            store_kind=args.store,
            total_requests=args.requests,
            concurrency=args.concurrency,
            num_sessions=args.sessions,
            pg_dsn=args.pg_dsn,
            redis_url=args.redis_url,
            enable_tracemalloc=args.tracemalloc,
        )
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        lat = result["latency_ms"]
        sec = result["security_and_correctness"]
        mem = result["memory"]
        print(
            f"\n=== Gatekeep Live HTTP Benchmark (uvicorn ASGI, store={result['store']}) ===\n"
            f"Requests:    {result['total_requests']} total | concurrency={result['concurrency']} | sessions={result['sessions']}\n"
            f"Wall Time:   {result['wall_time_s']}s\n"
            f"Throughput:  {result['throughput_rps']} req/s\n"
            f"Latency:     p50={lat['p50']}ms | p95={lat['p95']}ms | p99={lat['p99']}ms | max={lat['max']}ms | mean={lat['mean']}ms\n"
            f"Correctness: http_errors={sec['http_errors']} | benign={sec['benign_allowed']}/{sec['benign_total']} allowed | "
            f"attacks={sec['attacks_blocked']}/{sec['attacks_total']} blocked\n"
            f"Memory:      peak_traced_heap={mem['peak_traced_heap_mb']} MiB | RSS {mem['rss_before_mb']} -> {mem['rss_after_mb']} MiB\n"
            f"Breakdown:"
        )
        for kind, stats in result["per_workload"].items():
            print(
                f"  - {kind:10s}: n={stats['count']:3d} | p50={stats['p50_ms']}ms | p95={stats['p95_ms']}ms | p99={stats['p99_ms']}ms"
            )

    sec = result["security_and_correctness"]
    ok = (
        sec["http_errors"] == 0
        and sec["unexpected_allows"] == 0
        and sec["unexpected_blocks"] == 0
        and sec["attacks_blocked"] == sec["attacks_total"]
        and sec["benign_allowed"] == sec["benign_total"]
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
