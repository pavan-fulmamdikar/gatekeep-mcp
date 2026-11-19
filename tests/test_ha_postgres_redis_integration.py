"""
tests/test_ha_postgres_redis_integration.py

Real Non-Mocked Multi-Replica HA Soak & Crash Recovery Integration Suite
against live PostgreSQL 16 and live Redis 7 containers (`docker-compose.ha.yml`).

Automatically skips during offline/local unit runs unless:
  - GATEKEEP_LIVE_PG_DSN=postgresql://gatekeep:gatekeep_dev@localhost:5432/gatekeep
  - GATEKEEP_LIVE_REDIS_URL=redis://localhost:6379/0

Covers:
  1. Real PostgreSQL 16 `psycopg_pool.ConnectionPool` + `SELECT COUNT(*)` + `SELECT ... FOR UPDATE` CAS conflicts
  2. Real cross-pod `pg_try_advisory_lock` mutual exclusion (Pod A holds lock -> Pod B times out -> Pod A unlocks -> Pod B acquires)
  3. 20-way concurrent multi-replica atomic global spend cap ($500 cap, 20x $100 across Pod A & Pod B -> strictly 5 allowed, 15 blocked)
  4. Real Postgres `SagaRecoveryDaemon` crash recovery (Pod A starts WAL mutation & dies -> Pod B sweeps and executes LIFO compensation)
  5. Real Redis 7 multi-replica `SCARD`, `WATCH` CAS, 20-way concurrent global spend cap, and cross-pod Redis Pub/Sub SSE delivery
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import queue
import time
import uuid
from typing import Any, Dict, List

import pytest

from gatekeep import (
    AsyncCallableMCPUpstream,
    CentralPolicyRegistry,
    ConcurrencyConflictError,
    MCPHttpGateway,
    MCPTransactionProxy,
    PostgresSessionStore,
    RedisSessionStore,
    SagaRecoveryDaemon,
    ToolPolicySpec,
)

LIVE_PG_DSN = os.environ.get("GATEKEEP_LIVE_PG_DSN", "").strip()
LIVE_REDIS_URL = os.environ.get("GATEKEEP_LIVE_REDIS_URL", "").strip()


def _drop_pg_tables(store: PostgresSessionStore) -> None:
    try:
        with store._connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute(f"DROP TABLE IF EXISTS {store._table}")
                cur.execute(f"DROP TABLE IF EXISTS {store._cp_table}")
                cur.execute(f"DROP TABLE IF EXISTS {store._audit_table}")
                if not getattr(conn, "autocommit", False):
                    conn.commit()
            finally:
                cur.close()
    except Exception:
        pass


@pytest.mark.skipif(
    not LIVE_PG_DSN,
    reason="Set GATEKEEP_LIVE_PG_DSN (e.g. via docker compose -f docker-compose.ha.yml up -d) to run live PostgreSQL 16 HA tests.",
)
def test_live_postgres_auto_pool_cas_and_advisory_locks():
    table = f"gk_ha_test_{uuid.uuid4().hex[:10]}"
    pod_a = PostgresSessionStore(dsn=LIVE_PG_DSN, table_name=table, pool_min_size=2, pool_max_size=8)
    pod_b = PostgresSessionStore(dsn=LIVE_PG_DSN, table_name=table, pool_min_size=2, pool_max_size=8)
    try:
        # Auto-pool active if psycopg_pool installed
        assert pod_a.count_sessions() == 0
        v1 = pod_a.save("ha-sess-1", {"ledger": {"turn": 1}, "gate": {}}, expected_version=0)
        assert v1 == 1
        assert pod_b.count_sessions() == 1

        # Real Postgres row-level FOR UPDATE CAS conflict
        v2 = pod_a.save("ha-sess-1", {"ledger": {"turn": 2}, "gate": {}}, expected_version=1)
        assert v2 == 2
        with pytest.raises(ConcurrencyConflictError):
            pod_b.save("ha-sess-1", {"ledger": {"turn": 99}, "gate": {}}, expected_version=1)

        # Real Postgres cross-pod pg_try_advisory_lock mutual exclusion
        with pod_a.session_lock("ha-lock-target", timeout_s=2.0):
            with pytest.raises(TimeoutError):
                with pod_b.session_lock("ha-lock-target", timeout_s=0.35):
                    pass

        # Once Pod A releases, Pod B acquires immediately
        with pod_b.session_lock("ha-lock-target", timeout_s=2.0):
            pass
    finally:
        _drop_pg_tables(pod_a)
        pod_a.close()
        pod_b.close()


@pytest.mark.skipif(
    not LIVE_PG_DSN,
    reason="Set GATEKEEP_LIVE_PG_DSN to run live PostgreSQL 16 HA tests.",
)
def test_live_postgres_multi_replica_atomic_global_spend_cap():
    table = f"gk_ha_cap_{uuid.uuid4().hex[:10]}"
    store_a = PostgresSessionStore(dsn=LIVE_PG_DSN, table_name=table, pool_min_size=2, pool_max_size=12)
    store_b = PostgresSessionStore(dsn=LIVE_PG_DSN, table_name=table, pool_min_size=2, pool_max_size=12)
    try:
        tools = [
            {
                "name": "charge_vendor",
                "description": "Transfer funds to vendor.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"amount": {"type": "number"}},
                    "required": ["amount"],
                },
            }
        ]
        pol_a = CentralPolicyRegistry(session_store=store_a)
        pol_a.set_policy(
            ToolPolicySpec(
                tool_name="charge_vendor",
                mode="write",
                max_cumulative_amount=500.0,
                amount_arg="amount",
                global_scope=True,
            )
        )
        pol_b = CentralPolicyRegistry(session_store=store_b)

        up = AsyncCallableMCPUpstream(
            tools=tools, executor=lambda n, a: {"charged": a["amount"]}
        )
        proxy_a = MCPTransactionProxy(
            up, session_store=store_a, policy_registry=pol_a, strict_provenance=False
        )
        proxy_b = MCPTransactionProxy(
            up, session_store=store_b, policy_registry=pol_b, strict_provenance=False
        )

        async def _burst() -> List[Dict[str, Any]]:
            tasks = []
            for i in range(20):
                target = proxy_a if i % 2 == 0 else proxy_b
                tasks.append(
                    target.ahandle_tools_call(
                        {
                            "name": "charge_vendor",
                            "arguments": {"amount": 100},
                            "_meta": {"session_id": f"cap-sess-{i}"},
                        }
                    )
                )
            return list(await asyncio.gather(*tasks))

        results = asyncio.run(_burst())
        allowed = [r for r in results if not r.get("isError")]
        blocked = [r for r in results if r.get("isError")]
        assert len(allowed) == 5, f"Expected exactly 5 allowed ($500 cap), got {len(allowed)}"
        assert len(blocked) == 15, f"Expected exactly 15 blocked, got {len(blocked)}"
    finally:
        _drop_pg_tables(store_a)
        store_a.close()
        store_b.close()


@pytest.mark.skipif(
    not LIVE_PG_DSN,
    reason="Set GATEKEEP_LIVE_PG_DSN to run live PostgreSQL 16 HA tests.",
)
def test_live_postgres_saga_crash_recovery_sweep():
    table = f"gk_ha_saga_{uuid.uuid4().hex[:10]}"
    store_a = PostgresSessionStore(dsn=LIVE_PG_DSN, table_name=table, pool_min_size=2, pool_max_size=6)
    store_b = PostgresSessionStore(dsn=LIVE_PG_DSN, table_name=table, pool_min_size=2, pool_max_size=6)
    compensated: List[Dict[str, Any]] = []
    try:
        tools = [
            {
                "name": "reserve_slot",
                "description": "Reserve a compute slot.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"slot_id": {"type": "string"}},
                    "required": ["slot_id"],
                },
            },
            {
                "name": "release_slot",
                "description": "Release a reserved compute slot.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"slot_id": {"type": "string"}},
                    "required": ["slot_id"],
                },
            },
        ]

        def _exec(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
            if name == "release_slot":
                compensated.append(dict(args))
                return {"released": True, **args}
            return {"reserved": True, **args}

        pol_a = CentralPolicyRegistry(session_store=store_a)
        pol_a.set_policy(
            ToolPolicySpec(
                tool_name="reserve_slot",
                mode="write",
                compensates_with="release_slot",
                compensation_args={"slot_id": "$args.slot_id"},
            )
        )
        up = AsyncCallableMCPUpstream(tools=tools, executor=_exec)
        proxy_a = MCPTransactionProxy(
            up, session_store=store_a, policy_registry=pol_a, strict_provenance=False
        )

        # Pod A reserves a slot and crashes before committing the transaction
        resp = proxy_a.handle_tools_call(
            {
                "name": "reserve_slot",
                "arguments": {"slot_id": "SLOT-777"},
                "_meta": {"session_id": "crashed-pod-sess"},
            }
        )
        assert not resp.get("isError")

        # Pod B starts cleanly from Postgres and sweeps orphaned uncommitted Sagas
        pol_b = CentralPolicyRegistry(session_store=store_b)
        proxy_b = MCPTransactionProxy(
            up, session_store=store_b, policy_registry=pol_b, strict_provenance=False
        )
        daemon = SagaRecoveryDaemon(
            session_store=store_b,
            registry=proxy_b.registry,
            policy_registry=pol_b,
            stale_after_seconds=0.0,
        )
        report = daemon.sweep_once()
        assert report.recovered_sessions >= 1
        assert report.failed_sessions == 0
        assert any(c.get("slot_id") == "SLOT-777" for c in compensated)
    finally:
        _drop_pg_tables(store_a)
        store_a.close()
        store_b.close()


@pytest.mark.skipif(
    not LIVE_REDIS_URL,
    reason="Set GATEKEEP_LIVE_REDIS_URL (e.g. via docker compose -f docker-compose.ha.yml up -d) to run live Redis 7 HA tests.",
)
def test_live_redis_multi_replica_scard_atomic_cap_and_cross_pod_sse():
    prefix = f"gk:live_ha:{uuid.uuid4().hex[:10]}:"
    store_a = RedisSessionStore(redis_url=LIVE_REDIS_URL, key_prefix=prefix)
    store_b = RedisSessionStore(redis_url=LIVE_REDIS_URL, key_prefix=prefix)
    tools = [
        {
            "name": "charge_vendor",
            "description": "Transfer funds to vendor.",
            "inputSchema": {
                "type": "object",
                "properties": {"amount": {"type": "number"}},
                "required": ["amount"],
            },
        }
    ]
    pol_a = CentralPolicyRegistry(session_store=store_a)
    pol_a.set_policy(
        ToolPolicySpec(
            tool_name="charge_vendor",
            mode="write",
            max_cumulative_amount=500.0,
            amount_arg="amount",
            global_scope=True,
        )
    )
    pol_b = CentralPolicyRegistry(session_store=store_b)
    up = AsyncCallableMCPUpstream(
        tools=tools, executor=lambda n, a: {"charged": a["amount"]}
    )
    proxy_a = MCPTransactionProxy(
        up, session_store=store_a, policy_registry=pol_a, strict_provenance=False
    )
    proxy_b = MCPTransactionProxy(
        up, session_store=store_b, policy_registry=pol_b, strict_provenance=False
    )
    channel = f"gatekeep:sse:test:{uuid.uuid4().hex[:8]}"
    gw_a = MCPHttpGateway(proxy_a, sse_pubsub_channel=channel)
    gw_b = MCPHttpGateway(proxy_b, sse_pubsub_channel=channel)

    try:
        # 1. Cross-pod Redis 7 Pub/Sub SSE delivery + self-echo suppression
        time.sleep(0.15)  # allow subscribe handshake on live Redis
        q_a: queue.Queue[str] = queue.Queue()
        q_b: queue.Queue[str] = queue.Queue()
        gw_a._register_sse_queue(["default:live-sse-1"], None, q_a)
        gw_b._register_sse_queue(["default:live-sse-1"], None, q_b)

        gw_b._publish_sse(
            ["default:live-sse-1"],
            "message",
            {"jsonrpc": "2.0", "id": 9001, "result": {"from": "pod_b"}},
        )
        assert '"id": 9001' in q_b.get(timeout=1.0)
        assert '"id": 9001' in q_a.get(timeout=2.0)
        time.sleep(0.15)
        assert q_b.empty(), "Live Redis Pub/Sub echoed Pod B's message back to Pod B!"

        # 2. 20-way concurrent multi-replica atomic global spend cap on live Redis 7
        def _invoke(idx: int) -> Dict[str, Any]:
            target = proxy_a if idx % 2 == 0 else proxy_b
            return target.handle_tools_call(
                {
                    "name": "charge_vendor",
                    "arguments": {"amount": 100},
                    "_meta": {"session_id": f"redis-cap-{idx}"},
                }
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(_invoke, range(20)))
        allowed = [r for r in results if not r.get("isError")]
        blocked = [r for r in results if r.get("isError")]
        assert len(allowed) == 5, f"Expected 5 allowed ($500 cap), got {len(allowed)}"
        assert len(blocked) == 15, f"Expected 15 blocked, got {len(blocked)}"
        assert store_a.count_sessions() >= 5
    finally:
        gw_a.close()
        gw_b.close()
        try:
            for k in list(store_a._client.scan_iter(match=f"{prefix}*")):
                store_a._client.delete(k)
        except Exception:
            pass
