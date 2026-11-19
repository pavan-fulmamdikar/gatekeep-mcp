"""
tests/test_runtime_scaling.py

Verifies Gatekeep's high-QPS HTTP runtime & multi-replica scaling fixes:
  1. O(1) `count_sessions()` across all stores + `/healthz` and `/metrics` never scanning `list_sessions()`
  2. Automatic `psycopg_pool.ConnectionPool` initialization in `PostgresSessionStore`
  3. Non-blocking async session locking (`async_session_lock`) & thread-offloaded store I/O in `ahandle_tools_call`
  4. Pooled `httpx.AsyncClient` reuse in `HttpMCPUpstream.acall_tool`
  5. Cross-replica Redis Pub/Sub SSE fan-out with origin self-echo suppression
"""

from __future__ import annotations

import asyncio
import json
import queue
import sys
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from gatekeep import (
    AsyncCallableMCPUpstream,
    CallableMCPUpstream,
    HttpMCPUpstream,
    InMemorySessionStore,
    MCPHttpGateway,
    MCPTransactionProxy,
    PostgresSessionStore,
    RedisSessionStore,
    SQLiteSessionStore,
)


# ── Fake Redis with real Pub/Sub + SCARD support ───────────────────────────────


class _FakePubSub:
    def __init__(self, broker: "_FakeRedisBroker") -> None:
        self._broker = broker
        self._channels: set[str] = set()
        self._q: queue.Queue = queue.Queue()
        self._closed = False

    def subscribe(self, channel: str) -> None:
        self._channels.add(channel)
        self._broker._register_pubsub(channel, self)

    def get_message(
        self, ignore_subscribe_messages: bool = False, timeout: float = 0.0
    ) -> Optional[Dict[str, Any]]:
        if self._closed:
            return None
        try:
            return self._q.get(timeout=timeout if timeout and timeout > 0 else 0.01)
        except queue.Empty:
            return None

    def close(self) -> None:
        self._closed = True
        for ch in list(self._channels):
            self._broker._unregister_pubsub(ch, self)
        self._channels.clear()


class _FakeRedisBroker:
    """Thread-safe FakeRedis supporting KV, Sets (SADD/SREM/SCARD), NX locks, and Pub/Sub."""

    def __init__(self, forbid_scan: bool = False) -> None:
        self._lock = threading.RLock()
        self._kv: Dict[str, Any] = {}
        self._sets: Dict[str, set[str]] = {}
        self._subs: Dict[str, List[_FakePubSub]] = {}
        self.forbid_scan = forbid_scan
        self.scard_calls = 0

    def get(self, key: str) -> Any:
        with self._lock:
            return self._kv.get(key)

    def set(
        self,
        key: str,
        value: Any,
        *,
        nx: bool = False,
        px: Optional[int] = None,
        ex: Optional[int] = None,
    ) -> bool:
        with self._lock:
            if nx and key in self._kv:
                return False
            self._kv[key] = value
            return True

    def delete(self, key: str) -> int:
        with self._lock:
            return 1 if self._kv.pop(key, None) is not None else 0

    def sadd(self, key: str, member: str) -> int:
        with self._lock:
            s = self._sets.setdefault(key, set())
            before = len(s)
            s.add(str(member))
            return len(s) - before

    def srem(self, key: str, member: str) -> int:
        with self._lock:
            s = self._sets.get(key)
            if not s or str(member) not in s:
                return 0
            s.remove(str(member))
            return 1

    def scard(self, key: str) -> int:
        with self._lock:
            self.scard_calls += 1
            return len(self._sets.get(key, set()))

    def scan_iter(self, match: Optional[str] = None):
        if self.forbid_scan:
            raise AssertionError("scan_iter() must not be called by count_sessions()!")
        prefix = (match or "").rstrip("*")
        with self._lock:
            return [k for k in self._kv.keys() if k.startswith(prefix)]

    def pubsub(self, ignore_subscribe_messages: bool = False) -> _FakePubSub:
        return _FakePubSub(self)

    def _register_pubsub(self, channel: str, sub: _FakePubSub) -> None:
        with self._lock:
            self._subs.setdefault(channel, []).append(sub)

    def _unregister_pubsub(self, channel: str, sub: _FakePubSub) -> None:
        with self._lock:
            lst = self._subs.get(channel)
            if lst and sub in lst:
                lst.remove(sub)

    def publish(self, channel: str, message: str) -> int:
        with self._lock:
            subs = list(self._subs.get(channel, []))
        for sub in subs:
            if not sub._closed:
                sub._q.put({"type": "message", "channel": channel, "data": message})
        return len(subs)


# ── Fake Postgres DB-API + Fake psycopg_pool ───────────────────────────────────


class _FakePgCursor:
    def __init__(self, state: Dict[str, Any]) -> None:
        self._state = state
        self._rows: List[Tuple[Any, ...]] = []

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        norm = " ".join(sql.strip().split()).upper()
        self._state["queries"].append(norm)
        if norm.startswith("CREATE ") or norm.startswith("BEGIN") or norm.startswith("COMMIT"):
            self._rows = []
            return
        if "SELECT COUNT(*)" in norm:
            self._rows = [(len(self._state["sessions"]),)]
            return
        if "SELECT PG_TRY_ADVISORY_LOCK" in norm:
            key = params[0]
            if key in self._state["advisory_locks"]:
                self._rows = [(False,)]
            else:
                self._state["advisory_locks"].add(key)
                self._rows = [(True,)]
            return
        if "SELECT PG_ADVISORY_UNLOCK" in norm:
            self._state["advisory_locks"].discard(params[0])
            self._rows = [(True,)]
            return
        if norm.startswith("SELECT VERSION FROM"):
            rec = self._state["sessions"].get(params[0])
            self._rows = [(rec["version"],)] if rec else []
            return
        if norm.startswith("INSERT INTO") and "ON CONFLICT" in norm and "VERSION" in norm:
            sid, ver, payload, upd = params
            self._state["sessions"][sid] = {
                "payload": payload,
                "version": int(ver),
                "updated_at": float(upd),
            }
            self._rows = []
            return
        if norm.startswith("SELECT PAYLOAD FROM"):
            rec = self._state["sessions"].get(params[0])
            self._rows = [(rec["payload"],)] if rec else []
            return
        if norm.startswith("SELECT SESSION_ID FROM"):
            self._rows = [(k,) for k in sorted(self._state["sessions"].keys())]
            return
        self._rows = []

    def fetchone(self) -> Optional[Tuple[Any, ...]]:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> List[Tuple[Any, ...]]:
        return list(self._rows)

    def close(self) -> None:
        pass


class _FakePgConn:
    def __init__(self, state: Dict[str, Any]) -> None:
        self._state = state
        self.autocommit = False

    def cursor(self) -> _FakePgCursor:
        return _FakePgCursor(self._state)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


class _FakePgPool:
    def __init__(self, dsn: str, min_size: int = 2, max_size: int = 16, open: bool = True) -> None:
        self.dsn = dsn
        self.min_size = min_size
        self.max_size = max_size
        self.opened = open
        self.closed = False
        self.state: Dict[str, Any] = {"sessions": {}, "advisory_locks": set(), "queries": []}
        self.getconn_calls = 0
        self.putconn_calls = 0

    def getconn(self) -> _FakePgConn:
        self.getconn_calls += 1
        return _FakePgConn(self.state)

    def putconn(self, conn: _FakePgConn) -> None:
        self.putconn_calls += 1

    def close(self) -> None:
        self.closed = True


# ── Tests ──────────────────────────────────────────────────────────────────────


def test_count_sessions_is_o1_and_healthz_metrics_never_scan(tmp_path: Path):
    # 1. InMemory
    mem = InMemorySessionStore()
    assert mem.count_sessions() == 0
    mem.save("s1", {"ledger": {}, "gate": {}})
    mem.save("s2", {"ledger": {}, "gate": {}})
    assert mem.count_sessions() == 2
    mem.delete("s1")
    assert mem.count_sessions() == 1

    # 2. SQLite
    sq = SQLiteSessionStore(str(tmp_path / "count.db"))
    try:
        assert sq.count_sessions() == 0
        sq.save("a", {"ledger": {}, "gate": {}})
        sq.save("b", {"ledger": {}, "gate": {}})
        assert sq.count_sessions() == 2
        sq.delete("a")
        assert sq.count_sessions() == 1
    finally:
        sq.close()

    # 3. Redis uses SCARD without calling scan_iter
    broker = _FakeRedisBroker(forbid_scan=True)
    rstore = RedisSessionStore(client=broker, key_prefix="gk:test:")
    assert rstore.count_sessions() == 0
    rstore.save("r1", {"ledger": {}, "gate": {}})
    rstore.save("r2", {"ledger": {}, "gate": {}})
    assert rstore.count_sessions() == 2
    assert broker.scard_calls >= 2
    rstore.delete("r1")
    assert rstore.count_sessions() == 1
    broker.forbid_scan = False
    assert rstore.list_sessions() == ["r2"]

    # 4. /healthz and /metrics NEVER invoke list_sessions()
    def _forbid_list_sessions() -> List[str]:
        raise AssertionError("list_sessions() must NOT be called by /healthz or /metrics!")

    mem.list_sessions = _forbid_list_sessions  # type: ignore[method-assign]
    upstream = CallableMCPUpstream(
        tools=[{"name": "ping_tool", "description": "Read ping", "inputSchema": {"type": "object", "properties": {}}}],
        executor=lambda name, args: {"ok": True},
    )
    proxy = MCPTransactionProxy(upstream, session_store=mem)
    gateway = MCPHttpGateway(proxy, sse_pubsub_client=False)
    try:
        async def _check() -> None:
            hz = await gateway._route_http_request("GET", "/healthz", "", {}, b"")
            assert hz.status == 200
            assert json.loads(hz.body)["sessions"] == 1

            mt = await gateway._route_http_request("GET", "/metrics", "", {}, b"")
            assert mt.status == 200
            assert b"slim_gateway_active_sessions 1" in mt.body

        asyncio.run(_check())
    finally:
        gateway.close()


def test_postgres_auto_creates_connection_pool_and_o1_count(monkeypatch: pytest.MonkeyPatch):
    created_pools: List[_FakePgPool] = []

    class _RecordingPool(_FakePgPool):
        def __init__(self, dsn: str, min_size: int = 2, max_size: int = 16, open: bool = True) -> None:
            super().__init__(dsn, min_size=min_size, max_size=max_size, open=open)
            created_pools.append(self)

    fake_mod = types.ModuleType("psycopg_pool")
    fake_mod.ConnectionPool = _RecordingPool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "psycopg_pool", fake_mod)
    if sys.modules.get("psycopg") is None:
        monkeypatch.setitem(sys.modules, "psycopg", types.ModuleType("psycopg"))

    store = PostgresSessionStore(
        dsn="postgresql://user:pass@localhost:5432/gatekeep",
        pool_min_size=3,
        pool_max_size=12,
    )
    try:
        assert len(created_pools) == 1
        pool = created_pools[0]
        assert pool.min_size == 3
        assert pool.max_size == 12
        assert pool.opened is True
        assert store._pool is pool
        assert store._conn is None

        store.save("pg-s1", {"ledger": {}, "gate": {}})
        store.save("pg-s2", {"ledger": {}, "gate": {}})
        assert store.count_sessions() == 2
        assert any("SELECT COUNT(*)" in q for q in pool.state["queries"])

        async def _lock_test() -> None:
            async with store.async_session_lock("pg-s1"):
                assert len(pool.state["advisory_locks"]) == 1
            assert len(pool.state["advisory_locks"]) == 0

        asyncio.run(_lock_test())
        assert pool.getconn_calls >= 3
        assert pool.putconn_calls == pool.getconn_calls
    finally:
        store.close()
        assert created_pools[0].closed is True


def test_async_tools_call_non_blocking_across_sessions_and_serial_within_session(tmp_path: Path):
    """
    Proves two slow upstream calls on DIFFERENT sessions overlap concurrently
    on SQLite + Redis stores (no threading.RLock held across await!), while
    4 concurrent calls on the SAME session serialize cleanly without CAS errors.
    """
    for store_kind in ("sqlite", "redis"):
        if store_kind == "sqlite":
            store = SQLiteSessionStore(str(tmp_path / "async_nonblock.db"))
        else:
            store = RedisSessionStore(client=_FakeRedisBroker())

        async def _slow_exec(name: str, args: Dict[str, Any]) -> Any:
            await asyncio.sleep(0.22)
            return {"status": "ok", "echo": args.get("id", "x")}

        upstream = AsyncCallableMCPUpstream(
            tools=[
                {
                    "name": "read_item",
                    "description": "Read item slowly",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                    },
                }
            ],
            executor=_slow_exec,
        )
        proxy = MCPTransactionProxy(upstream, session_store=store)

        async def _run() -> Tuple[float, List[Dict[str, Any]]]:
            t0 = time.perf_counter()
            r_a, r_b = await asyncio.gather(
                proxy.ahandle_tools_call(
                    {"name": "read_item", "arguments": {"id": "A"}, "_meta": {"session_id": "sess-a"}}
                ),
                proxy.ahandle_tools_call(
                    {"name": "read_item", "arguments": {"id": "B"}, "_meta": {"session_id": "sess-b"}}
                ),
            )
            elapsed_parallel = time.perf_counter() - t0
            assert not r_a.get("isError")
            assert not r_b.get("isError")

            # Same-session serialization (must not fail with ConcurrencyConflictError)
            same_results = await asyncio.gather(
                *[
                    proxy.ahandle_tools_call(
                        {
                            "name": "read_item",
                            "arguments": {"id": f"S-{i}"},
                            "_meta": {"session_id": "sess-same"},
                        }
                    )
                    for i in range(4)
                ]
            )
            return elapsed_parallel, same_results

        try:
            elapsed, same_results = asyncio.run(_run())
            # 2 parallel 0.22s calls must overlap (< 0.40s rather than >= 0.44s serial)
            assert elapsed < 0.40, f"{store_kind}: cross-session async calls blocked event loop ({elapsed:.3f}s)"
            assert all(not r.get("isError") for r in same_results)
            snap = store.load("sess-same")
            assert snap is not None and snap["version"] >= 4
        finally:
            if hasattr(store, "close"):
                store.close()


def test_http_mcp_upstream_uses_pooled_httpx_async_client():
    pytest.importorskip("httpx")
    hits = {"count": 0}

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            req_id = body.get("id")
            method = body.get("method")
            if method == "notifications/initialized":
                self.send_response(202)
                self.end_headers()
                return
            if method == "initialize":
                res: Dict[str, Any] = {"protocolVersion": "2025-03-26", "capabilities": {}}
            else:
                hits["count"] += 1
                res = {"content": [{"type": "text", "text": json.dumps({"n": hits["count"]})}]}
            payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "upstream-sess-1")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    upstream = HttpMCPUpstream(f"http://127.0.0.1:{port}/mcp")
    try:
        async def _run() -> None:
            results = await asyncio.gather(
                *[upstream.acall_tool("echo", {"i": i}) for i in range(8)]
            )
            assert len(results) == 8
            assert len(upstream._async_clients) == 1
            assert upstream._session_id == "upstream-sess-1"
            await upstream.aclose()
            assert len(upstream._async_clients) == 0

        asyncio.run(_run())
        assert hits["count"] == 8
    finally:
        srv.shutdown()
        srv.server_close()


def test_multi_replica_sse_pubsub_fanout_and_no_self_echo():
    broker = _FakeRedisBroker()
    store_a = RedisSessionStore(client=broker, key_prefix="gk:ha:")
    store_b = RedisSessionStore(client=broker, key_prefix="gk:ha:")

    upstream = CallableMCPUpstream(
        tools=[{"name": "read_status", "description": "Read", "inputSchema": {"type": "object", "properties": {}}}],
        executor=lambda name, args: {"status": "ok"},
    )
    proxy_a = MCPTransactionProxy(upstream, session_store=store_a)
    proxy_b = MCPTransactionProxy(upstream, session_store=store_b)

    # Auto-detects Redis Pub/Sub client from RedisSessionStore
    pod_a = MCPHttpGateway(proxy_a)
    pod_b = MCPHttpGateway(proxy_b)
    assert pod_a._sse_pubsub_client is broker
    assert pod_b._sse_pubsub_client is broker
    assert pod_a._instance_id != pod_b._instance_id

    try:
        q_pod_a: queue.Queue[str] = queue.Queue()
        q_pod_b: queue.Queue[str] = queue.Queue()
        pod_a._register_sse_queue(["default:sess-cross"], None, q_pod_a)
        pod_b._register_sse_queue(["default:sess-cross"], None, q_pod_b)

        # Event published on Pod B must arrive on Pod A via Pub/Sub and only ONCE on Pod B
        pod_b._publish_sse(
            ["default:sess-cross"],
            "message",
            {"jsonrpc": "2.0", "id": 42, "result": {"ok": True}},
        )

        msg_b = q_pod_b.get(timeout=1.0)
        msg_a = q_pod_a.get(timeout=1.5)
        assert '"id": 42' in msg_b
        assert '"id": 42' in msg_a

        # Confirm origin suppression: Pod B must NOT receive a duplicate copy of its own broadcast
        time.sleep(0.15)
        assert q_pod_b.empty(), "Pod B received duplicate self-echo from Redis Pub/Sub!"
        assert q_pod_a.empty(), "Pod A received duplicate event!"
    finally:
        pod_a.close()
        pod_b.close()
