"""
gatekeep/persistence.py

Durable Session & Saga Persistence Backends for Gatekeep.
Replaces single-process volatile RAM state with pluggable stores supporting
ACID transactions, optimistic concurrency control (CAS versioning), distributed
session locking, and crash recovery of uncommitted Saga compensations:

  - `InMemorySessionStore`: Thread-safe isolated JSON snapshot store (testing/single-proc).
  - `SQLiteSessionStore`: Zero-dependency durable WAL-mode SQLite journal.
  - `RedisSessionStore`: Distributed multi-container store with TTL & optimistic WATCH CAS.
  - `PostgresSessionStore`: Multi-worker ACID PostgreSQL store with `FOR UPDATE` row CAS
    and `pg_advisory_lock` distributed session coordination.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Dict, Iterator, List, Optional, Tuple


class ConcurrencyConflictError(RuntimeError):
    """
    Raised when an optimistic Compare-And-Swap (`expected_version`) save
    detects that the session was modified concurrently by another worker.
    """


@dataclass
class SessionSnapshot:
    """Versioned durable snapshot of a Gatekeep session (Ledger + Saga + Gate audit chain)."""

    session_id: str
    ledger: Dict[str, Any]
    gate: Dict[str, Any]
    version: int = 1
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "ledger": dict(self.ledger),
            "gate": dict(self.gate),
            "version": self.version,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionSnapshot":
        return cls(
            session_id=str(data["session_id"]),
            ledger=dict(data.get("ledger") or {}),
            gate=dict(data.get("gate") or {}),
            version=int(data.get("version", 1)),
            updated_at=float(data.get("updated_at", time.time())),
        )


def _check_expected_version(
    session_id: str,
    current_version: Optional[int],
    expected_version: Optional[int],
) -> int:
    """Validate optimistic lock version and return next version number."""
    actual = current_version if current_version is not None else 0
    if expected_version is not None and actual != expected_version:
        raise ConcurrencyConflictError(
            f"Optimistic concurrency conflict for session '{session_id}': "
            f"expected version {expected_version}, found {actual}."
        )
    return actual + 1


def _encode_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str)


def _build_versioned_payload(
    session_id: str,
    snapshot: Dict[str, Any],
    current_version: Optional[int],
    expected_version: Optional[int],
) -> tuple[int, str]:
    """Validate version and encode a normalized versioned SessionSnapshot JSON payload."""
    next_version = _check_expected_version(session_id, current_version, expected_version)
    record = SessionSnapshot(
        session_id=session_id,
        ledger=dict(snapshot.get("ledger") or {}),
        gate=dict(snapshot.get("gate") or {}),
        version=next_version,
        updated_at=time.time(),
    )
    return next_version, _encode_json(record.to_dict())


class SessionStateStore(ABC):
    """
    Abstract persistence backend for Gatekeep session state (`ToolReturnLedger`,
    `SagaCoordinator`, and `PreExecutionGate` hash-chained `AuditReceipt`s).
    """

    @abstractmethod
    def save(
        self,
        session_id: str,
        snapshot: Dict[str, Any],
        expected_version: Optional[int] = None,
    ) -> int:
        """
        Persist `snapshot` (`{"ledger": ..., "gate": ...}`) for `session_id`.
        If `expected_version` is given, enforces optimistic CAS (0 means must not exist).
        Returns the newly committed integer `version`.
        """

    @abstractmethod
    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Load the latest persisted snapshot dict (with `version` & `updated_at`), or None."""

    @abstractmethod
    def delete(self, session_id: str) -> bool:
        """Remove persisted state for `session_id`. Returns True if removed."""

    @abstractmethod
    def list_sessions(self) -> List[str]:
        """Return all stored session IDs."""

    def count_sessions(self) -> int:
        """Return total stored session count without materializing IDs when supported."""
        return len(self.list_sessions())

    def exists(self, session_id: str) -> bool:
        """Return True if a persisted snapshot exists for `session_id`."""
        return self.load(session_id) is not None

    @contextmanager
    def session_lock(self, session_id: str, timeout_s: float = 10.0) -> Iterator[None]:
        """Acquire a re-entrant / mutually exclusive lock scoped to `session_id`."""
        yield

    def _get_async_session_lock(self, session_id: str) -> asyncio.Lock:
        """Return a per-(event-loop, session_id) asyncio.Lock without blocking the event loop."""
        guard = getattr(self, "_async_locks_guard", None)
        if guard is None:
            guard = threading.Lock()
            self._async_locks_guard = guard
        locks = getattr(self, "_async_session_locks", None)
        if locks is None:
            locks = {}
            self._async_session_locks = locks
        loop_id = id(asyncio.get_running_loop())
        key = (loop_id, str(session_id))
        with guard:
            lock = locks.get(key)
            if lock is None:
                if len(locks) > 2048:
                    stale = [k for k, v in locks.items() if not v.locked()]
                    for k in stale[: len(stale) // 2 + 1]:
                        locks.pop(k, None)
                lock = asyncio.Lock()
                locks[key] = lock
            return lock

    @asynccontextmanager
    async def async_session_lock(
        self, session_id: str, timeout_s: float = 10.0
    ) -> AsyncIterator[None]:
        """
        Event-loop-safe async session lock. Serializes same-session coroutines
        via an `asyncio.Lock` without holding a blocking `threading.RLock` across
        `await` boundaries (allowing concurrent sessions to make full progress).
        """
        lock = self._get_async_session_lock(session_id)
        try:
            await asyncio.wait_for(lock.acquire(), timeout=max(0.05, float(timeout_s)))
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"Timed out after {timeout_s}s acquiring async session lock for '{session_id}'."
            ) from exc
        try:
            yield
        finally:
            lock.release()

    def save_control_doc(self, namespace: str, doc: Dict[str, Any]) -> None:
        """
        Persist a named control-plane document (e.g. policy registry or escalation
        tickets) outside the session keyspace so `list_sessions()` stays pure.
        """
        cache = getattr(self, "_fallback_control_docs", None)
        if cache is None:
            cache = {}
            self._fallback_control_docs = cache
        cache[str(namespace)] = _encode_json(doc)

    def load_control_doc(self, namespace: str) -> Optional[Dict[str, Any]]:
        """Load a persisted control-plane document by namespace, or None."""
        cache = getattr(self, "_fallback_control_docs", None)
        if not cache:
            return None
        raw = cache.get(str(namespace))
        return json.loads(raw) if raw is not None else None

    def update_control_doc(
        self,
        namespace: str,
        updater: Callable[[Dict[str, Any]], Tuple[bool, Dict[str, Any], Any]],
    ) -> Tuple[bool, Any]:
        """Atomically read-modify-write a control-plane document, returning `(committed, meta)`."""
        lock = getattr(self, "_fallback_control_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._fallback_control_lock = lock
        with lock:
            curr = self.load_control_doc(namespace)
            doc = dict(curr) if isinstance(curr, dict) else {}
            ok, new_doc, meta = updater(doc)
            if ok:
                self.save_control_doc(namespace, new_doc)
            return bool(ok), meta

    @staticmethod
    def _match_audit_filters(
        item: Dict[str, Any],
        *,
        session_id: Optional[str] = None,
        verdict: Optional[str] = None,
        tool_name: Optional[str] = None,
        rule_triggered: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> bool:
        if session_id and item.get("session_id") != session_id:
            return False
        if verdict and str(item.get("verdict", "")).upper() != str(verdict).upper():
            return False
        if tool_name and item.get("tool_name") != tool_name:
            return False
        if rule_triggered and item.get("rule_triggered") != rule_triggered:
            return False
        if actor_id and item.get("actor_id") != actor_id:
            return False
        return True

    def append_audit_receipt(self, receipt_dict: Dict[str, Any]) -> None:
        """
        Append an immutable audit receipt record into durable storage independent
        of `session_id` snapshots so session deletion/TTL never erases compliance logs.
        """
        log = getattr(self, "_fallback_audit_log", None)
        if log is None:
            log = []
            self._fallback_audit_log = log
        log.append(_encode_json(receipt_dict))

    def load_audit_receipts(
        self,
        *,
        session_id: Optional[str] = None,
        verdict: Optional[str] = None,
        tool_name: Optional[str] = None,
        rule_triggered: Optional[str] = None,
        actor_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Query append-only audit receipts ordered chronologically."""
        log = getattr(self, "_fallback_audit_log", None)
        if not log:
            return []
        matches: List[Dict[str, Any]] = []
        for raw in log:
            item = json.loads(raw)
            if self._match_audit_filters(
                item,
                session_id=session_id,
                verdict=verdict,
                tool_name=tool_name,
                rule_triggered=rule_triggered,
                actor_id=actor_id,
            ):
                matches.append(item)
                if len(matches) >= limit:
                    break
        return matches


class InMemorySessionStore(SessionStateStore):
    """Thread-safe in-memory snapshot store using deep JSON serialization isolation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: Dict[str, str] = {}
        self._versions: Dict[str, int] = {}
        self._session_locks: Dict[str, threading.RLock] = {}
        self._control_docs: Dict[str, str] = {}
        self._audit_log: List[str] = []

    def append_audit_receipt(self, receipt_dict: Dict[str, Any]) -> None:
        with self._lock:
            self._audit_log.append(_encode_json(receipt_dict))

    def load_audit_receipts(
        self,
        *,
        session_id: Optional[str] = None,
        verdict: Optional[str] = None,
        tool_name: Optional[str] = None,
        rule_triggered: Optional[str] = None,
        actor_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            matches: List[Dict[str, Any]] = []
            for raw in self._audit_log:
                item = json.loads(raw)
                if self._match_audit_filters(
                    item,
                    session_id=session_id,
                    verdict=verdict,
                    tool_name=tool_name,
                    rule_triggered=rule_triggered,
                    actor_id=actor_id,
                ):
                    matches.append(item)
                    if len(matches) >= limit:
                        break
            return matches

    def save(
        self,
        session_id: str,
        snapshot: Dict[str, Any],
        expected_version: Optional[int] = None,
    ) -> int:
        with self._lock:
            current_version = self._versions.get(session_id)
            next_version, payload = _build_versioned_payload(
                session_id, snapshot, current_version, expected_version
            )
            self._sessions[session_id] = payload
            self._versions[session_id] = next_version
            return next_version

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            raw = self._sessions.get(session_id)
            if raw is None:
                return None
            return json.loads(raw)

    def delete(self, session_id: str) -> bool:
        with self._lock:
            existed = session_id in self._sessions
            self._sessions.pop(session_id, None)
            self._versions.pop(session_id, None)
            return existed

    def list_sessions(self) -> List[str]:
        with self._lock:
            return sorted(self._sessions.keys())

    def count_sessions(self) -> int:
        with self._lock:
            return len(self._sessions)

    @contextmanager
    def session_lock(self, session_id: str, timeout_s: float = 10.0) -> Iterator[None]:
        with self._lock:
            lock = self._session_locks.setdefault(session_id, threading.RLock())
        acquired = lock.acquire(timeout=timeout_s)
        if not acquired:
            raise TimeoutError(
                f"Timed out after {timeout_s}s acquiring session lock for '{session_id}'."
            )
        try:
            yield
        finally:
            lock.release()

    def save_control_doc(self, namespace: str, doc: Dict[str, Any]) -> None:
        with self._lock:
            self._control_docs[str(namespace)] = _encode_json(doc)

    def load_control_doc(self, namespace: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            raw = self._control_docs.get(str(namespace))
            return json.loads(raw) if raw is not None else None

    def update_control_doc(
        self,
        namespace: str,
        updater: Callable[[Dict[str, Any]], Tuple[bool, Dict[str, Any], Any]],
    ) -> Tuple[bool, Any]:
        with self._lock:
            raw = self._control_docs.get(str(namespace))
            doc = json.loads(raw) if raw is not None else {}
            ok, new_doc, meta = updater(dict(doc) if isinstance(doc, dict) else {})
            if ok:
                self._control_docs[str(namespace)] = _encode_json(new_doc)
            return bool(ok), meta


class SQLiteSessionStore(SessionStateStore):
    """
    Zero-dependency durable WAL-mode SQLite persistence store.
    Guarantees ACID transaction commits across worker restarts and process crashes.
    """

    def __init__(self, db_path: str = "gatekeep_sessions.db", busy_timeout_ms: int = 5000) -> None:
        self.db_path = db_path
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        self._session_locks: Dict[str, threading.RLock] = {}

        if db_path != ":memory:":
            parent = os.path.dirname(os.path.abspath(db_path))
            if parent:
                os.makedirs(parent, exist_ok=True)

        self._conn = sqlite3.connect(
            db_path,
            timeout=max(1.0, busy_timeout_ms / 1000.0),
            check_same_thread=False,
            isolation_level=None,
        )
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode=WAL;")
                cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute(f"PRAGMA busy_timeout={int(self._busy_timeout_ms)};")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS gatekeep_sessions (
                    session_id TEXT PRIMARY KEY,
                    ledger_json TEXT NOT NULL,
                    gate_json TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    updated_at REAL NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS gatekeep_control_plane (
                    namespace TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS gatekeep_audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    rule_triggered TEXT NOT NULL,
                    actor_id TEXT,
                    payload_json TEXT NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_gatekeep_audit_session ON gatekeep_audit_log (session_id, seq)"
            )

    def save(
        self,
        session_id: str,
        snapshot: Dict[str, Any],
        expected_version: Optional[int] = None,
    ) -> int:
        ledger_json = _encode_json(snapshot.get("ledger") or {})
        gate_json = _encode_json(snapshot.get("gate") or {})
        now = time.time()

        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute(
                    "SELECT version FROM gatekeep_sessions WHERE session_id = ?",
                    (session_id,),
                )
                row = cur.fetchone()
                current_version = int(row[0]) if row is not None else None
                next_version = _check_expected_version(
                    session_id, current_version, expected_version
                )
                cur.execute(
                    """
                    INSERT INTO gatekeep_sessions (session_id, ledger_json, gate_json, version, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        ledger_json = excluded.ledger_json,
                        gate_json = excluded.gate_json,
                        version = excluded.version,
                        updated_at = excluded.updated_at
                    """,
                    (session_id, ledger_json, gate_json, next_version, now),
                )
                cur.execute("COMMIT")
                return next_version
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT ledger_json, gate_json, version, updated_at
                FROM gatekeep_sessions
                WHERE session_id = ?
                """,
                (session_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return {
                "session_id": session_id,
                "ledger": json.loads(row[0]),
                "gate": json.loads(row[1]),
                "version": int(row[2]),
                "updated_at": float(row[3]),
            }

    def delete(self, session_id: str) -> bool:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute(
                    "DELETE FROM gatekeep_sessions WHERE session_id = ?",
                    (session_id,),
                )
                deleted = cur.rowcount > 0
                cur.execute("COMMIT")
                return deleted
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def list_sessions(self) -> List[str]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT session_id FROM gatekeep_sessions ORDER BY session_id ASC")
            return [str(r[0]) for r in cur.fetchall()]

    def count_sessions(self) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM gatekeep_sessions")
            row = cur.fetchone()
            return int(row[0]) if row is not None else 0

    def save_control_doc(self, namespace: str, doc: Dict[str, Any]) -> None:
        payload = _encode_json(doc)
        now = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute(
                    """
                    INSERT INTO gatekeep_control_plane (namespace, payload_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(namespace) DO UPDATE SET
                        payload_json = excluded.payload_json,
                        updated_at = excluded.updated_at
                    """,
                    (str(namespace), payload, now),
                )
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def load_control_doc(self, namespace: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT payload_json FROM gatekeep_control_plane WHERE namespace = ?",
                (str(namespace),),
            )
            row = cur.fetchone()
            return json.loads(row[0]) if row is not None else None

    def update_control_doc(
        self,
        namespace: str,
        updater: Callable[[Dict[str, Any]], Tuple[bool, Dict[str, Any], Any]],
    ) -> Tuple[bool, Any]:
        ns = str(namespace)
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute(
                    "SELECT payload_json FROM gatekeep_control_plane WHERE namespace = ?",
                    (ns,),
                )
                row = cur.fetchone()
                curr_doc = json.loads(row[0]) if row is not None else {}
                ok, new_doc, meta = updater(dict(curr_doc) if isinstance(curr_doc, dict) else {})
                if ok:
                    payload = _encode_json(new_doc)
                    now = time.time()
                    cur.execute(
                        """
                        INSERT INTO gatekeep_control_plane (namespace, payload_json, updated_at)
                        VALUES (?, ?, ?)
                        ON CONFLICT(namespace) DO UPDATE SET
                            payload_json = excluded.payload_json,
                            updated_at = excluded.updated_at
                        """,
                        (ns, payload, now),
                    )
                cur.execute("COMMIT")
                return bool(ok), meta
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def append_audit_receipt(self, receipt_dict: Dict[str, Any]) -> None:
        payload = _encode_json(receipt_dict)
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute(
                    """
                    INSERT INTO gatekeep_audit_log (
                        session_id, timestamp, verdict, tool_name, rule_triggered, actor_id, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(receipt_dict.get("session_id", "default")),
                        str(receipt_dict.get("timestamp", "")),
                        str(receipt_dict.get("verdict", "")),
                        str(receipt_dict.get("tool_name", "")),
                        str(receipt_dict.get("rule_triggered", "")),
                        receipt_dict.get("actor_id"),
                        payload,
                    ),
                )
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def load_audit_receipts(
        self,
        *,
        session_id: Optional[str] = None,
        verdict: Optional[str] = None,
        tool_name: Optional[str] = None,
        rule_triggered: Optional[str] = None,
        actor_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if verdict:
            clauses.append("UPPER(verdict) = ?")
            params.append(str(verdict).upper())
        if tool_name:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if rule_triggered:
            clauses.append("rule_triggered = ?")
            params.append(rule_triggered)
        if actor_id:
            clauses.append("actor_id = ?")
            params.append(actor_id)

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT payload_json FROM gatekeep_audit_log {where_sql} ORDER BY seq ASC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, tuple(params))
            return [json.loads(r[0]) for r in cur.fetchall()]

    @contextmanager
    def session_lock(self, session_id: str, timeout_s: float = 10.0) -> Iterator[None]:
        with self._lock:
            lock = self._session_locks.setdefault(session_id, threading.RLock())
        acquired = lock.acquire(timeout=timeout_s)
        if not acquired:
            raise TimeoutError(
                f"Timed out after {timeout_s}s acquiring session lock for '{session_id}'."
            )
        try:
            yield
        finally:
            lock.release()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            if getattr(self, "_conn", None) is not None:
                self._conn.close()
                self._conn = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self) -> "SQLiteSessionStore":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class RedisSessionStore(SessionStateStore):
    """
    Distributed Redis-backed persistence store for multi-worker/stateless deployments.
    Accepts either a `redis_url` (lazily importing `redis`) or an explicit Redis `client`.
    Uses `WATCH`/`MULTI`/`EXEC` optimistic transactions for concurrency-safe saves.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        client: Optional[Any] = None,
        ttl_seconds: Optional[int] = None,
        key_prefix: str = "slim:gatekeep:session:",
    ) -> None:
        if client is None:
            try:
                import redis  # type: ignore
            except ImportError as exc:
                raise ImportError(
                    "RedisSessionStore requires the 'redis' package when `client` is not provided. "
                    "Install it with: pip install redis"
                ) from exc
            client = redis.Redis.from_url(redis_url, decode_responses=True)

        self._client = client
        self._ttl_seconds = ttl_seconds
        self._prefix = key_prefix
        self._lock = threading.RLock()

    def _key(self, session_id: str) -> str:
        return f"{self._prefix}{session_id}"

    def _lock_key(self, session_id: str) -> str:
        return f"{self._prefix}lock:{session_id}"

    def _write_key(self, pipe_or_client: Any, key: str, payload: str) -> None:
        if self._ttl_seconds is not None and self._ttl_seconds > 0:
            pipe_or_client.setex(key, self._ttl_seconds, payload)
        else:
            pipe_or_client.set(key, payload)

    def _decode(self, raw: Any) -> Optional[Dict[str, Any]]:
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if isinstance(raw, dict):
            return raw
        return json.loads(raw)

    def save(
        self,
        session_id: str,
        snapshot: Dict[str, Any],
        expected_version: Optional[int] = None,
    ) -> int:
        key = self._key(session_id)

        if hasattr(self._client, "pipeline"):
            while True:
                with self._client.pipeline() as pipe:
                    try:
                        pipe.watch(key)
                        existing = self._decode(pipe.get(key))
                        current_version = (
                            int(existing["version"]) if existing and "version" in existing else None
                        )
                        next_version, payload = _build_versioned_payload(
                            session_id, snapshot, current_version, expected_version
                        )
                        pipe.multi()
                        self._write_key(pipe, key, payload)
                        if hasattr(pipe, "sadd"):
                            pipe.sadd(f"{self._prefix}__sessions__", session_id)
                        pipe.execute()
                        return next_version
                    except Exception as exc:
                        # Retry WATCH abort unless it is an explicit CAS mismatch
                        if exc.__class__.__name__ == "WatchError":
                            continue
                        raise

        # Fallback path for simple mock Redis clients without pipeline/WATCH
        with self._lock:
            existing = self.load(session_id)
            current_version = (
                int(existing["version"]) if existing and "version" in existing else None
            )
            next_version, payload = _build_versioned_payload(
                session_id, snapshot, current_version, expected_version
            )
            self._write_key(self._client, key, payload)
            if hasattr(self._client, "sadd"):
                self._client.sadd(f"{self._prefix}__sessions__", session_id)
            return next_version

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self._decode(self._client.get(self._key(session_id)))

    def delete(self, session_id: str) -> bool:
        removed = bool(self._client.delete(self._key(session_id)))
        if hasattr(self._client, "srem"):
            try:
                self._client.srem(f"{self._prefix}__sessions__", session_id)
            except Exception:
                pass
        return removed

    def list_sessions(self) -> List[str]:
        pattern = f"{self._prefix}*"
        lock_marker = f"{self._prefix}lock:"
        cp_marker = f"{self._prefix}__cp__:"
        audit_marker = f"{self._prefix}__audit__"
        idx_marker = f"{self._prefix}__sessions__"
        if hasattr(self._client, "scan_iter"):
            raw_keys = list(self._client.scan_iter(match=pattern))
        else:
            raw_keys = list(self._client.keys(pattern))

        sessions: List[str] = []
        for k in raw_keys:
            k_str = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            if (
                k_str.startswith(lock_marker)
                or k_str.startswith(cp_marker)
                or k_str == audit_marker
                or k_str == idx_marker
            ):
                continue
            if k_str.startswith(self._prefix):
                sessions.append(k_str[len(self._prefix):])
        return sorted(sessions)

    def count_sessions(self) -> int:
        if hasattr(self._client, "scard"):
            try:
                return int(self._client.scard(f"{self._prefix}__sessions__"))
            except Exception:
                pass
        return len(self.list_sessions())

    def save_control_doc(self, namespace: str, doc: Dict[str, Any]) -> None:
        cp_key = f"{self._prefix}__cp__:{namespace}"
        self._client.set(cp_key, _encode_json(doc))

    def load_control_doc(self, namespace: str) -> Optional[Dict[str, Any]]:
        cp_key = f"{self._prefix}__cp__:{namespace}"
        return self._decode(self._client.get(cp_key))

    def update_control_doc(
        self,
        namespace: str,
        updater: Callable[[Dict[str, Any]], Tuple[bool, Dict[str, Any], Any]],
    ) -> Tuple[bool, Any]:
        with self.session_lock(f"__cp__:{namespace}"):
            curr = self.load_control_doc(namespace)
            doc = dict(curr) if isinstance(curr, dict) else {}
            ok, new_doc, meta = updater(doc)
            if ok:
                self.save_control_doc(namespace, new_doc)
            return bool(ok), meta

    def append_audit_receipt(self, receipt_dict: Dict[str, Any]) -> None:
        audit_key = f"{self._prefix}__audit__"
        encoded = _encode_json(receipt_dict)
        if hasattr(self._client, "rpush"):
            self._client.rpush(audit_key, encoded)
        else:
            with self._lock:
                existing = self._decode(self._client.get(audit_key))
                items = existing if isinstance(existing, list) else []
                items.append(receipt_dict)
                self._client.set(audit_key, _encode_json(items))

    def load_audit_receipts(
        self,
        *,
        session_id: Optional[str] = None,
        verdict: Optional[str] = None,
        tool_name: Optional[str] = None,
        rule_triggered: Optional[str] = None,
        actor_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        audit_key = f"{self._prefix}__audit__"
        if hasattr(self._client, "lrange"):
            raw_items = self._client.lrange(audit_key, 0, -1) or []
            decoded = [self._decode(x) for x in raw_items]
        else:
            existing = self._decode(self._client.get(audit_key))
            decoded = existing if isinstance(existing, list) else []

        matches: List[Dict[str, Any]] = []
        for item in decoded:
            if not isinstance(item, dict):
                continue
            if self._match_audit_filters(
                item,
                session_id=session_id,
                verdict=verdict,
                tool_name=tool_name,
                rule_triggered=rule_triggered,
                actor_id=actor_id,
            ):
                matches.append(item)
                if len(matches) >= limit:
                    break
        return matches

    @contextmanager
    def session_lock(self, session_id: str, timeout_s: float = 10.0) -> Iterator[None]:
        lock_key = self._lock_key(session_id)
        token = uuid.uuid4().hex
        deadline = time.monotonic() + timeout_s
        px_ms = max(1000, int(timeout_s * 1000))

        acquired = False
        while time.monotonic() < deadline:
            if self._client.set(lock_key, token, nx=True, px=px_ms):
                acquired = True
                break
            time.sleep(0.02)

        if not acquired:
            raise TimeoutError(
                f"Timed out after {timeout_s}s acquiring Redis session lock for '{session_id}'."
            )
        try:
            yield
        finally:
            try:
                cur_token = self._client.get(lock_key)
                if isinstance(cur_token, bytes):
                    cur_token = cur_token.decode("utf-8")
                if cur_token == token:
                    self._client.delete(lock_key)
            except Exception:
                pass

    @asynccontextmanager
    async def async_session_lock(
        self, session_id: str, timeout_s: float = 10.0
    ) -> AsyncIterator[None]:
        """Non-blocking distributed Redis session lock safe for asyncio event loops."""
        local_lock = self._get_async_session_lock(session_id)
        deadline = time.monotonic() + float(timeout_s)
        try:
            await asyncio.wait_for(
                local_lock.acquire(), timeout=max(0.05, deadline - time.monotonic())
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"Timed out after {timeout_s}s acquiring local Redis async lock for '{session_id}'."
            ) from exc

        lock_key = self._lock_key(session_id)
        token = uuid.uuid4().hex
        px_ms = max(1000, int(float(timeout_s) * 1000))
        acquired = False
        try:
            while time.monotonic() < deadline:
                acquired = bool(
                    await asyncio.to_thread(
                        self._client.set, lock_key, token, nx=True, px=px_ms
                    )
                )
                if acquired:
                    break
                await asyncio.sleep(0.015)

            if not acquired:
                raise TimeoutError(
                    f"Timed out after {timeout_s}s acquiring Redis session lock for '{session_id}'."
                )
            try:
                yield
            finally:
                def _release() -> None:
                    try:
                        cur_token = self._client.get(lock_key)
                        if isinstance(cur_token, bytes):
                            cur_token = cur_token.decode("utf-8")
                        if cur_token == token:
                            self._client.delete(lock_key)
                    except Exception:
                        pass

                await asyncio.to_thread(_release)
        finally:
            local_lock.release()


class PostgresSessionStore(SessionStateStore):
    """
    PostgreSQL-backed distributed `SessionStateStore` for multi-worker deployments.

    Uses row-level ``SELECT ... FOR UPDATE`` optimistic Compare-And-Swap versioning
    and session-level ``pg_try_advisory_lock`` coordination. Supports:
    - a `dsn` (lazily importing ``psycopg`` v3 or ``psycopg2``),
    - a connection `pool` (``.connection()`` context manager or ``.getconn()``/``.putconn()``), or
    - an injected DB-API 2.0 `conn` object for testing.
    """

    def __init__(
        self,
        dsn: Optional[str] = None,
        conn: Optional[Any] = None,
        table_name: str = "gatekeep_sessions",
        pool: Optional[Any] = None,
        pool_min_size: int = 2,
        pool_max_size: int = 16,
    ):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table_name):
            raise ValueError(f"Invalid SQL identifier for table_name: '{table_name}'.")
        if conn is None and pool is None and not dsn:
            raise ValueError("PostgresSessionStore requires 'dsn', 'pool', or 'conn'.")

        self._table = table_name
        self._cp_table = f"{table_name}_control_plane"
        self._audit_table = f"{table_name}_audit_log"
        self._pool = pool
        self._conn = conn
        self._owns_conn = False
        if conn is None and pool is None:
            created_pool, created_conn = self._connect_or_pool(
                str(dsn), min_size=int(pool_min_size), max_size=int(pool_max_size)
            )
            self._pool = created_pool
            self._conn = created_conn
            self._owns_conn = created_conn is not None
        self._local_lock = threading.RLock()
        self._init_schema()

    @classmethod
    def _connect_or_pool(
        cls, dsn: str, *, min_size: int = 2, max_size: int = 16
    ) -> Tuple[Optional[Any], Optional[Any]]:
        """Prefer `psycopg_pool.ConnectionPool` for multi-request concurrency, falling back to single conn."""
        try:
            from psycopg_pool import ConnectionPool  # type: ignore

            return (
                ConnectionPool(
                    dsn,
                    min_size=max(1, min_size),
                    max_size=max(min_size, max_size),
                    open=True,
                ),
                None,
            )
        except ImportError:
            pass
        return None, cls._connect(dsn)

    @staticmethod
    def _connect(dsn: str) -> Any:
        try:
            import psycopg  # type: ignore

            return psycopg.connect(dsn)
        except ImportError:
            pass
        try:
            import psycopg2  # type: ignore

            return psycopg2.connect(dsn)
        except ImportError as exc:
            raise ImportError(
                "PostgresSessionStore requires 'psycopg' or 'psycopg2'. "
                "Install with: pip install psycopg[binary]"
            ) from exc

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        if self._pool is not None:
            if hasattr(self._pool, "connection"):
                with self._pool.connection() as pooled_conn:
                    yield pooled_conn
                return
            if hasattr(self._pool, "getconn") and hasattr(self._pool, "putconn"):
                pooled_conn = self._pool.getconn()
                try:
                    yield pooled_conn
                finally:
                    self._pool.putconn(pooled_conn)
                return
        with self._local_lock:
            yield self._conn

    @staticmethod
    def _advisory_key(session_id: str) -> int:
        digest = hashlib.sha256(session_id.encode("utf-8")).digest()[:8]
        return int.from_bytes(digest, byteorder="big", signed=True)

    @staticmethod
    def _begin(conn: Any, cur: Any) -> bool:
        autocommit = bool(getattr(conn, "autocommit", False))
        if autocommit:
            cur.execute("BEGIN")
        return autocommit

    @staticmethod
    def _commit(conn: Any, cur: Any, began_explicitly: bool) -> None:
        if began_explicitly:
            cur.execute("COMMIT")
        else:
            conn.commit()

    @staticmethod
    def _rollback(conn: Any, cur: Any, began_explicitly: bool) -> None:
        try:
            if began_explicitly:
                cur.execute("ROLLBACK")
            else:
                conn.rollback()
        except Exception:
            pass

    def _init_schema(self) -> None:
        with self._connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._table} (
                        session_id TEXT PRIMARY KEY,
                        version BIGINT NOT NULL,
                        payload TEXT NOT NULL,
                        updated_at DOUBLE PRECISION NOT NULL
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._cp_table} (
                        namespace TEXT PRIMARY KEY,
                        payload TEXT NOT NULL,
                        updated_at DOUBLE PRECISION NOT NULL
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._audit_table} (
                        seq BIGSERIAL PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        verdict TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        rule_triggered TEXT NOT NULL,
                        actor_id TEXT,
                        payload TEXT NOT NULL
                    )
                    """
                )
                if not getattr(conn, "autocommit", False):
                    conn.commit()
            finally:
                cur.close()

    def save(
        self,
        session_id: str,
        snapshot: Dict[str, Any],
        expected_version: Optional[int] = None,
    ) -> int:
        with self._connection() as conn:
            cur = conn.cursor()
            began = False
            try:
                began = self._begin(conn, cur)
                cur.execute(
                    f"SELECT version FROM {self._table} WHERE session_id = %s FOR UPDATE",
                    (session_id,),
                )
                row = cur.fetchone()
                current_version = int(row[0]) if row is not None else None
                next_version, payload = _build_versioned_payload(
                    session_id=session_id,
                    snapshot=snapshot,
                    current_version=current_version,
                    expected_version=expected_version,
                )
                now = time.time()
                cur.execute(
                    f"""
                    INSERT INTO {self._table} (session_id, version, payload, updated_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (session_id) DO UPDATE SET
                        version = EXCLUDED.version,
                        payload = EXCLUDED.payload,
                        updated_at = EXCLUDED.updated_at
                    """,
                    (session_id, next_version, payload, now),
                )
                self._commit(conn, cur, began)
                return next_version
            except Exception:
                self._rollback(conn, cur, began)
                raise
            finally:
                cur.close()

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"SELECT payload FROM {self._table} WHERE session_id = %s",
                    (session_id,),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                return json.loads(row[0])
            finally:
                cur.close()

    def delete(self, session_id: str) -> bool:
        with self._connection() as conn:
            cur = conn.cursor()
            began = False
            try:
                began = self._begin(conn, cur)
                cur.execute(
                    f"DELETE FROM {self._table} WHERE session_id = %s",
                    (session_id,),
                )
                deleted = (cur.rowcount or 0) > 0
                self._commit(conn, cur, began)
                return deleted
            except Exception:
                self._rollback(conn, cur, began)
                raise
            finally:
                cur.close()

    def list_sessions(self) -> List[str]:
        with self._connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute(f"SELECT session_id FROM {self._table} ORDER BY session_id")
                rows = cur.fetchall()
                return [str(r[0]) for r in rows]
            finally:
                cur.close()

    def count_sessions(self) -> int:
        with self._connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute(f"SELECT COUNT(*) FROM {self._table}")
                row = cur.fetchone()
                return int(row[0]) if row is not None else 0
            finally:
                cur.close()

    def save_control_doc(self, namespace: str, doc: Dict[str, Any]) -> None:
        payload = _encode_json(doc)
        now = time.time()
        with self._connection() as conn:
            cur = conn.cursor()
            began = False
            try:
                began = self._begin(conn, cur)
                cur.execute(
                    f"""
                    INSERT INTO {self._cp_table} (namespace, payload, updated_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (namespace) DO UPDATE SET
                        payload = EXCLUDED.payload,
                        updated_at = EXCLUDED.updated_at
                    """,
                    (str(namespace), payload, now),
                )
                self._commit(conn, cur, began)
            except Exception:
                self._rollback(conn, cur, began)
                raise
            finally:
                cur.close()

    def load_control_doc(self, namespace: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"SELECT payload FROM {self._cp_table} WHERE namespace = %s",
                    (str(namespace),),
                )
                row = cur.fetchone()
                return json.loads(row[0]) if row is not None else None
            finally:
                cur.close()

    def update_control_doc(
        self,
        namespace: str,
        updater: Callable[[Dict[str, Any]], Tuple[bool, Dict[str, Any], Any]],
    ) -> Tuple[bool, Any]:
        ns = str(namespace)
        with self.session_lock(f"__cp__:{ns}"):
            with self._connection() as conn:
                cur = conn.cursor()
                began = False
                try:
                    began = self._begin(conn, cur)
                    cur.execute(
                        f"SELECT payload FROM {self._cp_table} WHERE namespace = %s",
                        (ns,),
                    )
                    row = cur.fetchone()
                    curr_doc = json.loads(row[0]) if row is not None else {}
                    ok, new_doc, meta = updater(
                        dict(curr_doc) if isinstance(curr_doc, dict) else {}
                    )
                    if ok:
                        payload = _encode_json(new_doc)
                        now = time.time()
                        cur.execute(
                            f"""
                            INSERT INTO {self._cp_table} (namespace, payload, updated_at)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (namespace) DO UPDATE SET
                                payload = EXCLUDED.payload,
                                updated_at = EXCLUDED.updated_at
                            """,
                            (ns, payload, now),
                        )
                    self._commit(conn, cur, began)
                    return bool(ok), meta
                except Exception:
                    self._rollback(conn, cur, began)
                    raise
                finally:
                    cur.close()

    def append_audit_receipt(self, receipt_dict: Dict[str, Any]) -> None:
        payload = _encode_json(receipt_dict)
        with self._connection() as conn:
            cur = conn.cursor()
            began = False
            try:
                began = self._begin(conn, cur)
                cur.execute(
                    f"""
                    INSERT INTO {self._audit_table} (
                        session_id, timestamp, verdict, tool_name, rule_triggered, actor_id, payload
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(receipt_dict.get("session_id", "default")),
                        str(receipt_dict.get("timestamp", "")),
                        str(receipt_dict.get("verdict", "")),
                        str(receipt_dict.get("tool_name", "")),
                        str(receipt_dict.get("rule_triggered", "")),
                        receipt_dict.get("actor_id"),
                        payload,
                    ),
                )
                self._commit(conn, cur, began)
            except Exception:
                self._rollback(conn, cur, began)
                raise
            finally:
                cur.close()

    def load_audit_receipts(
        self,
        *,
        session_id: Optional[str] = None,
        verdict: Optional[str] = None,
        tool_name: Optional[str] = None,
        rule_triggered: Optional[str] = None,
        actor_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if session_id:
            clauses.append("session_id = %s")
            params.append(session_id)
        if verdict:
            clauses.append("UPPER(verdict) = %s")
            params.append(str(verdict).upper())
        if tool_name:
            clauses.append("tool_name = %s")
            params.append(tool_name)
        if rule_triggered:
            clauses.append("rule_triggered = %s")
            params.append(rule_triggered)
        if actor_id:
            clauses.append("actor_id = %s")
            params.append(actor_id)

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT payload FROM {self._audit_table} {where_sql} ORDER BY seq ASC LIMIT %s"
        params.append(int(limit))
        with self._connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute(sql, tuple(params))
                return [json.loads(r[0]) for r in cur.fetchall()]
            finally:
                cur.close()

    @contextmanager
    def session_lock(self, session_id: str, timeout_s: float = 10.0) -> Iterator[None]:
        key = self._advisory_key(session_id)
        deadline = time.monotonic() + timeout_s
        with self._connection() as conn:
            acquired = False
            while time.monotonic() < deadline:
                cur = conn.cursor()
                try:
                    cur.execute("SELECT pg_try_advisory_lock(%s)", (key,))
                    row = cur.fetchone()
                    acquired = bool(row and row[0])
                    if not getattr(conn, "autocommit", False):
                        conn.commit()
                finally:
                    cur.close()
                if acquired:
                    break
                time.sleep(0.02)

            if not acquired:
                raise TimeoutError(
                    f"Timed out after {timeout_s}s acquiring Postgres advisory lock for '{session_id}'."
                )

            try:
                yield
            finally:
                cur = conn.cursor()
                try:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (key,))
                    if not getattr(conn, "autocommit", False):
                        conn.commit()
                except Exception:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                finally:
                    cur.close()

    @asynccontextmanager
    async def async_session_lock(
        self, session_id: str, timeout_s: float = 10.0
    ) -> AsyncIterator[None]:
        """
        Non-blocking async Postgres session lock.
        Serializes same-pod coroutines via `asyncio.Lock`, and when a connection pool
        supporting `getconn`/`putconn` is configured (e.g. `psycopg_pool.ConnectionPool`),
        acquires a cross-pod `pg_try_advisory_lock` off the event loop thread.
        """
        local_lock = self._get_async_session_lock(session_id)
        deadline = time.monotonic() + float(timeout_s)
        try:
            await asyncio.wait_for(
                local_lock.acquire(), timeout=max(0.05, deadline - time.monotonic())
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"Timed out after {timeout_s}s acquiring local Postgres async lock for '{session_id}'."
            ) from exc

        try:
            if (
                self._pool is None
                or not hasattr(self._pool, "getconn")
                or not hasattr(self._pool, "putconn")
            ):
                # Single-connection mode: avoid holding `_local_lock` across `await`;
                # row-level `SELECT ... FOR UPDATE` CAS protects cross-replica writes.
                yield
                return

            key = self._advisory_key(session_id)

            def _try_acquire() -> Optional[Any]:
                conn = self._pool.getconn()
                try:
                    cur = conn.cursor()
                    try:
                        cur.execute("SELECT pg_try_advisory_lock(%s)", (key,))
                        row = cur.fetchone()
                        ok = bool(row and row[0])
                        if not getattr(conn, "autocommit", False):
                            conn.commit()
                    finally:
                        cur.close()
                    if ok:
                        return conn
                except Exception:
                    try:
                        self._pool.putconn(conn)
                    except Exception:
                        pass
                    raise
                self._pool.putconn(conn)
                return None

            def _unlock_and_return(conn: Any) -> None:
                try:
                    cur = conn.cursor()
                    try:
                        cur.execute("SELECT pg_advisory_unlock(%s)", (key,))
                        if not getattr(conn, "autocommit", False):
                            conn.commit()
                    except Exception:
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                    finally:
                        cur.close()
                finally:
                    try:
                        self._pool.putconn(conn)
                    except Exception:
                        pass

            lock_conn: Optional[Any] = None
            while time.monotonic() < deadline:
                lock_conn = await asyncio.to_thread(_try_acquire)
                if lock_conn is not None:
                    break
                await asyncio.sleep(0.015)

            if lock_conn is None:
                raise TimeoutError(
                    f"Timed out after {timeout_s}s acquiring Postgres advisory lock for '{session_id}'."
                )

            try:
                yield
            finally:
                await asyncio.to_thread(_unlock_and_return, lock_conn)
        finally:
            local_lock.release()

    def close(self) -> None:
        if self._pool is not None and hasattr(self._pool, "close"):
            with self._local_lock:
                self._pool.close()
                return
        if self._owns_conn and self._conn is not None and hasattr(self._conn, "close"):
            with self._local_lock:
                self._conn.close()

    def __enter__(self) -> "PostgresSessionStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()
