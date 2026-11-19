"""
gatekeep/saga.py

Production-Ready Saga Transaction & Compensation Coordinator for AI Agents.
Guarantees clean, zero-orphan execution state across multi-step mutations:
1. Pushes compensating inverse actions (LIFO order) as forward write tools succeed.
2. Triggers automated deterministic rollbacks when an unrecoverable failure,
   circuit-breaker trip, or permanent policy BLOCK occurs.
3. Emits SHA-256 hash-chained AuditReceipts for every compensation execution.
"""

from __future__ import annotations

import inspect
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("gatekeep.saga")


@dataclass
class SagaStep:
    """Represents a registered compensation step in the transaction stack."""
    step_id: str
    forward_tool: str
    forward_args: Dict[str, Any]
    forward_result: Any
    compensating_tool: Optional[str] = None
    compensation_args: Optional[Dict[str, Any]] = None
    on_rollback: Optional[Callable] = None
    timestamp: float = field(default_factory=time.time)
    status: str = "PENDING"  # PENDING, COMPENSATED, FAILED, COMMITTED

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this step to a JSON-compatible dictionary (omitting live callables)."""
        return {
            "step_id": self.step_id,
            "forward_tool": self.forward_tool,
            "forward_args": dict(self.forward_args) if isinstance(self.forward_args, dict) else self.forward_args,
            "forward_result": self.forward_result,
            "compensating_tool": self.compensating_tool,
            "compensation_args": dict(self.compensation_args) if isinstance(self.compensation_args, dict) else self.compensation_args,
            "timestamp": self.timestamp,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], registry: Optional[Any] = None) -> "SagaStep":
        """Reconstruct a SagaStep from a dict, re-attaching registry on_rollback hooks if present."""
        forward_tool = str(data["forward_tool"])
        on_rollback: Optional[Callable] = None
        if registry is not None:
            tool_def = registry.get(forward_tool)
            if tool_def is not None:
                on_rollback = getattr(tool_def, "on_rollback", None)

        return cls(
            step_id=str(data["step_id"]),
            forward_tool=forward_tool,
            forward_args=dict(data.get("forward_args") or {}),
            forward_result=data.get("forward_result"),
            compensating_tool=data.get("compensating_tool"),
            compensation_args=dict(data["compensation_args"]) if data.get("compensation_args") is not None else None,
            on_rollback=on_rollback,
            timestamp=float(data.get("timestamp", time.time())),
            status=str(data.get("status", "PENDING")),
        )


@dataclass
class RollbackSummary:
    """Summary record produced after a saga rollback execution."""
    success: bool
    total_steps: int
    compensated_steps: int
    failed_steps: int
    details: List[Dict[str, Any]] = field(default_factory=list)


class SagaCoordinator:
    """
    Manages the LIFO compensation stack for a session.
    Thread-safe, serializable, and deterministic.
    """

    def __init__(self, registry: Optional[Any] = None) -> None:
        self._lock = threading.RLock()
        self.registry = registry
        self._stack: List[SagaStep] = []
        self._history: List[SagaStep] = []
        self._in_flight: Dict[str, Dict[str, Any]] = {}
        self._idempotency_cache: Dict[str, Dict[str, Any]] = {}

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._stack)

    @property
    def in_flight_count(self) -> int:
        with self._lock:
            return len(self._in_flight)

    @property
    def in_flight_entries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(v) for v in self._in_flight.values()]

    def begin_in_flight(
        self,
        wal_id: str,
        tool_name: str,
        forward_args: Dict[str, Any],
        *,
        idempotency_key: Optional[str] = None,
        compensating_tool: Optional[str] = None,
        compensation_args: Optional[Any] = None,
        fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record an IN_FLIGHT write-ahead journal entry prior to external tool dispatch."""
        entry = {
            "wal_id": wal_id,
            "idempotency_key": idempotency_key,
            "tool_name": tool_name,
            "forward_args": dict(forward_args or {}),
            "compensating_tool": compensating_tool,
            "compensation_args": compensation_args,
            "fingerprint": fingerprint,
            "started_at": time.time(),
            "status": "IN_FLIGHT",
        }
        with self._lock:
            self._in_flight[wal_id] = entry
        return dict(entry)

    def finish_in_flight(
        self,
        wal_id: str,
        *,
        success: bool = True,
        idempotency_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
        cached_result: Any = None,
    ) -> None:
        """Clear an IN_FLIGHT journal entry after upstream response and optionally cache idempotent result."""
        with self._lock:
            entry = self._in_flight.pop(wal_id, None)
            idem_key = idempotency_key or (entry.get("idempotency_key") if entry else None)
            fp = fingerprint or (entry.get("fingerprint") if entry else None)
            if success and idem_key:
                self._idempotency_cache[idem_key] = {
                    "fingerprint": fp,
                    "result": cached_result,
                    "completed_at": time.time(),
                }
                while len(self._idempotency_cache) > 200:
                    oldest = next(iter(self._idempotency_cache))
                    self._idempotency_cache.pop(oldest, None)

    def get_idempotent_replay(
        self,
        idempotency_key: Optional[str],
        *,
        fingerprint: Optional[str] = None,
    ) -> Tuple[str, Any]:
        """
        Check idempotency state for `idempotency_key`.

        Returns ``(status, payload)`` where ``status`` is one of
        ``"HIT"``, ``"CONFLICT"``, ``"IN_FLIGHT"``, or ``"MISS"``.
        """
        if not idempotency_key:
            return "MISS", None
        with self._lock:
            cached = self._idempotency_cache.get(idempotency_key)
            if cached is not None:
                expected_fp = cached.get("fingerprint")
                if fingerprint and expected_fp and expected_fp != fingerprint:
                    return "CONFLICT", None
                return "HIT", cached.get("result")

            for entry in self._in_flight.values():
                if entry.get("idempotency_key") == idempotency_key:
                    expected_fp = entry.get("fingerprint")
                    if fingerprint and expected_fp and expected_fp != fingerprint:
                        return "CONFLICT", None
                    return "IN_FLIGHT", dict(entry)
        return "MISS", None

    _TEMPLATE_PATTERN = re.compile(r"\{(result|args)(?:\.([A-Za-z0-9_.\-]+))?\}")

    @classmethod
    def _lookup_path(cls, root: Any, path: Optional[str]) -> Any:
        if not path:
            return root
        cur = root
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
        return cur

    @classmethod
    def _resolve_template_value(
        cls,
        value: Any,
        result: Any,
        arguments: Dict[str, Any],
    ) -> Any:
        if isinstance(value, dict):
            return {k: cls._resolve_template_value(v, result, arguments) for k, v in value.items()}
        if isinstance(value, list):
            return [cls._resolve_template_value(v, result, arguments) for v in value]
        if not isinstance(value, str):
            return value

        sources = {"result": result, "args": arguments}
        full_match = cls._TEMPLATE_PATTERN.fullmatch(value)
        if full_match:
            src_name, path = full_match.group(1), full_match.group(2)
            return cls._lookup_path(sources[src_name], path)

        if "{" not in value:
            return value

        def _replace(match: re.Match[str]) -> str:
            src_name, path = match.group(1), match.group(2)
            resolved = cls._lookup_path(sources[src_name], path)
            return "" if resolved is None else str(resolved)

        return cls._TEMPLATE_PATTERN.sub(_replace, value)

    @classmethod
    def resolve_compensation_args(
        cls,
        compensation_args: Optional[Any],
        result: Any,
        arguments: Dict[str, Any],
        tool_name: str = "",
    ) -> Dict[str, Any]:
        """Resolve dynamic callable or declarative `{result.*}`/`{args.*}` templates."""
        if callable(compensation_args):
            try:
                sig = inspect.signature(compensation_args)
                if len(sig.parameters) >= 2:
                    return dict(compensation_args(result, arguments))
                return dict(compensation_args(result))
            except Exception as e:
                logger.warning(
                    f"[Saga] Failed to resolve compensation_args for '{tool_name}': {e}"
                )
                return {}
        if isinstance(compensation_args, dict):
            resolved = cls._resolve_template_value(compensation_args, result, arguments)
            return resolved if isinstance(resolved, dict) else {}
        return {}

    def record_forward_execution(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        result: Any,
        compensates_with: Optional[str] = None,
        compensation_args: Optional[Any] = None,
        on_rollback: Optional[Callable] = None,
    ) -> Optional[SagaStep]:
        """
        Record a successful write action and register its compensation step.
        """
        if not (compensates_with or on_rollback):
            # No compensation registered for this tool
            return None

        resolved_args = self.resolve_compensation_args(
            compensation_args=compensation_args,
            result=result,
            arguments=arguments,
            tool_name=tool_name,
        )

        with self._lock:
            step_id = f"saga_{int(time.time()*1000)}_{len(self._stack) + 1}"
            step = SagaStep(
                step_id=step_id,
                forward_tool=tool_name,
                forward_args=dict(arguments),
                forward_result=result,
                compensating_tool=compensates_with,
                compensation_args=resolved_args,
                on_rollback=on_rollback,
            )
            self._stack.append(step)
        logger.info(f"[Saga] Registered compensation step '{step_id}' for '{tool_name}'")
        return step

    @classmethod
    def _has_unresolved_result_template(cls, value: Any) -> bool:
        if isinstance(value, dict):
            return any(cls._has_unresolved_result_template(v) for v in value.values())
        if isinstance(value, list):
            return any(cls._has_unresolved_result_template(v) for v in value)
        if isinstance(value, str):
            return any(m.group(1) == "result" for m in cls._TEMPLATE_PATTERN.finditer(value))
        return False

    def _drain_stack(self) -> List[SagaStep]:
        with self._lock:
            steps: List[SagaStep] = []
            if self._in_flight:
                for entry in reversed(list(self._in_flight.values())):
                    comp_tool = entry.get("compensating_tool")
                    comp_tpl = entry.get("compensation_args")
                    fwd_args = dict(entry.get("forward_args") or {})
                    if not comp_tool and self.registry is not None:
                        td = self.registry.get(entry.get("tool_name", ""))
                        if td is not None:
                            comp_tool = getattr(td, "compensates_with", None)
                            comp_tpl = getattr(td, "compensation_args", None)
                    unresolved = bool(comp_tpl is not None and self._has_unresolved_result_template(comp_tpl))
                    resolved_comp_args = (
                        self.resolve_compensation_args(comp_tpl, {}, fwd_args)
                        if comp_tool and not unresolved
                        else None
                    )
                    step = SagaStep(
                        step_id=str(entry.get("wal_id") or "wal_inflight"),
                        forward_tool=str(entry.get("tool_name") or ""),
                        forward_args=fwd_args,
                        forward_result=None,
                        compensating_tool=comp_tool,
                        compensation_args=resolved_comp_args,
                        status="IN_FLIGHT_UNRESOLVED" if (not comp_tool or unresolved) else "IN_FLIGHT",
                    )
                    setattr(
                        step,
                        "_unresolved_reason",
                        (
                            f"Interrupted mid-flight on '{step.forward_tool}' before forward response; "
                            + (
                                "cannot resolve {result.*} compensation template."
                                if unresolved
                                else "no compensating_tool declared."
                            )
                        )
                        if (not comp_tool or unresolved)
                        else "",
                    )
                    steps.append(step)
                self._in_flight.clear()

            if self._stack:
                steps.extend(reversed(self._stack))
                self._stack.clear()
            return steps

    def _resolve_comp_tool(self, step: SagaStep, gate: Optional[Any]) -> Any:
        target_reg = (
            self.registry
            if self.registry is not None
            else (getattr(gate, "registry", None) if gate else None)
        )
        if target_reg is None:
            from gatekeep.registry import ToolRegistry

            target_reg = ToolRegistry.instance()

        comp_tool_def = target_reg.get(step.compensating_tool)
        if comp_tool_def is None:
            raise RuntimeError(
                f"Compensating tool '{step.compensating_tool}' is not registered."
            )
        return comp_tool_def

    def _record_step_outcome(
        self,
        step: SagaStep,
        gate: Optional[Any],
        t0: float,
        step_success: bool,
        error_msg: str,
        details: List[Dict[str, Any]],
    ) -> None:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        step.status = "COMPENSATED" if step_success else "FAILED"
        with self._lock:
            self._history.append(step)

        action_name = step.compensating_tool or f"{step.forward_tool}:on_rollback"
        details.append(
            {
                "step_id": step.step_id,
                "forward_tool": step.forward_tool,
                "action": action_name,
                "success": step_success,
                "elapsed_ms": elapsed_ms,
                "error": error_msg or None,
            }
        )

        if gate is not None and hasattr(gate, "_record_receipt"):
            try:
                from gatekeep.gate import Verdict

                gate._record_receipt(
                    tool_name=action_name,
                    args=step.compensation_args or {},
                    verdict=Verdict.ROLLBACK,
                    rule_triggered="saga_compensation_rollback",
                    reason=f"Compensated forward action '{step.forward_tool}'. Status: {'OK' if step_success else error_msg}",
                    latency_ms=elapsed_ms,
                )
            except Exception:
                pass

    def rollback(
        self,
        gate: Optional[Any] = None,
        stop_on_error: bool = False,
    ) -> RollbackSummary:
        """
        Roll back all uncommitted forward actions in reverse LIFO order.
        Executes either `on_rollback` callable or `compensating_tool` via registry.
        """
        steps_to_rollback = self._drain_stack()
        if not steps_to_rollback:
            return RollbackSummary(
                success=True, total_steps=0, compensated_steps=0, failed_steps=0, details=[]
            )

        compensated = 0
        failed = 0
        details: List[Dict[str, Any]] = []

        for step in steps_to_rollback:
            t0 = time.perf_counter()
            step_success = False
            error_msg = ""
            try:
                unresolved_msg = getattr(step, "_unresolved_reason", "")
                if unresolved_msg:
                    raise RuntimeError(unresolved_msg)
                if callable(step.on_rollback):
                    sig = inspect.signature(step.on_rollback)
                    if len(sig.parameters) >= 2:
                        step.on_rollback(step.forward_result, step.forward_args)
                    else:
                        step.on_rollback(step.forward_result)
                    step_success = True
                elif step.compensating_tool:
                    comp_tool_def = self._resolve_comp_tool(step, gate)
                    c_args = step.compensation_args or {}
                    comp_tool_def.fn(**c_args)
                    step_success = True
            except Exception as e:
                step_success = False
                error_msg = str(e)
                logger.error(
                    f"[Saga] Failed to execute compensation for '{step.forward_tool}': {e}"
                )

            if step_success:
                compensated += 1
            else:
                failed += 1
            self._record_step_outcome(step, gate, t0, step_success, error_msg, details)

            if not step_success and stop_on_error:
                break

        return RollbackSummary(
            success=(failed == 0),
            total_steps=len(steps_to_rollback),
            compensated_steps=compensated,
            failed_steps=failed,
            details=details,
        )

    async def arollback(
        self,
        gate: Optional[Any] = None,
        stop_on_error: bool = False,
    ) -> RollbackSummary:
        """Async variant of `rollback()` supporting async compensating tools & callbacks."""
        steps_to_rollback = self._drain_stack()
        if not steps_to_rollback:
            return RollbackSummary(
                success=True, total_steps=0, compensated_steps=0, failed_steps=0, details=[]
            )

        compensated = 0
        failed = 0
        details: List[Dict[str, Any]] = []

        for step in steps_to_rollback:
            t0 = time.perf_counter()
            step_success = False
            error_msg = ""
            try:
                unresolved_msg = getattr(step, "_unresolved_reason", "")
                if unresolved_msg:
                    raise RuntimeError(unresolved_msg)
                if callable(step.on_rollback):
                    sig = inspect.signature(step.on_rollback)
                    if len(sig.parameters) >= 2:
                        res = step.on_rollback(step.forward_result, step.forward_args)
                    else:
                        res = step.on_rollback(step.forward_result)
                    if inspect.isawaitable(res):
                        await res
                    step_success = True
                elif step.compensating_tool:
                    comp_tool_def = self._resolve_comp_tool(step, gate)
                    c_args = step.compensation_args or {}
                    afn = getattr(comp_tool_def, "afn", None) or getattr(
                        comp_tool_def.fn, "afn", None
                    )
                    if callable(afn):
                        res = afn(**c_args)
                    else:
                        res = comp_tool_def.fn(**c_args)
                    if inspect.isawaitable(res):
                        await res
                    step_success = True
            except Exception as e:
                step_success = False
                error_msg = str(e)
                logger.error(
                    f"[Saga] Failed to execute async compensation for '{step.forward_tool}': {e}"
                )

            if step_success:
                compensated += 1
            else:
                failed += 1
            self._record_step_outcome(step, gate, t0, step_success, error_msg, details)

            if not step_success and stop_on_error:
                break

        return RollbackSummary(
            success=(failed == 0),
            total_steps=len(steps_to_rollback),
            compensated_steps=compensated,
            failed_steps=failed,
            details=details,
        )

    def commit(self) -> None:
        """
        Commit the transaction: clears pending compensations when a multi-step
        workflow completes successfully.
        """
        with self._lock:
            for step in self._stack:
                step.status = "COMMITTED"
                self._history.append(step)
            self._stack.clear()

    def clear(self) -> None:
        """Discard pending compensations without executing them."""
        with self._lock:
            self._stack.clear()
            self._in_flight.clear()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize pending stack, WAL in-flight entries, idempotency cache, and history."""
        with self._lock:
            out: Dict[str, Any] = {
                "stack": [step.to_dict() for step in self._stack],
                "history": [step.to_dict() for step in self._history],
            }
            if self._in_flight:
                out["in_flight"] = {k: dict(v) for k, v in self._in_flight.items()}
            if self._idempotency_cache:
                out["idempotency_cache"] = {k: dict(v) for k, v in self._idempotency_cache.items()}
            return out

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        registry: Optional[Any] = None,
    ) -> "SagaCoordinator":
        """Reconstruct a SagaCoordinator from serialized state, re-attaching registry hooks."""
        coord = cls(registry=registry)
        raw_stack = data.get("stack", [])
        if isinstance(raw_stack, list):
            coord._stack = [
                SagaStep.from_dict(s, registry=registry) if isinstance(s, dict) else s
                for s in raw_stack
            ]
        raw_history = data.get("history", [])
        if isinstance(raw_history, list):
            coord._history = [
                SagaStep.from_dict(s, registry=registry) if isinstance(s, dict) else s
                for s in raw_history
            ]
        raw_in_flight = data.get("in_flight")
        if isinstance(raw_in_flight, dict):
            coord._in_flight = {str(k): dict(v) for k, v in raw_in_flight.items() if isinstance(v, dict)}
        raw_idem = data.get("idempotency_cache")
        if isinstance(raw_idem, dict):
            coord._idempotency_cache = {str(k): dict(v) for k, v in raw_idem.items() if isinstance(v, dict)}
        return coord
