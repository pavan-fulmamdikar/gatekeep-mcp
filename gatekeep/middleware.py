"""
gatekeep/middleware.py

GatekeepMiddleware — Drop-in Policy Enforcement & Stateful Ledger Dispatcher
for OpenAI SDK, Anthropic SDK, LangChain/LangGraph, and MCP tool handlers.

Allows developers to enforce Observe-Before-Write (`requires`), entity provenance
taint tracking (`provenance_args`), deterministic state predicates (`check`), and
SHA-256 hash-chained `AuditReceipt` logging without rewriting their agent loop
around `SlimAgent`.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import functools
import inspect
import json
from typing import Any, Callable, Dict, List, Optional, Union

from gatekeep.decorator import slim_tool
from gatekeep.gate import GateDecision, PreExecutionGate
from gatekeep.ledger import ToolReturnLedger
from gatekeep.registry import ToolRegistry


class GatekeepPolicyError(PermissionError):
    """
    Raised by `GatekeepMiddleware` when `raise_on_block=True` and a tool call
    is denied (`REVISE`, `BLOCK`, or `ESCALATE`) by `PreExecutionGate`.
    """

    def __init__(self, decision: GateDecision) -> None:
        self.decision: GateDecision = decision
        super().__init__(
            f"[{decision.verdict.value}] {decision.tool_name} "
            f"({decision.rule_triggered}): {decision.reason}"
        )


class GatekeepMiddleware:
    """
    Framework-agnostic middleware that wraps tool execution in a stateful
    `ToolReturnLedger` and `PreExecutionGate`.
    """

    def __init__(
        self,
        ledger: Optional[ToolReturnLedger] = None,
        gate: Optional[PreExecutionGate] = None,
        registry: Optional[ToolRegistry] = None,
        strict_provenance: bool = True,
        max_tool_retries: int = 3,
        audit_log_path: Optional[str] = None,
        raise_on_block: bool = False,
        session_id: str = "default",
        session_store: Optional[Any] = None,
        auto_persist: bool = True,
    ) -> None:
        self.registry: ToolRegistry = registry if registry is not None else ToolRegistry.instance()
        if gate is not None:
            self.gate: PreExecutionGate = gate
            self.ledger: ToolReturnLedger = ledger or self.gate.ledger
        elif session_store is not None and ledger is None:
            self.gate = PreExecutionGate.from_store(
                session_id=session_id,
                session_store=session_store,
                registry=self.registry,
                strict_provenance=strict_provenance,
                max_tool_retries=max_tool_retries,
                audit_log_path=audit_log_path,
                auto_persist=auto_persist,
            )
            self.ledger = self.gate.ledger
        else:
            self.ledger = ledger or ToolReturnLedger(session_id=session_id)
            self.gate = PreExecutionGate(
                ledger=self.ledger,
                registry=self.registry,
                strict_provenance=strict_provenance,
                max_tool_retries=max_tool_retries,
                audit_log_path=audit_log_path,
                session_store=session_store,
                auto_persist=auto_persist,
            )
        self.raise_on_block: bool = raise_on_block

    def rollback(self, stop_on_error: bool = False) -> Any:
        """Execute LIFO Saga rollback of pending mutations for the current session."""
        return self.gate.rollback(stop_on_error=stop_on_error)

    def commit(self) -> None:
        """Commit pending Saga mutations when multi-step workflow finishes cleanly."""
        self.gate.commit()

    def observe_user(self, text: str, advance_turn: bool = True) -> None:
        """Record a user prompt into the session ledger to harvest valid user-supplied IDs."""
        if advance_turn:
            self.ledger.advance_turn()
        self.ledger.observe_user_input(text)

    @staticmethod
    def _run_coroutine_sync(coro: Any) -> Any:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is None:
            return asyncio.run(coro)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()

    def dispatch(
        self,
        tool_name: str,
        arguments: Optional[Union[Dict[str, Any], str]] = None,
        approval_token: Optional[str] = None,
    ) -> Any:
        """
        Synchronously evaluate `tool_name(**arguments)` through `PreExecutionGate`,
        execute if allowed, and absorb the result into `ToolReturnLedger`.
        """
        args = self._coerce_args(arguments)
        decision = self.gate.evaluate(
            tool_name=tool_name,
            arguments=args,
            approval_token=approval_token,
        )
        if not decision.allowed:
            if self.raise_on_block:
                raise GatekeepPolicyError(decision)
            return decision.to_tool_message()

        tool_def = self.registry.get(tool_name)
        if tool_def is None:
            return decision.to_tool_message()

        result = tool_def.fn(**args)
        if inspect.isawaitable(result):
            result = self._run_coroutine_sync(result)

        self.ledger.absorb_tool_return(
            tool_name=tool_name,
            args=args,
            result=result,
            mode=getattr(tool_def, "mode", None),
            provides=getattr(tool_def, "provides", None),
        )
        return result

    async def adispatch(
        self,
        tool_name: str,
        arguments: Optional[Union[Dict[str, Any], str]] = None,
        approval_token: Optional[str] = None,
    ) -> Any:
        """
        Asynchronously evaluate `tool_name(**arguments)` through `PreExecutionGate.aevaluate()`,
        execute if allowed, and absorb the result into `ToolReturnLedger`.
        """
        args = self._coerce_args(arguments)
        decision = await self.gate.aevaluate(
            tool_name=tool_name,
            arguments=args,
            approval_token=approval_token,
        )
        if not decision.allowed:
            if self.raise_on_block:
                raise GatekeepPolicyError(decision)
            return decision.to_tool_message()

        tool_def = self.registry.get(tool_name)
        if tool_def is None:
            return decision.to_tool_message()

        result = tool_def.fn(**args)
        if inspect.isawaitable(result):
            result = await result

        self.ledger.absorb_tool_return(
            tool_name=tool_name,
            args=args,
            result=result,
            mode=getattr(tool_def, "mode", None),
            provides=getattr(tool_def, "provides", None),
        )
        return result

    def wrap(
        self,
        fn: Optional[Callable[..., Any]] = None,
        **slim_tool_kwargs: Any,
    ) -> Callable[..., Any]:
        """
        Decorator/wrapper that turns any synchronous or async Python function
        into a Gatekeep-protected callable.

        Can be used as `@mw.wrap` or `@mw.wrap(mode="write", requires=["order"])`.
        """
        def _decorator(target_fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = slim_tool_kwargs.get("name") or getattr(target_fn, "_slim_name", None) or target_fn.__name__
            if self.registry.get(tool_name) is None:
                reg_kwargs = dict(slim_tool_kwargs)
                reg_kwargs.setdefault("description", inspect.getdoc(target_fn) or f"Execute {tool_name}")
                reg_kwargs["registry"] = self.registry
                slim_tool(**reg_kwargs)(target_fn)

            sig = inspect.signature(target_fn)

            if inspect.iscoroutinefunction(target_fn):
                @functools.wraps(target_fn)
                async def _async_wrapped(*args: Any, **kwargs: Any) -> Any:
                    bound = sig.bind_partial(*args, **kwargs)
                    bound.apply_defaults()
                    return await self.adispatch(tool_name, dict(bound.arguments))

                return _async_wrapped

            @functools.wraps(target_fn)
            def _sync_wrapped(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                return self.dispatch(tool_name, dict(bound.arguments))

            return _sync_wrapped

        if fn is not None:
            return _decorator(fn)
        return _decorator

    # ── OpenAI & Anthropic Batch Helpers ──────────────────────────────────────

    def handle_openai_tool_calls(
        self,
        tool_calls: List[Any],
    ) -> List[Dict[str, Any]]:
        """
        Process a list of OpenAI `tool_calls` (dicts or SDK objects) through Gatekeep
        and return ready-to-append `{"role": "tool", ...}` message dicts.
        """
        messages: List[Dict[str, Any]] = []
        for tc in tool_calls:
            call_dict = tc.model_dump() if hasattr(tc, "model_dump") else dict(tc)
            call_id = call_dict.get("id", "")
            fn_block = call_dict.get("function", {})
            name = fn_block.get("name", "")
            raw_args = fn_block.get("arguments", "{}")
            result = self.dispatch(name, raw_args)
            messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": json.dumps(result),
            })
        return messages

    async def ahandle_openai_tool_calls(
        self,
        tool_calls: List[Any],
    ) -> List[Dict[str, Any]]:
        """Async counterpart to `handle_openai_tool_calls`."""
        messages: List[Dict[str, Any]] = []
        for tc in tool_calls:
            call_dict = tc.model_dump() if hasattr(tc, "model_dump") else dict(tc)
            call_id = call_dict.get("id", "")
            fn_block = call_dict.get("function", {})
            name = fn_block.get("name", "")
            raw_args = fn_block.get("arguments", "{}")
            result = await self.adispatch(name, raw_args)
            messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": json.dumps(result),
            })
        return messages

    def handle_anthropic_tool_uses(
        self,
        content_blocks: List[Any],
    ) -> Dict[str, Any]:
        """
        Process Anthropic `content` blocks, execute any `tool_use` blocks through
        Gatekeep, and return a `{"role": "user", "content": [...]}` tool_result message.
        """
        results: List[Dict[str, Any]] = []
        for block in content_blocks:
            b_dict = block.model_dump() if hasattr(block, "model_dump") else (
                dict(block) if isinstance(block, dict) else {}
            )
            if b_dict.get("type") != "tool_use":
                continue
            use_id = b_dict.get("id", "")
            name = b_dict.get("name", "")
            inp = b_dict.get("input", {})
            result = self.dispatch(name, inp)
            results.append({
                "type": "tool_result",
                "tool_use_id": use_id,
                "content": json.dumps(result),
            })
        return {"role": "user", "content": results}

    async def ahandle_anthropic_tool_uses(
        self,
        content_blocks: List[Any],
    ) -> Dict[str, Any]:
        """Async counterpart to `handle_anthropic_tool_uses`."""
        results: List[Dict[str, Any]] = []
        for block in content_blocks:
            b_dict = block.model_dump() if hasattr(block, "model_dump") else (
                dict(block) if isinstance(block, dict) else {}
            )
            if b_dict.get("type") != "tool_use":
                continue
            use_id = b_dict.get("id", "")
            name = b_dict.get("name", "")
            inp = b_dict.get("input", {})
            result = await self.adispatch(name, inp)
            results.append({
                "type": "tool_result",
                "tool_use_id": use_id,
                "content": json.dumps(result),
            })
        return {"role": "user", "content": results}

    # ── Session Persistence ───────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialize both the session `ToolReturnLedger` and `PreExecutionGate` state."""
        return {
            "ledger": self.ledger.to_dict(),
            "gate": self.gate.to_dict(),
        }

    def restore_state(self, data: Dict[str, Any]) -> "GatekeepMiddleware":
        """Restore both `ToolReturnLedger` and `PreExecutionGate` state in-place."""
        if "ledger" in data and isinstance(data["ledger"], dict):
            restored_ledger = ToolReturnLedger.from_dict(data["ledger"])
            # Preserve any registered custom policy callables on current ledger
            restored_ledger._policies = list(self.ledger._policies)
            self.ledger = restored_ledger
            self.gate.ledger = restored_ledger
        if "gate" in data and isinstance(data["gate"], dict):
            self.gate.restore_state(data["gate"])
        return self

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str)

    @staticmethod
    def _coerce_args(arguments: Optional[Union[Dict[str, Any], str]]) -> Dict[str, Any]:
        if arguments is None:
            return {}
        if isinstance(arguments, str):
            return json.loads(arguments) if arguments.strip() else {}
        if isinstance(arguments, dict):
            return dict(arguments)
        return {}
