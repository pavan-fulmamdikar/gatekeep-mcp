"""
gatekeep/decorator.py

The @slim_tool decorator — the only thing most library users ever touch.

Usage::

    from gatekeep import slim_tool

    @slim_tool(description="Fetch real-time stock price for a ticker symbol")
    def get_stock_price(ticker: str, currency: str = "USD") -> dict:
        ...

    @slim_tool  # description falls back to the docstring
    def send_email(to: str, subject: str, body: str) -> bool:
        \"\"\"Send an email to a recipient with a subject and body.\"\"\"
        ...
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from gatekeep.registry import ToolRegistry


def slim_tool(
    fn: Optional[Callable] = None,
    *,
    description: Optional[str] = None,
    name: Optional[str] = None,
    tags: Union[List[str], Tuple[str, ...]] = (),
    version: str = "1.0.0",
    parameters: Optional[Dict[str, Any]] = None,
    tool_type: str = "ACTION",
    risk_level: str = "LOW",
    mode: Optional[str] = None,
    provides: Optional[List[str]] = None,
    requires: Optional[List[str]] = None,
    provenance_args: Optional[List[str]] = None,
    check: Optional[Callable] = None,
    policy: Optional[str] = None,
    requires_approval: bool = False,
    compensates_with: Optional[str] = None,
    compensation_args: Optional[Any] = None,
    on_rollback: Optional[Callable] = None,
    registry: Optional[ToolRegistry] = None,
) -> Any:
    """
    Decorator that registers a function as a Gatekeep tool.

    Can be used with or without arguments::

        @slim_tool
        def my_fn(): ...

        @slim_tool(description="Override description", tags=["crm", "email"])
        def my_fn(): ...

        @slim_tool(
            description="Process refund for an order",
            mode="write",
            requires=["order"],
            provenance_args=["order_id"],
            check=lambda args, ledger: args["amount"] <= ledger.get("order.total", 0),
        )
        def refund_order(order_id: str, amount: float) -> dict: ...

    Args:
        fn:                (Positional, injected by Python when used bare.) The function.
        description:       Tool description used for semantic search. Falls back to docstring.
        name:              Override the tool name. Defaults to fn.__name__.
        tags:              Category labels.
        version:           Semver version string for this tool.
        parameters:        Manually specify the JSON Schema parameters block.
                           Auto-derived from type hints when omitted.
        tool_type:         "ACTION" or "QUERY".
        risk_level:        "LOW", "MEDIUM", "HIGH", or "CRITICAL".
        mode:              Gatekeep execution mode: "read" or "write" (auto-inferred if omitted).
        provides:          Entity namespaces populated into ToolReturnLedger when this read tool runs.
        requires:          Entity namespaces or read tool names required in the ledger before
                           this tool is unlocked (Progressive Tool Unlocking).
        provenance_args:   Parameter names whose values must exist in session provenance.
        check:             Deterministic predicate `(args, ledger) -> bool | (bool, reason)`.
        requires_approval: Require human-in-the-loop approval token before execution.

    Returns:
        The original function, unmodified — only side-effecting the registry.
    """
    # Normalise tags to tuple for hashability in ToolDefinition
    normalised_tags: Tuple[str, ...] = tuple(tags)

    def _register(func: Callable) -> Callable:
        target_registry = registry if registry is not None else ToolRegistry.instance()
        target_registry.register(
            fn=func,
            description=description,
            name=name,
            tags=normalised_tags,
            version=version,
            parameters=parameters,
            tool_type=tool_type,
            risk_level=risk_level,
            mode=mode,
            provides=provides,
            requires=requires,
            provenance_args=provenance_args,
            check=check,
            policy=policy,
            requires_approval=requires_approval,
            compensates_with=compensates_with,
            compensation_args=compensation_args,
            on_rollback=on_rollback,
        )

        # Preserve the original function perfectly — no wrapping needed.
        # The decorator is purely a registration side effect.
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        # Attach a convenience reference to the ToolDefinition
        wrapper._slim_tool = target_registry.get(name or func.__name__)
        return wrapper

    # Handle both @slim_tool and @slim_tool(...) usage patterns
    if fn is not None:
        # Used bare: @slim_tool  (fn is the decorated function)
        return _register(fn)

    # Used with args: @slim_tool(description="...")
    return _register


# Preferred alias in standalone Gatekeep package
gatekeep_tool = slim_tool
