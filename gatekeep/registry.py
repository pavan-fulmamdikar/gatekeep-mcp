"""
gatekeep/registry.py

ToolDefinition  — immutable record describing one registered tool.
ToolRegistry    — process-wide singleton that stores all @slim_tool entries.

The registry is intentionally decoupled from the vector store.
It holds the ground-truth metadata; the indexer writes it into whatever
backend is configured.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, get_type_hints


# ── JSON-schema type mapping ──────────────────────────────────────────────────

_PY_TO_JSON: Dict[Any, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
    List: "array",
    Dict: "object",
}


def _py_type_to_json(annotation: Any) -> str:
    """Convert a Python type annotation to a JSON Schema type string."""
    origin = getattr(annotation, "__origin__", None)
    if origin is list:
        return "array"
    if origin is dict:
        return "object"
    return _PY_TO_JSON.get(annotation, "string")


def _build_json_schema(fn: Callable) -> Dict[str, Any]:
    """
    Auto-derive a JSON Schema 'parameters' block from a function's signature
    and type hints, compatible with the OpenAI / Anthropic tool-calling format.
    """
    try:
        hints = get_type_hints(fn)
    except Exception:
        hints = {}

    sig = inspect.signature(fn)
    properties: Dict[str, Any] = {}
    required: List[str] = []

    for name, param in sig.parameters.items():
        if name == "self":
            continue

        annotation = hints.get(name, str)
        json_type = _py_type_to_json(annotation)

        prop: Dict[str, Any] = {"type": json_type}

        # Pull inline description from default if it's a string sentinel
        # (advanced usage — most users just rely on the docstring)
        if param.default is inspect.Parameter.empty:
            required.append(name)
        else:
            prop["default"] = param.default

        properties[name] = prop

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


# ── ToolDefinition ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ToolDefinition:
    """
    Immutable record for one registered tool.

    Attributes:
        name:           Function name used as the tool identifier.
        description:    Human-readable (and embedding-friendly) description.
        parameters:     JSON Schema dict for the tool's parameters.
        fn:             Reference to the original callable.
        tags:           Optional list of category tags (used for future filtering).
        version:        Optional semver string for multi-version tool management.
        synthetic_queries: Optional list of queries to help improve retrieval.
    """

    name: str
    description: str
    parameters: Dict[str, Any]
    fn: Callable
    tags: List[str] = field(default_factory=list)
    version: Optional[str] = None
    synthetic_queries: List[str] = field(default_factory=list)
    tool_type: str = "ACTION"
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    mode: Optional[str] = None  # "read" | "write" (auto-inferred if None)
    provides: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    provenance_args: Optional[List[str]] = None
    check: Optional[Callable] = None
    policy: Optional[str] = None
    requires_approval: bool = False
    compensates_with: Optional[str] = None
    compensation_args: Optional[Any] = None
    on_rollback: Optional[Callable] = None

    def to_llm_schema(self) -> Dict[str, Any]:
        """
        Return the tool in the format expected by OpenAI / Anthropic APIs.

        OpenAI format::

            {
                "type": "function",
                "function": {
                    "name": "...",
                    "description": "...",
                    "parameters": { ... }
                }
            }
        """
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_anthropic_schema(self) -> Dict[str, Any]:
        """
        Return the tool in Anthropic's tool format::

            {
                "name": "...",
                "description": "...",
                "input_schema": { ... }
            }
        """
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }

    def __repr__(self) -> str:
        return f"ToolDefinition(name={self.name!r}, tags={self.tags})"


# ── ToolRegistry ──────────────────────────────────────────────────────────────

class ToolRegistry:
    """
    Process-wide singleton storing all @slim_tool registrations.

    Usage (direct registration — the decorator uses this internally)::

        registry = ToolRegistry.instance()
        registry.register(my_function, description="Does X")

    Most users never touch this class directly.
    """

    _instance: Optional["ToolRegistry"] = None

    def __init__(self) -> None:
        self._tools: Dict[str, ToolDefinition] = {}

    @classmethod
    def instance(cls) -> "ToolRegistry":
        """Return the global singleton, creating it on first call."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """
        Wipe the global singleton.
        Useful in tests to start from a clean state.
        """
        cls._instance = None

    def register(
        self,
        fn: Callable,
        description: Optional[str] = None,
        name: Optional[str] = None,
        tags: tuple = (),
        version: str = "1.0.0",
        parameters: Optional[Dict[str, Any]] = None,
        synthetic_queries: Optional[List[str]] = None,
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
    ) -> ToolDefinition:
        """
        Register a callable as a Gatekeep tool.

        Args:
            fn:           The function to register.
            description:  Override description (falls back to docstring).
            name:         Override tool name (falls back to fn.__name__).
            tags:         Category tags for future filtering.
            version:      Semver string.
            parameters:   Override auto-derived JSON schema.

        Returns:
            The created ToolDefinition.

        Raises:
            ValueError: If name is already registered.
        """
        import re as _re
        tool_name = name or fn.__name__
        tool_desc = description or (inspect.getdoc(fn) or "").strip()

        if not tool_desc:
            raise ValueError(
                f"@slim_tool on '{tool_name}' has no description. "
                "Provide one via the 'description' argument or a docstring."
            )

        # if not _re.match(r"^[a-zA-Z0-9_-]{1,64}$", tool_name):
        #     raise ValueError(
        #         f"Tool name '{tool_name}' is invalid. "
        #         "Must be 1-64 characters, only letters, digits, underscores, hyphens. "
        #         "Both OpenAI and Anthropic reject names outside this pattern."
        #     )

        if tool_name in self._tools:
            raise ValueError(
                f"Tool '{tool_name}' is already registered. "
                "Use a unique function name or pass name='...' to override."
            )

        schema = parameters if parameters is not None else _build_json_schema(fn)

        if synthetic_queries is None:
            safe_desc = tool_desc.split(".")[0].strip() if tool_desc else tool_name
            synthetic_queries = [
                f"How do I use {tool_name}?",
                f"I need to {safe_desc}.",
                f"Execute the {tool_name} tool."
            ]

        definition = ToolDefinition(
            name=tool_name,
            description=tool_desc,
            parameters=schema,
            fn=fn,
            tags=list(tags) if isinstance(tags, tuple) else tags,
            version=version,
            synthetic_queries=synthetic_queries,
            tool_type=tool_type,
            risk_level=risk_level,
            mode=mode,
            provides=list(provides) if provides else [],
            requires=list(requires) if requires else [],
            provenance_args=list(provenance_args) if provenance_args is not None else None,
            check=check,
            policy=policy,
            requires_approval=requires_approval,
            compensates_with=compensates_with,
            compensation_args=compensation_args,
            on_rollback=on_rollback,
        )

        self._tools[tool_name] = definition
        return definition

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Look up a tool by name. Returns None if not found."""
        return self._tools.get(name)

    def get_all(self) -> List[ToolDefinition]:
        """Return all registered tools as a list."""
        return list(self._tools.values())

    def names(self) -> List[str]:
        """Return all registered tool names."""
        return list(self._tools.keys())

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __repr__(self) -> str:
        return f"ToolRegistry({len(self._tools)} tools: {self.names()})"
