"""
gatekeep/ledger.py

ToolReturnLedger — Schema-Anchored Session State & Provenance Ledger.

Implements the core state-tracking primitives from LedgerAgent (arXiv:2606.20529)
extended with automatic entity provenance (taint tracking) and progressive tool
unlocking:
  1. Observe-Not-Assume: Only READ tool outputs update ground-truth entity state.
  2. Canonical Path Indexing: Stores both latest entity fields (`order.total`) and
     ID-keyed paths (`orders.W100.total`).
  3. Provenance / Anti-Hallucination Tracking: Records every scalar ID/value seen
     in user prompts and READ tool outputs so WRITE tools cannot be called with
     hallucinated identifiers.
  4. Progressive Tool Unlocking: Determines which WRITE tools have their
     prerequisite state satisfied before the LLM even sees the tool schemas.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union


_READ_VERBS = {
    "get", "fetch", "read", "list", "search", "find", "lookup", "check",
    "query", "view", "inspect", "show", "describe", "retrieve", "verify",
}

_WRITE_VERBS = {
    "create", "update", "delete", "remove", "send", "post", "grant", "revoke",
    "transfer", "pay", "refund", "cancel", "drop", "wipe", "modify", "set",
    "add", "insert", "execute", "run", "trigger", "unlock", "lock", "book",
    "purchase", "buy", "sell", "upload", "share", "invite", "reset", "reply",
    "forward", "archive", "publish", "submit", "approve", "reject", "edit",
    "write", "patch", "save", "move", "rename", "copy", "append", "overwrite",
}

_WRITE_VERB_SYNONYMS: Dict[str, Set[str]] = {
    "edit": {
        "modify", "update", "change", "fix", "patch", "write", "save",
        "alter", "revise", "bump", "raise", "increase", "decrease", "lower",
        "adjust", "replace", "refactor",
    },
    "update": {"modify", "edit", "change", "fix", "patch", "save", "refresh"},
    "modify": {"edit", "update", "change", "fix", "patch"},
    "write": {"save", "edit", "create", "update", "store", "put"},
    "create": {"add", "make", "new", "generate", "open", "build"},
    "add": {"create", "append", "insert", "attach"},
    "delete": {"remove", "drop", "erase", "purge", "wipe", "clean"},
    "remove": {"delete", "drop", "erase", "unlink"},
    "refund": {"reimburse", "credit", "return"},
    "cancel": {"abort", "stop", "void", "revoke"},
    "send": {"notify", "reply", "forward", "message", "email", "mail"},
    "post": {"send", "publish", "share", "submit"},
}


_MUTATING_INTENT_EXTRA_VERBS = {
    "configure", "downgrade", "upgrade", "enable", "disable", "deploy",
    "issue", "process", "provision", "attach", "detach", "rotate",
    "assign", "allocate", "remediate", "mitigate", "schedule", "scale",
    "restart", "reboot", "migrate", "restore", "revert", "rollback",
    "wire", "charge", "deposit", "withdraw", "authorize", "merge",
}

_AMBIGUOUS_NON_MUTATING_WORDS = {"return"}

_ALL_MUTATING_INTENT_WORDS: Set[str] = (set(_WRITE_VERBS) | _MUTATING_INTENT_EXTRA_VERBS) - _AMBIGUOUS_NON_MUTATING_WORDS
for _syns in _WRITE_VERB_SYNONYMS.values():
    _ALL_MUTATING_INTENT_WORDS.update(s for s in _syns if s not in _AMBIGUOUS_NON_MUTATING_WORDS)


def _matches_verb_inflection(word: str, verb: str) -> bool:
    """Match base verb and standard English verb inflections without false-matching nouns like 'sender'."""
    if word == verb:
        return True
    stem = verb[:-1] if verb.endswith("e") and len(verb) >= 4 else verb
    return word in {
        f"{verb}s",
        f"{verb}es",
        f"{verb}ed",
        f"{verb}d",
        f"{verb}ing",
        f"{stem}ed",
        f"{stem}ing",
    }


def _extract_targets_from_text(text: str) -> Set[str]:
    """Extract candidate file paths, emails, URLs, and IDs mentioned inside untrusted text."""
    targets: Set[str] = set()
    if not text:
        return targets
    patterns = (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        r"https?://[^\s<>\"')]+",
        r"(?:[A-Za-z]:)?[A-Za-z0-9_.\-]+(?:[/\\][A-Za-z0-9_.\-]+)+",
        r"(?<![A-Za-z0-9_])[A-Za-z0-9_.\-]+\.(?:json|ya?ml|env|py|ts|js|md|txt|toml|ini|cfg|conf|sql|sh|tf|csv)\b",
        r"(?<![A-Za-z0-9_])\.env(?:\.[A-Za-z0-9_\-]+)?\b",
        r"\b[A-Z]{2,10}-\d{2,10}\b",
    )
    for pat in patterns:
        for m in re.findall(pat, text):
            cleaned = str(m).strip(".,;:!?\"'()[]{}")
            if cleaned:
                targets.add(cleaned)
    return targets


def _provenance_variants(s_val: str) -> List[str]:
    """Generate canonical provenance comparison variants without losing identity precision."""
    variants: List[str] = []

    def _add(item: str) -> None:
        if item and item not in variants:
            variants.append(item)

    _add(s_val)
    _add(s_val.lower())
    if "\\" in s_val or "/" in s_val:
        norm_path = s_val.replace("\\", "/")
        if norm_path.startswith("./"):
            norm_path = norm_path[2:]
        _add(norm_path)
        _add(norm_path.lower())
    if re.fullmatch(r"-?\d+(?:\.\d+)?", s_val):
        try:
            num = float(s_val)
            if num.is_integer():
                _add(str(int(num)))
            else:
                _add(str(num))
        except Exception:
            pass
    return variants


def _tokenize_tool_name(tool_name: str) -> List[str]:
    """Split snake_case, kebab-case, and CamelCase tool names into lowercase tokens."""
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", tool_name)
    camel_split = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", camel_split)
    return [p for p in re.split(r"[_\-\s]+", camel_split.lower()) if p]


def infer_tool_mode(tool_name: str, explicit_mode: Optional[str] = None) -> str:
    """
    Infer 'read', 'write', or 'unknown' mode.
    Only explicit declarations or unambiguous verb patterns map to 'read' or 'write'.
    Unrecognized tools default to 'unknown' rather than 'write' to prevent false blocking.
    """
    if explicit_mode:
        norm = explicit_mode.strip().lower()
        if norm in ("read", "query", "observe"):
            return "read"
        if norm in ("write", "action", "mutate", "destructive"):
            return "write"
    parts = _tokenize_tool_name(tool_name)
    if not parts:
        return "unknown"
    if parts[0] in _READ_VERBS:
        return "read"
    if any(p in _WRITE_VERBS for p in parts):
        return "write"
    if any(p in _READ_VERBS for p in parts):
        return "read"
    return "unknown"


def _singularize_noun(token: str) -> str:
    """Convert common plural entity tokens ('files', 'directories', 'orders') to singular form."""
    if len(token) > 4 and token.endswith("ies"):
        return token[:-3] + "y"
    if len(token) > 3 and token.endswith("s") and not token.endswith(("ss", "us")):
        return token[:-1]
    return token


def extract_entity_namespaces(tool_name: str, provides: Optional[List[str]] = None) -> List[str]:
    """Derive canonical entity namespace(s) from a tool name or explicit provides list."""
    namespaces: List[str] = []
    if provides:
        for p in provides:
            clean = p.strip().lower()
            if clean and clean not in namespaces:
                namespaces.append(clean)
    parts = _tokenize_tool_name(tool_name)
    if len(parts) > 1 and parts[0] in _READ_VERBS:
        remainder = "_".join(parts[1:])
        if remainder not in namespaces:
            namespaces.append(remainder)
        for tok in parts[1:]:
            if tok in _READ_VERBS or tok in _WRITE_VERBS:
                continue
            singular = _singularize_noun(tok)
            if singular and singular not in namespaces:
                namespaces.append(singular)
    elif len(parts) > 1 and parts[0] not in _WRITE_VERBS:
        # Leading service/namespace token (e.g. AmazonGetProductDetails -> 'amazon')
        service_prefix = parts[0]
        if service_prefix and service_prefix not in namespaces:
            namespaces.append(service_prefix)
        for nv in parts:
            if nv in _READ_VERBS or nv in _WRITE_VERBS:
                continue
            singular = _singularize_noun(nv)
            if singular and singular not in namespaces:
                namespaces.append(singular)
    elif parts:
        for nv in parts:
            if nv in _READ_VERBS or nv in _WRITE_VERBS:
                continue
            singular = _singularize_noun(nv)
            if singular and singular not in namespaces:
                namespaces.append(singular)
        full = "_".join(parts)
        if full not in namespaces:
            namespaces.append(full)
    return namespaces


@dataclass
class LedgerEntry:
    """Single recorded fact inside the session ledger."""
    key: str
    value: Any
    source_tool: str
    turn: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "source_tool": self.source_tool,
            "turn": self.turn,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LedgerEntry":
        return cls(
            key=str(data["key"]),
            value=data.get("value"),
            source_tool=str(data.get("source_tool", "manual")),
            turn=int(data.get("turn", 0)),
            timestamp=float(data.get("timestamp", time.time())),
        )


class ToolReturnLedger:
    """
    Stateful, schema-anchored ledger tracking observed facts and value provenance
    across multi-turn agent interactions. Thread-safe and JSON-serializable for
    persistence across stateless HTTP/worker processes.
    """

    def __init__(
        self,
        session_id: str = "default",
        on_change: Optional[Callable[[], None]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self.session_id: str = session_id
        self._turn: int = 0
        self._state: Dict[str, Any] = {}
        self._entries: Dict[str, LedgerEntry] = {}
        self._completed_read_tools: Set[str] = set()
        self._active_namespaces: Set[str] = set()
        self._active_domain: Optional[str] = None
        # Provenance map: normalized_string_value -> source ("user_prompt" | "tool:<name>")
        self._provenance: Dict[str, str] = {}
        # Structured non-text result values confirmed by READ tools & targets extracted from untrusted text
        self._trusted_result_values: Set[str] = set()
        self._tainted_targets: Set[str] = set()
        self._user_messages: List[str] = []
        self._tool_history: List[Dict[str, Any]] = []
        self._policies: List[Tuple[Optional[str], Callable[..., Any], str]] = []
        from gatekeep.saga import SagaCoordinator
        self.saga: SagaCoordinator = SagaCoordinator()
        self._registry: Optional[Any] = None
        self._policy_registry: Optional[Any] = None
        self._on_change: Optional[Callable[[], None]] = on_change

    def _notify_change(self) -> None:
        """Invoke persistence change callback outside self._lock when configured."""
        cb = self._on_change
        if cb is not None:
            cb()

    # ── Turn & User Observation ───────────────────────────────────────────────

    def advance_turn(self) -> int:
        """Increment the conversation turn counter."""
        with self._lock:
            self._turn += 1
            turn = self._turn
        self._notify_change()
        return turn

    @property
    def turn(self) -> int:
        with self._lock:
            return self._turn

    @property
    def active_domain(self) -> Optional[str]:
        with self._lock:
            return self._active_domain

    @property
    def active_namespaces(self) -> Set[str]:
        with self._lock:
            return set(self._active_namespaces)

    @property
    def completed_read_tools(self) -> Set[str]:
        with self._lock:
            return set(self._completed_read_tools)

    def observe_user_input(self, text: str) -> None:
        """
        Harvest potential identifiers, numbers, emails, and tokens from user text
        so user-supplied IDs pass provenance checks on subsequent tool calls.
        """
        if not text:
            return
        with self._lock:
            if not self._user_messages or self._user_messages[-1] != text:
                self._user_messages.append(text)
            tokens = re.findall(r"[A-Za-z0-9_.@:/\\#-]+", text)
            for tok in tokens:
                cleaned = tok.strip(".,;:!?\"'()[]{}#$@")
                if len(cleaned) >= 2 or cleaned.isdigit():
                    for var in _provenance_variants(cleaned):
                        self._provenance.setdefault(var, "user_prompt")
                        self._tainted_targets.discard(var)
            for explicit_target in _extract_targets_from_text(text):
                for var in _provenance_variants(explicit_target):
                    self._tainted_targets.discard(var)
        self._notify_change()

    # ── State Recording & Retrieval ───────────────────────────────────────────

    # Untrusted free-text fields in tool outputs that must NEVER be harvested
    # as verified entity provenance (prevents indirect prompt injection via READ payloads)
    _UNTRUSTED_TEXT_KEYS: Set[str] = {
        "body", "content", "text", "message", "html", "snippet",
        "raw_output", "response", "description", "comment", "review",
        "summary", "notes", "bio", "payload", "markdown", "transcript",
    }

    def record(self, key: str, value: Any, source_tool: str = "manual") -> None:
        """Record a typed value at a canonical path in the ledger."""
        with self._lock:
            self._state[key] = value
            self._entries[key] = LedgerEntry(
                key=key,
                value=value,
                source_tool=source_tool,
                turn=self._turn,
            )
            prefix = key.split(".")[0].lower()
            if prefix:
                self._active_namespaces.add(prefix)
            leaf_key = key.split(".")[-1].lower()
            self._harvest_provenance(
                value,
                source=f"tool:{source_tool}",
                key_hint=leaf_key,
                mark_trusted=(leaf_key not in self._UNTRUSTED_TEXT_KEYS),
            )

    def _harvest_provenance(
        self,
        value: Any,
        source: str,
        key_hint: str = "",
        *,
        mark_trusted: bool = False,
    ) -> None:
        """
        Recursively record structured scalar values in the provenance table,
        skipping untrusted free-text/prose fields where indirect prompt injections occur.
        """
        if value is None or isinstance(value, bool):
            return
        if key_hint and key_hint.lower() in self._UNTRUSTED_TEXT_KEYS:
            return
        if isinstance(value, (str, int, float)):
            s_val = str(value).strip()
            if not s_val:
                return
            # Ignore long free-text prose strings from tool outputs
            if source != "user_input" and isinstance(value, str):
                if len(s_val) > 80 or s_val.count(" ") > 4:
                    return
            for var in _provenance_variants(s_val):
                self._provenance[var] = source
                if mark_trusted:
                    self._trusted_result_values.add(var)
                    self._tainted_targets.discard(var)
        elif isinstance(value, dict):
            for k, v in value.items():
                self._harvest_provenance(v, source, key_hint=str(k), mark_trusted=mark_trusted)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                self._harvest_provenance(item, source, key_hint=key_hint, mark_trusted=mark_trusted)

    @staticmethod
    def _is_directory_listing_text(text: str) -> bool:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return bool(lines) and all(ln.startswith(("[DIR] ", "[FILE] ")) for ln in lines)

    def _harvest_untrusted_targets(
        self,
        value: Any,
        *,
        key_hint: str = "",
        force_untrusted: bool = False,
        tool_name: str = "",
    ) -> None:
        """Extract targets (paths, emails, URLs, IDs) mentioned inside untrusted external text."""
        if value is None or isinstance(value, bool):
            return
        if isinstance(value, dict):
            for k, v in value.items():
                ks = str(k).lower()
                self._harvest_untrusted_targets(
                    v,
                    key_hint=ks,
                    force_untrusted=force_untrusted or (ks in self._UNTRUSTED_TEXT_KEYS),
                    tool_name=tool_name,
                )
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self._harvest_untrusted_targets(
                    item,
                    key_hint=key_hint,
                    force_untrusted=force_untrusted,
                    tool_name=tool_name,
                )
            return
        if isinstance(value, str):
            is_top_raw_str = force_untrusted or (key_hint == "" and (len(value) > 40 or "\n" in value or " " in value))
            if not is_top_raw_str:
                return
            if "list_dir" in tool_name.lower() or "list_allowed" in tool_name.lower() or self._is_directory_listing_text(value):
                return
            for raw_tok in _extract_targets_from_text(value):
                variants = _provenance_variants(raw_tok)
                if any(
                    self._provenance.get(v) == "user_prompt" or v in self._trusted_result_values
                    for v in variants
                ):
                    continue
                # Also skip if user explicitly named the file's basename in user prompt
                base = raw_tok.replace("\\", "/").rsplit("/", 1)[-1].lower()
                user_blob = " ".join(self._user_messages).lower()
                if base and base in user_blob:
                    continue
                self._tainted_targets.update(variants)

    def absorb_tool_return(
        self,
        tool_name: str,
        args: Dict[str, Any],
        result: Any,
        mode: Optional[str] = None,
        provides: Optional[List[str]] = None,
        domain: Optional[str] = None,
        compensates_with: Optional[str] = None,
        compensation_args: Optional[Any] = None,
        on_rollback: Optional[Callable] = None,
        registry: Optional[Any] = None,
    ) -> None:
        """
        Ingest a tool's execution result into the ledger.

        Follows the Observe-Not-Assume rule:
          - READ tools update canonical entity state, unlock dependent WRITE tools,
            and register entity provenance.
          - WRITE tools are logged in execution history, and their confirmed
            return fields are recorded under `<tool_name>.*` without fabricating
            unverified read namespaces unless explicitly declared in `provides`.
        """
        with self._lock:
            pol_spec = (
                self._policy_registry.get_policy(tool_name)
                if getattr(self, "_policy_registry", None) is not None
                else None
            )
            eff_mode_hint = (pol_spec.mode if pol_spec and pol_spec.mode else None) or mode
            eff_provides = list(provides) if provides is not None else []
            if pol_spec and pol_spec.provides:
                for p_ns in pol_spec.provides:
                    if p_ns not in eff_provides:
                        eff_provides.append(p_ns)
            provides_arg = eff_provides if (provides is not None or (pol_spec and pol_spec.provides)) else None

            effective_mode = infer_tool_mode(tool_name, eff_mode_hint)
            self._tool_history.append({
                "turn": self._turn,
                "tool_name": tool_name,
                "mode": effective_mode,
                "args": dict(args) if isinstance(args, dict) else {},
                "result": result,
            })

            # Any argument passed to a successful READ tool that returned valid data
            # is also confirmed to exist
            if effective_mode == "read" and self._is_successful_result(result):
                self._completed_read_tools.add(tool_name)
                self._active_namespaces.add(tool_name.lower())
                if domain:
                    self._active_domain = domain

                namespaces = extract_entity_namespaces(tool_name, provides=provides_arg)
                for ns in namespaces:
                    self._active_namespaces.add(ns)

                # Record input arguments as confirmed provenance
                if isinstance(args, dict):
                    self._harvest_provenance(args, source=f"tool:{tool_name}")

                if isinstance(result, dict):
                    # Identify primary entity ID if present in result or args
                    entity_id = self._extract_entity_id(args, result)
                    for k, v in result.items():
                        self.record(f"{tool_name}.{k}", v, source_tool=tool_name)
                        for ns in namespaces:
                            self.record(f"{ns}.{k}", v, source_tool=tool_name)
                            if entity_id:
                                self.record(f"{ns}.{entity_id}.{k}", v, source_tool=tool_name)
                                plural_ns = ns if ns.endswith("s") else f"{ns}s"
                                self.record(f"{plural_ns}.{entity_id}.{k}", v, source_tool=tool_name)
                    if entity_id:
                        for ns in namespaces:
                            self.record(f"{ns}.id", entity_id, source_tool=tool_name)
                elif isinstance(result, list):
                    self.record(f"{tool_name}.items", result, source_tool=tool_name)
                    self.record(f"{tool_name}.count", len(result), source_tool=tool_name)
                    for ns in namespaces:
                        self.record(f"{ns}.items", result, source_tool=tool_name)
                        self.record(f"{ns}.count", len(result), source_tool=tool_name)
                        for item in result:
                            if isinstance(item, dict):
                                item_id = self._extract_entity_id({}, item)
                                for k, v in item.items():
                                    if item_id:
                                        self.record(f"{ns}.{item_id}.{k}", v, source_tool=tool_name)
                                        plural_ns = ns if ns.endswith("s") else f"{ns}s"
                                        self.record(f"{plural_ns}.{item_id}.{k}", v, source_tool=tool_name)
                    self._harvest_provenance(result, source=f"tool:{tool_name}", mark_trusted=True)
                else:
                    self.record(f"{tool_name}.value", result, source_tool=tool_name)
                    for ns in namespaces:
                        self.record(f"{ns}.value", result, source_tool=tool_name)
                self._harvest_untrusted_targets(result, tool_name=tool_name)
            else:
                # WRITE tool: only record explicit `provides` if specified
                if provides_arg and self._is_successful_result(result):
                    for ns in provides_arg:
                        clean_ns = ns.strip().lower()
                        self._active_namespaces.add(clean_ns)
                        if isinstance(result, dict):
                            for k, v in result.items():
                                self.record(f"{clean_ns}.{k}", v, source_tool=tool_name)

                # Record successful write action into Saga compensation stack
                if self._is_successful_result(result):
                    c_tool = compensates_with
                    c_args = compensation_args
                    c_hook = on_rollback
                    target_reg = registry if registry is not None else self._registry
                    if target_reg is not None and (c_tool is None and c_hook is None):
                        t_def = target_reg.get(tool_name)
                        if t_def:
                            c_tool = getattr(t_def, "compensates_with", None)
                            c_args = getattr(t_def, "compensation_args", None)
                            c_hook = getattr(t_def, "on_rollback", None)
                    if pol_spec is not None and pol_spec.compensates_with:
                        c_tool = pol_spec.compensates_with
                        if pol_spec.compensation_args is not None:
                            c_args = pol_spec.compensation_args
                    if c_tool or c_hook:
                        self.saga.record_forward_execution(
                            tool_name=tool_name,
                            arguments=args,
                            result=result,
                            compensates_with=c_tool,
                            compensation_args=c_args,
                            on_rollback=c_hook,
                        )
        self._notify_change()

    @staticmethod
    def _is_successful_result(result: Any) -> bool:
        if result is None:
            return False
        if isinstance(result, dict):
            if "error" in result and result["error"]:
                return False
            if result.get("status") in ("BLOCKED", "REVISE", "ESCALATE", "ERROR", "error", "failed"):
                return False
        return True

    @staticmethod
    def _extract_entity_id(args: Dict[str, Any], result: Dict[str, Any]) -> Optional[str]:
        for container in (result, args):
            if not isinstance(container, dict):
                continue
            for k, v in container.items():
                k_low = k.lower()
                if k_low == "id" or k_low.endswith("_id") or k_low in ("ticker", "symbol", "email", "code"):
                    if isinstance(v, (str, int)) and str(v).strip():
                        return str(v).strip()
        return None

    # ── Lookups & Predicates ──────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value from the ledger by canonical path."""
        with self._lock:
            if key in self._state:
                return self._state[key]
            # Try case-insensitive lookup
            key_low = key.lower()
            for k, v in self._state.items():
                if k.lower() == key_low:
                    return v
            return default

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            if key in self._state:
                return self._state[key]
            val = self.get(key, default=KeyError)
            if val is KeyError:
                raise KeyError(f"Key '{key}' not found in ToolReturnLedger.")
            return val

    def __contains__(self, key: str) -> bool:
        with self._lock:
            if key in self._state or key.lower() in self._active_namespaces or key in self._completed_read_tools:
                return True
            key_low = key.lower()
            return any(k.lower() == key_low or k.lower().startswith(f"{key_low}.") for k in self._state)

    def rollback(self, gate: Optional[Any] = None, stop_on_error: bool = False) -> Any:
        """
        Execute automated LIFO saga compensation rollback for all pending mutations.
        Returns a RollbackSummary with detailed step results.
        """
        return self.saga.rollback(gate=gate, stop_on_error=stop_on_error)

    def commit(self) -> None:
        """Commit the current saga transaction upon successful multi-step completion."""
        self.saga.commit()

    def state_snapshot(self) -> Dict[str, Any]:
        """Return a shallow copy of the current ledger state."""
        with self._lock:
            return dict(self._state)

    def has_requirement(self, req: str) -> bool:
        """Check whether a required entity namespace, tool name, or state key is present."""
        with self._lock:
            req_clean = req.strip()
            req_low = req_clean.lower()
            if req_clean in self._completed_read_tools or req_low in self._completed_read_tools:
                return True
            if req_low in self._active_namespaces:
                return True
            if req_clean in self._state or req_low in self._state:
                return True
            return any(k.lower().startswith(f"{req_low}.") for k in self._state)

    def is_tool_unlocked(self, tool_def: Any) -> Tuple[bool, List[str]]:
        """
        Check if all prerequisites in `tool_def.requires` are satisfied in the ledger.
        Returns (unlocked: bool, missing_requirements: List[str]).
        """
        requires = getattr(tool_def, "requires", None) or []
        if not requires:
            return True, []
        with self._lock:
            missing = [req for req in requires if not self.has_requirement(req)]
            return len(missing) == 0, missing

    def check_provenance(
        self,
        value: Any,
        *,
        redactor: Optional[Any] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify whether a scalar argument value was genuinely observed in this session
        (either in user input or in a prior READ tool return).

        When a pseudonymizing `redactor` is supplied, hashed tags (`[REDACTED:<kind>:<hex>]`)
        stored in the redacted ledger can still be verified without storing plaintext PII.
        """
        if value is None or isinstance(value, bool):
            return True, "literal"
        s_val = str(value).strip()
        if not s_val:
            return False, None
        variants = _provenance_variants(s_val)
        with self._lock:
            for var in variants:
                if var in self._provenance:
                    return True, self._provenance[var]
            # Substring check in raw user messages as fallback
            for msg in self._user_messages:
                msg_low = msg.lower()
                for var in variants:
                    if var in msg or var.lower() in msg_low:
                        return True, "user_prompt"
            # Verify against pseudonymized PII/credential tags stored by SensitiveDataRedactor
            if redactor is not None and getattr(redactor, "pseudonymize", False):
                digest_fn = getattr(redactor, "pseudonym_digest", None)
                redact_str_fn = getattr(redactor, "redact_string", None)
                for var in variants:
                    if callable(redact_str_fn):
                        red_str = redact_str_fn(var)
                        if red_str != var and red_str in self._provenance:
                            return True, self._provenance[red_str]
                    if callable(digest_fn):
                        digest = digest_fn(var)
                        if digest:
                            suffix = f":{digest}]"
                            for prov_key, src in self._provenance.items():
                                if prov_key.startswith("[REDACTED:") and prov_key.endswith(suffix):
                                    return True, src
            return False, None

    def is_target_tainted(self, value: Any) -> Tuple[bool, Optional[str]]:
        """
        Return `(True, matched_target)` if `value` references a target first observed inside
        untrusted external text (`_UNTRUSTED_TEXT_KEYS`) and never authorized by user input
        or a structured trusted tool result field.
        """
        if value is None or isinstance(value, bool):
            return False, None
        s_val = str(value).strip()
        if not s_val:
            return False, None
        variants = _provenance_variants(s_val)
        norm_val = s_val.replace("\\", "/").lower()
        base_val = norm_val.rsplit("/", 1)[-1]
        with self._lock:
            if not self._tainted_targets:
                return False, None
            if any(
                self._provenance.get(v) == "user_prompt" or v in self._trusted_result_values
                for v in variants
            ):
                return False, None
            if base_val and "." in base_val:
                for msg in self._user_messages:
                    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(base_val)}(?![A-Za-z0-9_])", msg.lower()):
                        return False, None
            for var in variants:
                if var in self._tainted_targets:
                    return True, var
            if "/" in norm_val:
                for t in self._tainted_targets:
                    t_norm = t.replace("\\", "/").lower()
                    if norm_val.endswith("/" + t_norm) or ("/" in t_norm and t_norm.endswith("/" + norm_val)):
                        return True, t
            return False, None

    def has_mutating_user_intent(self) -> Tuple[bool, Optional[str]]:
        """
        Verify that a tainted session's user prompt expressed at least one mutating/write
        intent (as opposed to a purely read-only query like 'review/summarize/list').
        """
        with self._lock:
            if not self._completed_read_tools or not self._user_messages:
                return True, None

            user_corpus = " ".join(self._user_messages).lower()
            user_words = set(re.findall(r"\b[a-z]{3,}\b", user_corpus))
            matched = sorted(_ALL_MUTATING_INTENT_WORDS & user_words)
            if matched:
                return True, f"user_mutating_intent:{matched[0]}"
            for w in user_words:
                for intent_v in _ALL_MUTATING_INTENT_WORDS:
                    if _matches_verb_inflection(w, intent_v):
                        return True, f"user_mutating_intent:{intent_v}"
            if re.search(r"(?:^|\b(?:and|then|to|please))\s+email\b", user_corpus):
                return True, "user_mutating_intent:email"
            return False, (
                f"Read-only user prompt cannot trigger WRITE tools after external READ tool(s) "
                f"{sorted(self._completed_read_tools)}."
            )

    def is_write_intent_authorized(self, tool_name: str) -> Tuple[bool, Optional[str]]:
        """
        Check whether a mutating WRITE tool corresponds to an explicit user write intent
        after the session has already executed external READ tool(s) that could carry IPIs.
        """
        with self._lock:
            if not self._completed_read_tools or not self._user_messages:
                return True, None

            tokens = _tokenize_tool_name(tool_name)
            write_verbs_in_tool = [t for t in tokens if t in _WRITE_VERBS and len(t) >= 3]
            user_corpus = " ".join(self._user_messages).lower()
            user_words = set(re.findall(r"\b[a-z]{3,}\b", user_corpus))

            for v_tok in write_verbs_in_tool:
                if v_tok in user_words:
                    return True, f"user_write_verb:{v_tok}"
                stem = v_tok[:-1] if v_tok.endswith(("e", "s")) and len(v_tok) > 4 else v_tok
                if len(stem) >= 3 and any(w == stem or w.startswith(stem) for w in user_words):
                    return True, f"user_write_verb:{v_tok}"
                synonyms = _WRITE_VERB_SYNONYMS.get(v_tok, ())
                if synonyms and (set(synonyms) & user_words):
                    return True, f"user_write_verb:{v_tok}_synonym"

            if not write_verbs_in_tool and tokens and tokens[0] in user_words:
                return True, f"user_write_verb:{tokens[0]}"

            # Communication verbs used imperatively ("and email them", "please notify them")
            if "send" in write_verbs_in_tool and (
                {"notify", "reply", "forward", "message"} & user_words
                or re.search(r"(?:^|\b(?:and|then|to|please))\s+email\b", user_corpus)
            ):
                return True, "user_write_verb:send_alias"

            return False, (
                f"Unsolicited WRITE blocked in tainted session: '{tool_name}' "
                f"was triggered after external READ tool(s) {sorted(self._completed_read_tools)}, "
                f"but write action {write_verbs_in_tool or tokens} was not requested in the user prompt."
            )

    def is_write_authorized_zero_config(self, tool_name: str) -> Tuple[bool, Optional[str]]:
        """
        Zero-config write guard against Indirect Prompt Injection (IPI).

        When a session has already executed at least one READ tool (ingesting untrusted
        external content) and has recorded the user's prompt, a WRITE tool that has no
        explicit `requires` policy is only authorized if:
          1. Its target service/entity namespace has been observed by a prior READ tool
             in this session (blocking blind cross-domain writes), AND
          2. Its write-action verb (or stem) was explicitly requested in the user's prompt.
        """
        with self._lock:
            if not self._completed_read_tools or not self._user_messages:
                return True, None

            tool_namespaces = set(extract_entity_namespaces(tool_name))
            domain_in_state = any(
                k.lower().endswith(f".{ns}") or k.lower() == ns
                for k in self._state
                for ns in tool_namespaces
            )
            if not ((tool_namespaces & self._active_namespaces) or domain_in_state):
                return False, (
                    f"Unsolicited cross-domain WRITE blocked: '{tool_name}' targets "
                    f"unread domain {sorted(tool_namespaces)} after external READ tool(s) "
                    f"{sorted(self._completed_read_tools)}."
                )

            return self.is_write_intent_authorized(tool_name)

    # ── Custom Policy Registration ────────────────────────────────────────────

    def add_policy(
        self,
        predicate: Callable[[ str, Dict[str, Any], "ToolReturnLedger" ], Union[bool, Tuple[bool, str]]],
        description: str = "Custom ledger policy violated",
        tool_name: Optional[str] = None,
    ) -> "ToolReturnLedger":
        """
        Register a global or tool-specific policy predicate.

        Signature of predicate: `(tool_name, args, ledger) -> bool | (bool, reason_str)`
        """
        with self._lock:
            self._policies.append((tool_name, predicate, description))
        return self

    def evaluate_custom_policies(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        """Run all registered custom policies applicable to `tool_name`."""
        with self._lock:
            policies = list(self._policies)
        for target_tool, predicate, default_desc in policies:
            if target_tool is not None and target_tool != tool_name:
                continue
            res = predicate(tool_name, args, self)
            if isinstance(res, tuple):
                ok, reason = res
                if not ok:
                    return False, reason or default_desc
            elif not res:
                return False, default_desc
        return True, ""

    # ── Prompt Rendering & Context ────────────────────────────────────────────

    def render_for_prompt(self, max_keys: int = 25) -> str:
        """Render a compact, deterministic summary of observed session state for LLM injection."""
        with self._lock:
            if not self._state:
                return ""
            # Filter out redundant plural/tool-prefixed duplicates for compact display
            shown: Dict[str, Any] = {}
            for k, v in self._state.items():
                if k.split(".")[0] in self._completed_read_tools and len(self._active_namespaces) > 1:
                    continue
                shown[k] = v
                if len(shown) >= max_keys:
                    break
            if not shown:
                shown = dict(list(self._state.items())[:max_keys])
            lines = ["[OBSERVED SESSION STATE (ToolReturnLedger)]"]
            for k, v in shown.items():
                lines.append(f"  {k} = {v!r}")
            return "\n".join(lines)

    def get_retrieval_context(self) -> Dict[str, Any]:
        """Return structured context for retrieval scoring and domain locking."""
        with self._lock:
            return {
                "active_domain": self._active_domain,
                "active_namespaces": list(self._active_namespaces),
                "completed_read_tools": list(self._completed_read_tools),
                "state_keys": list(self._state.keys()),
            }

    # ── Serialization & Persistence ───────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the session ledger state (including Saga stack) to JSON-compatible dict."""
        with self._lock:
            return {
                "session_id": self.session_id,
                "turn": self._turn,
                "state": dict(self._state),
                "entries": {k: e.to_dict() for k, e in self._entries.items()},
                "completed_read_tools": sorted(self._completed_read_tools),
                "active_namespaces": sorted(self._active_namespaces),
                "active_domain": self._active_domain,
                "provenance": dict(self._provenance),
                "trusted_result_values": sorted(self._trusted_result_values),
                "tainted_targets": sorted(self._tainted_targets),
                "user_messages": list(self._user_messages),
                "tool_history": list(self._tool_history),
                "saga": self.saga.to_dict(),
            }

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        registry: Optional[Any] = None,
    ) -> "ToolReturnLedger":
        """Reconstruct a ToolReturnLedger (and Saga stack) from a dict produced by `to_dict()`."""
        ledger = cls(session_id=str(data.get("session_id", "default")))
        ledger._registry = registry
        ledger._turn = int(data.get("turn", 0))
        ledger._state = dict(data.get("state", {}))
        raw_entries = data.get("entries", {})
        if isinstance(raw_entries, dict):
            ledger._entries = {
                k: LedgerEntry.from_dict(v) if isinstance(v, dict) else v
                for k, v in raw_entries.items()
            }
        ledger._completed_read_tools = set(data.get("completed_read_tools", []))
        ledger._active_namespaces = set(data.get("active_namespaces", []))
        ledger._active_domain = data.get("active_domain")
        ledger._provenance = dict(data.get("provenance", {}))
        ledger._trusted_result_values = set(data.get("trusted_result_values", []))
        ledger._tainted_targets = set(data.get("tainted_targets", []))
        ledger._user_messages = list(data.get("user_messages", []))
        ledger._tool_history = list(data.get("tool_history", []))
        raw_saga = data.get("saga")
        if isinstance(raw_saga, dict):
            from gatekeep.saga import SagaCoordinator
            ledger.saga = SagaCoordinator.from_dict(raw_saga, registry=registry)
        elif registry is not None:
            ledger.saga.registry = registry
        return ledger

    def to_json(self) -> str:
        """Serialize the session ledger to a deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, default=str)

    @classmethod
    def from_json(
        cls,
        raw: str,
        registry: Optional[Any] = None,
    ) -> "ToolReturnLedger":
        """Reconstruct a ToolReturnLedger from a JSON string produced by `to_json()`."""
        return cls.from_dict(json.loads(raw), registry=registry)

    def clear(self) -> None:
        """Reset all session state."""
        with self._lock:
            self._turn = 0
            self._state.clear()
            self._entries.clear()
            self._completed_read_tools.clear()
            self._active_namespaces.clear()
            self._active_domain = None
            self._provenance.clear()
            self._trusted_result_values.clear()
            self._tainted_targets.clear()
            self._user_messages.clear()
            self._tool_history.clear()
            self.saga.clear()
        self._notify_change()
