"""
gatekeep/mcp/onboarding.py

Deterministic starter policy generator (`gatekeep --init-policy`).
Inspects an upstream MCP server's `tools/list` catalog and emits a ready-to-edit
`CentralPolicyRegistry` JSON configuration with `mode`, `provides`, `requires`,
`provenance_args`, `requires_approval`, and matched `compensates_with` Saga pairs.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from gatekeep.ledger import (
    _tokenize_tool_name,
    extract_entity_namespaces,
    infer_tool_mode,
)

# Forward verb -> candidate inverse compensation verbs (in priority order)
_COMPENSATION_VERB_PAIRS: Dict[str, Tuple[str, ...]] = {
    "reserve": ("release", "cancel", "unreserve"),
    "hold": ("release", "cancel", "void"),
    "allocate": ("release", "deallocate", "free"),
    "lock": ("unlock", "release"),
    "create": ("delete", "remove", "destroy", "cancel", "close"),
    "add": ("remove", "delete"),
    "insert": ("delete", "remove"),
    "charge": ("refund", "void", "reverse"),
    "capture": ("refund", "void"),
    "authorize": ("void", "cancel", "revoke"),
    "debit": ("credit", "refund"),
    "enable": ("disable",),
    "activate": ("deactivate",),
    "open": ("close",),
    "start": ("stop", "cancel"),
    "book": ("cancel",),
    "assign": ("unassign", "revoke"),
    "grant": ("revoke",),
    "subscribe": ("unsubscribe",),
}

_HIGH_RISK_VERBS: Set[str] = {
    "delete",
    "destroy",
    "drop",
    "purge",
    "wipe",
    "truncate",
    "refund",
    "transfer",
    "wire",
    "payout",
    "deploy",
    "publish",
    "revoke",
    "grant",
    "terminate",
}

_SENSITIVE_ARG_KEYS: Set[str] = {
    "id",
    "to",
    "email",
    "recipient",
    "recipients",
    "cc",
    "bcc",
    "webhook",
    "webhook_url",
    "target",
    "destination",
    "account",
    "account_id",
    "user_id",
    "customer_id",
    "order_id",
    "invoice_id",
    "payment_id",
    "reservation_id",
    "ticket_id",
    "hold_id",
    "slot_id",
    "repo",
}

_REQUIRE_PRE_READ_VERBS: Set[str] = {
    "update",
    "edit",
    "modify",
    "patch",
    "refund",
    "cancel",
    "delete",
    "remove",
    "destroy",
    "drop",
    "purge",
    "wipe",
    "truncate",
    "approve",
    "reject",
    "transfer",
    "wire",
    "charge",
    "capture",
    "void",
    "revoke",
    "move",
    "rename",
    "overwrite",
}

_EXISTING_TARGET_ARG_KEYS: Set[str] = {
    "path",
    "file_path",
    "source",
}

_GENERIC_VERBS: Set[str] = set(_COMPENSATION_VERB_PAIRS.keys()) | {
    "get",
    "list",
    "read",
    "fetch",
    "find",
    "search",
    "lookup",
    "query",
    "check",
    "inspect",
    "view",
    "describe",
    "show",
    "update",
    "edit",
    "set",
    "write",
    "put",
    "post",
    "send",
    "notify",
    "execute",
    "run",
    "call",
    "release",
    "cancel",
    "delete",
    "remove",
    "destroy",
    "refund",
    "void",
    "disable",
    "deactivate",
    "close",
    "stop",
    "unlock",
    "revoke",
    "unassign",
    "unsubscribe",
}


def _schema_properties(tool_schema: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    input_schema = tool_schema.get("inputSchema") or tool_schema.get("parameters") or {}
    props = input_schema.get("properties") if isinstance(input_schema, dict) else {}
    return props if isinstance(props, dict) else {}


def _entity_nouns(tool_name: str) -> Set[str]:
    tokens = _tokenize_tool_name(tool_name)
    nouns = set(extract_entity_namespaces(tool_name))
    for tok in tokens:
        if tok not in _GENERIC_VERBS and len(tok) > 1:
            nouns.add(tok)
    return nouns


def _find_compensation_target(
    tool_name: str,
    tool_props: Dict[str, Any],
    catalog_props: Dict[str, Dict[str, Any]],
) -> Tuple[Optional[str], Dict[str, str]]:
    tokens = _tokenize_tool_name(tool_name)
    if not tokens:
        return None, {}

    forward_verbs = [t for t in tokens if t in _COMPENSATION_VERB_PAIRS]
    if not forward_verbs:
        return None, {}

    nouns = _entity_nouns(tool_name)
    for verb in forward_verbs:
        for inv_verb in _COMPENSATION_VERB_PAIRS[verb]:
            candidates: List[Tuple[int, str]] = []
            for cand_name in sorted(catalog_props.keys()):
                if cand_name == tool_name:
                    continue
                cand_tokens = _tokenize_tool_name(cand_name)
                if inv_verb not in cand_tokens:
                    continue
                cand_nouns = _entity_nouns(cand_name)
                overlap = len(nouns & cand_nouns)
                if nouns and overlap == 0:
                    continue
                candidates.append((overlap, cand_name))

            if candidates:
                candidates.sort(key=lambda item: (-item[0], item[1]))
                comp_name = candidates[0][1]
                comp_props = catalog_props.get(comp_name, {})
                comp_args: Dict[str, str] = {}
                for k in sorted(comp_props.keys()):
                    if k in tool_props:
                        comp_args[k] = f"{{args.{k}}}"
                return comp_name, comp_args

    return None, {}


def generate_starter_policy(tools: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Deterministically generate a `CentralPolicyRegistry`-compatible configuration dict
    from an upstream MCP `tools/list` catalog.
    """
    catalog_props: Dict[str, Dict[str, Any]] = {}
    modes: Dict[str, str] = {}
    provides_map: Dict[str, List[str]] = {}
    all_provided_entities: Set[str] = set()

    for raw in tools:
        name = str(raw["name"])
        catalog_props[name] = _schema_properties(raw)
        mode = infer_tool_mode(name).upper()
        if mode not in ("READ", "WRITE", "DESTRUCTIVE"):
            toks = set(_tokenize_tool_name(name))
            if toks & {"delete", "destroy", "drop", "purge", "wipe"}:
                mode = "DESTRUCTIVE"
            elif toks & set(_COMPENSATION_VERB_PAIRS.keys()) or toks & _HIGH_RISK_VERBS:
                mode = "WRITE"
        modes[name] = mode
        if mode == "READ":
            ents = sorted(extract_entity_namespaces(name) or _entity_nouns(name))
            provides_map[name] = ents
            all_provided_entities.update(ents)
        else:
            provides_map[name] = []

    policies: Dict[str, Dict[str, Any]] = {}
    for raw in tools:
        name = str(raw["name"])
        mode = modes[name]
        props = catalog_props[name]
        tokens = set(_tokenize_tool_name(name))

        requires: List[str] = []
        provenance_args: List[str] = []
        requires_approval = False
        risk_level = "LOW"
        compensates_with: Optional[str] = None
        compensation_args: Dict[str, str] = {}

        if mode != "READ":
            nouns = _entity_nouns(name)
            matching_reqs: List[str] = []
            for prop_name in props:
                if prop_name.endswith("_id"):
                    stem = prop_name[:-3]
                    if stem in all_provided_entities and stem not in matching_reqs:
                        matching_reqs.append(stem)
            if not matching_reqs and (tokens & _REQUIRE_PRE_READ_VERBS):
                matching_reqs = sorted(nouns & all_provided_entities)
            requires = matching_reqs

            is_existing_target_op = bool(tokens & _REQUIRE_PRE_READ_VERBS)
            props_low = {str(pk).lower() for pk in props.keys()}
            skip_dest_for_move = is_existing_target_op and "source" in props_low and bool(tokens & {"move", "rename", "copy"})
            provenance_args = [
                k for k in props.keys()
                if (
                    (k.lower() in _SENSITIVE_ARG_KEYS and not (skip_dest_for_move and k.lower() == "destination"))
                    or k.lower().endswith("_id")
                    or (is_existing_target_op and k.lower() in _EXISTING_TARGET_ARG_KEYS)
                )
            ]

            if tokens & _HIGH_RISK_VERBS:
                requires_approval = True
                risk_level = "CRITICAL" if (tokens & {"delete", "destroy", "drop", "purge", "wipe"}) else "HIGH"
            else:
                risk_level = "MEDIUM"

            compensates_with, compensation_args = _find_compensation_target(
                name, props, catalog_props
            )

        spec: Dict[str, Any] = {
            "tool_name": name,
            "mode": mode,
            "provides": provides_map[name],
            "requires": requires,
            "provenance_args": provenance_args,
            "requires_approval": requires_approval,
            "risk_level": risk_level,
            "enabled": True,
        }
        if compensates_with:
            spec["compensates_with"] = compensates_with
            if compensation_args:
                spec["compensation_args"] = compensation_args

        policies[name] = spec

    return {
        "version": 1,
        "generated_by": "gatekeep --init-policy",
        "tools": policies,
    }


_BOUNDED_NUMERIC_HINTS: Set[str] = {
    "amount",
    "qty",
    "quantity",
    "count",
    "limit",
    "total",
    "price",
    "rate",
    "budget",
    "days",
}


def synthesize_policies_from_store(
    session_store: Any,
    *,
    tools: Optional[Sequence[Dict[str, Any]]] = None,
    safety_multiplier: float = 2.0,
    min_precedence_ratio: float = 0.6,
) -> Dict[str, Any]:
    """
    Mine real recorded `AuditVault` receipts and `SessionStateStore` histories
    to synthesize a data-driven `CentralPolicyRegistry` configuration plus
    shadow-mode false-positive diagnostics (`--learn-from-db`).
    """
    from gatekeep.control_plane import AuditVault

    vault = AuditVault(session_store)
    receipts = vault.query(limit=5000)

    by_session: Dict[str, List[Any]] = defaultdict(list)
    observed_arg_keys: Dict[str, Set[str]] = defaultdict(set)
    tool_stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"calls": 0, "blocks": 0, "shadow_would_blocks": 0, "rules": defaultdict(int)}
    )
    numeric_peaks: Dict[str, Dict[str, float]] = defaultdict(dict)

    for r in receipts:
        if r.rule_triggered in ("mcp_resource_read", "saga_compensation_rollback"):
            continue
        by_session[r.session_id].append(r)
        st = tool_stats[r.tool_name]
        st["calls"] += 1
        if r.verdict.value in ("BLOCK", "REVISE", "ESCALATE"):
            st["blocks"] += 1
            st["rules"][r.rule_triggered] += 1
        elif r.shadow and r.would_verdict:
            st["shadow_would_blocks"] += 1
            st["rules"][f"shadow:{r.rule_triggered}"] += 1

        if isinstance(r.arguments, dict):
            for k, v in r.arguments.items():
                observed_arg_keys[r.tool_name].add(str(k))
                if (
                    r.verdict.value == "ALLOW"
                    and isinstance(v, (int, float))
                    and not isinstance(v, bool)
                    and k.lower() in _BOUNDED_NUMERIC_HINTS
                    and v >= 0
                ):
                    cur = numeric_peaks[r.tool_name].get(k)
                    if cur is None or float(v) > cur:
                        numeric_peaks[r.tool_name][k] = float(v)

    base_catalog = list(tools) if tools else [
        {
            "name": name,
            "description": "",
            "inputSchema": {
                "type": "object",
                "properties": {k: {"type": "string"} for k in sorted(observed_arg_keys[name])},
            },
        }
        for name in sorted(tool_stats.keys())
    ]
    synthesized = generate_starter_policy(base_catalog)
    policies: Dict[str, Dict[str, Any]] = synthesized["tools"]

    # Discover empirical READ -> WRITE precedence edges across sessions
    write_session_count: Dict[str, int] = defaultdict(int)
    preceded_by: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for sid, sess_receipts in by_session.items():
        sess_receipts.sort(key=lambda item: (item.turn, item.timestamp))
        seen_reads: Set[str] = set()
        seen_writes_in_sess: Set[str] = set()
        for item in sess_receipts:
            spec = policies.get(item.tool_name)
            mode = spec.get("mode", "READ") if spec else infer_tool_mode(item.tool_name).upper()
            if mode == "READ":
                ents = (spec or {}).get("provides") or sorted(
                    extract_entity_namespaces(item.tool_name) or _entity_nouns(item.tool_name)
                )
                seen_reads.update(ents)
            elif item.tool_name not in seen_writes_in_sess:
                seen_writes_in_sess.add(item.tool_name)
                write_session_count[item.tool_name] += 1
                for ent in seen_reads:
                    preceded_by[item.tool_name][ent] += 1

    for tool_name, spec in policies.items():
        if spec.get("mode") != "READ":
            total_w = write_session_count.get(tool_name, 0)
            if total_w > 0:
                learned_reqs = [
                    ent
                    for ent, cnt in sorted(preceded_by[tool_name].items())
                    if (cnt / total_w) >= min_precedence_ratio
                ]
                merged = sorted(set(spec.get("requires", [])) | set(learned_reqs))
                spec["requires"] = merged

            peaks = numeric_peaks.get(tool_name, {})
            if peaks and not spec.get("policy"):
                clauses = []
                for k, peak in sorted(peaks.items()):
                    bound = max(1, int(math.ceil(peak * safety_multiplier)))
                    clauses.append(f"{k} <= {bound}")
                spec["policy"] = " and ".join(clauses)

    diagnostics = [
        {
            "tool_name": t,
            "calls": st["calls"],
            "blocks": st["blocks"],
            "shadow_would_blocks": st["shadow_would_blocks"],
            "rules": dict(st["rules"]),
        }
        for t, st in sorted(tool_stats.items())
    ]

    return {
        "version": 1,
        "generated_by": "gatekeep --learn-from-db",
        "sessions_analyzed": len(by_session),
        "receipts_analyzed": len(receipts),
        "tools": policies,
        "diagnostics": diagnostics,
    }


def simulate_policy_against_traces(
    session_store: Any,
    candidate_policy: Dict[str, Any],
    *,
    tools: Optional[Sequence[Dict[str, Any]]] = None,
    session_id: Optional[str] = None,
    session_prefix: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Replay recorded `AuditVault` traces in isolated sandboxed memory against a
    draft `CentralPolicyRegistry` dict without mutating production sessions.
    """
    from gatekeep.control_plane import AuditVault, CentralPolicyRegistry
    from gatekeep.gate import PreExecutionGate
    from gatekeep.persistence import InMemorySessionStore
    from gatekeep.registry import ToolRegistry

    vault = AuditVault(session_store)
    receipts = vault.query(session_id=session_id, limit=5000)
    if session_prefix:
        receipts = [r for r in receipts if r.session_id.startswith(session_prefix)]

    by_session: Dict[str, List[Any]] = defaultdict(list)
    for r in receipts:
        if r.rule_triggered in ("mcp_resource_read", "saga_compensation_rollback"):
            continue
        by_session[r.session_id].append(r)

    draft_registry = CentralPolicyRegistry()
    draft_registry.load_dict(candidate_policy, replace=True)

    sim_tool_reg = ToolRegistry()
    known_tools: Dict[str, Dict[str, Any]] = {}
    for t in tools or []:
        known_tools[str(t["name"])] = dict(t)
    for r in receipts:
        if r.tool_name not in known_tools:
            known_tools[r.tool_name] = {"name": r.tool_name, "description": ""}

    def _noop(**kwargs: Any) -> Dict[str, Any]:
        return {"simulated": True}

    for tname, schema in known_tools.items():
        pol = draft_registry.get_policy(tname)
        sim_tool_reg.register(
            fn=_noop,
            name=tname,
            description=str(schema.get("description") or tname),
            parameters=dict(schema.get("inputSchema") or {"type": "object", "properties": {}}),
            mode=(pol.mode if pol else infer_tool_mode(tname).upper()),
        )

    sim_store = InMemorySessionStore()
    total_events = 0
    unchanged = 0
    newly_blocked = 0
    newly_allowed = 0
    diffs: List[Dict[str, Any]] = []

    for sid, items in sorted(by_session.items()):
        items.sort(key=lambda item: (item.turn, item.timestamp))
        gate = PreExecutionGate.from_store(
            session_id=sid,
            session_store=sim_store,
            registry=sim_tool_reg,
            policy_registry=draft_registry,
            strict_provenance=False,
            auto_persist=False,
        )
        for item in items:
            total_events += 1
            original_verdict = item.would_verdict or item.verdict.value
            decision = gate.evaluate(
                tool_name=item.tool_name,
                arguments=dict(item.arguments or {}),
                actor_id=item.actor_id,
            )
            new_verdict = decision.verdict.value

            if new_verdict == "ALLOW":
                pol = draft_registry.get_policy(item.tool_name)
                eff_mode = (pol.mode if pol else infer_tool_mode(item.tool_name)).lower()
                if eff_mode == "read":
                    gate.ledger.absorb_tool_return(
                        tool_name=item.tool_name,
                        args=dict(item.arguments or {}),
                        result={"simulated": True},
                        mode="read",
                        provides=pol.provides if pol else None,
                        registry=sim_tool_reg,
                    )

            if new_verdict == original_verdict:
                unchanged += 1
            else:
                if original_verdict == "ALLOW" and new_verdict in ("BLOCK", "REVISE", "ESCALATE"):
                    newly_blocked += 1
                elif original_verdict in ("BLOCK", "REVISE", "ESCALATE") and new_verdict == "ALLOW":
                    newly_allowed += 1
                diffs.append(
                    {
                        "session_id": sid,
                        "turn": item.turn,
                        "tool_name": item.tool_name,
                        "original_verdict": original_verdict,
                        "simulated_verdict": new_verdict,
                        "rule_triggered": decision.rule_triggered,
                        "reason": decision.reason,
                    }
                )

    return {
        "sessions_replayed": len(by_session),
        "total_events": total_events,
        "unchanged": unchanged,
        "verdict_changes": len(diffs),
        "newly_blocked": newly_blocked,
        "newly_allowed": newly_allowed,
        "diffs": diffs,
    }
