"""
gatekeep/mcp/cli.py

Production CLI runner for `MCPTransactionProxy` & `AuditVault`/`SagaRecoveryDaemon`
maintenance utilities. Allows Claude Desktop, Cursor, Windsurf, or CI workers to
launch Slim as a stdio MCP security & transaction gateway in one command.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from gatekeep.control_plane import (
    AuditVault,
    CentralPolicyRegistry,
    EscalationRouter,
    SagaRecoveryDaemon,
)
from gatekeep.persistence import (
    InMemorySessionStore,
    PostgresSessionStore,
    RedisSessionStore,
    SQLiteSessionStore,
    SessionStateStore,
)
from gatekeep.redaction import SensitiveDataRedactor
from gatekeep.mcp.http_server import (
    ApiPrincipal,
    MCPHttpGateway,
    parse_api_principals,
    serve_http,
)
from gatekeep.mcp.onboarding import (
    generate_starter_policy,
    simulate_policy_against_traces,
    synthesize_policies_from_store,
)
from gatekeep.mcp.proxy import (
    HttpMCPUpstream,
    MCPTransactionProxy,
    MCPUpstream,
    StdioMCPUpstream,
)


def parse_upstream_spec(spec: str) -> Tuple[Optional[str], List[str]]:
    """
    Parse `--upstream` argument of form `'cmd arg1 arg2'`, `'name=cmd arg1 arg2'`,
    `'https://host/mcp'`, or `'name=https://host/mcp'`.
    """
    alias: Optional[str] = None
    cmd_str = spec.strip()
    if "=" in cmd_str and not cmd_str.startswith(("=", "\"", "'")):
        left, right = cmd_str.split("=", 1)
        left_clean = left.strip()
        if (
            left_clean
            and " " not in left_clean
            and "/" not in left_clean
            and "\\" not in left_clean
            and ":" not in left_clean
        ):
            alias = left_clean
            cmd_str = right.strip()

    if cmd_str.startswith(("http://", "https://")):
        return alias, [cmd_str]

    cmd = shlex.split(cmd_str, posix=(sys.platform != "win32"))
    if sys.platform == "win32":
        # Strip surrounding quotes preserved by non-POSIX shlex split
        cmd = [part[1:-1] if len(part) >= 2 and part[0] == part[-1] and part[0] in ("'", '"') else part for part in cmd]
    if not cmd:
        raise ValueError(f"Empty upstream command in spec: {spec!r}")
    return alias, cmd


def parse_upstream_headers(specs: Optional[Sequence[str]]) -> Dict[str, str]:
    """Parse repeatable `--upstream-header 'Key: Value'` flags."""
    headers: Dict[str, str] = {}
    for raw in specs or []:
        item = raw.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError(f"Invalid --upstream-header (expected 'Key: Value'): {raw!r}")
        k, v = item.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def parse_http_bind(spec: str) -> Tuple[str, int]:
    """Parse `--http` bind target ('host:port', ':port', or 'port')."""
    raw = spec.strip()
    if ":" in raw:
        host, port_str = raw.rsplit(":", 1)
        host = host.strip() or "127.0.0.1"
    else:
        host, port_str = "127.0.0.1", raw
    port = int(port_str)
    if not (0 <= port <= 65535):
        raise ValueError(f"Invalid TCP port in --http: {port}")
    return host, port


def parse_api_keys(specs: Optional[Sequence[str]]) -> Dict[str, str]:
    """Parse repeatable `--api-key` flags of form `'tenant=secret'` or `'secret'`."""
    mapping: Dict[str, str] = {}
    for idx, raw in enumerate(specs or []):
        item = raw.strip()
        if not item:
            continue
        if "=" in item:
            tenant, token = item.split("=", 1)
            tenant = tenant.strip() or f"tenant_{idx + 1}"
            token = token.strip()
        else:
            tenant, token = f"tenant_{idx + 1}", item
        if not token:
            raise ValueError(f"Empty API token in --api-key spec: {raw!r}")
        mapping[token] = tenant
    return mapping


def _open_session_store(args: argparse.Namespace) -> SessionStateStore:
    if getattr(args, "pg_dsn", None):
        return PostgresSessionStore(dsn=args.pg_dsn)
    if getattr(args, "redis_url", None):
        return RedisSessionStore(redis_url=args.redis_url)
    if getattr(args, "db", None):
        return SQLiteSessionStore(args.db)
    return InMemorySessionStore()


def _make_upstream_client(cmd: List[str], headers: Optional[Dict[str, str]] = None) -> MCPUpstream:
    if len(cmd) == 1 and cmd[0].startswith(("http://", "https://")):
        return HttpMCPUpstream(cmd[0], headers=headers)
    return StdioMCPUpstream(cmd)


def _make_jsonl_audit_sink(path: str):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock = __import__("threading").Lock()

    def _sink(receipt: Any) -> None:
        payload = receipt.to_dict() if hasattr(receipt, "to_dict") else dict(receipt)
        line = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        with lock:
            with target.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()

    return _sink


def _build_principals_from_args(args: argparse.Namespace) -> Dict[str, ApiPrincipal]:
    principals: Dict[str, ApiPrincipal] = {}
    principals.update(parse_api_principals(getattr(args, "api_key", None), default_role="admin"))
    for attr, role in (
        ("agent_key", "agent"),
        ("policy_admin_key", "policy_admin"),
        ("approver_key", "approver"),
        ("auditor_key", "auditor"),
    ):
        specs = getattr(args, attr, None)
        if not specs:
            continue
        normalized: List[str] = []
        for item in specs:
            raw = item.strip()
            if "=" in raw:
                lhs, secret = raw.split("=", 1)
                parts = [p.strip() for p in lhs.split(":")]
                if len(parts) == 1:
                    normalized.append(f"{parts[0]}:{role}={secret.strip()}")
                elif len(parts) == 2:
                    normalized.append(f"{parts[0]}:{role}:{parts[1]}={secret.strip()}")
                else:
                    normalized.append(raw)
            else:
                normalized.append(raw)
        principals.update(parse_api_principals(normalized, default_role=role))
    return principals


def build_proxy_from_args(args: argparse.Namespace) -> Tuple[MCPTransactionProxy, SessionStateStore, List[MCPUpstream]]:
    """Construct configured `SessionStateStore`, durable Control Plane, upstreams, and `MCPTransactionProxy`."""
    store = _open_session_store(args)
    redactor = None if getattr(args, "no_redact_pii", False) else SensitiveDataRedactor()
    audit_jsonl = getattr(args, "audit_jsonl", None)
    audit_sink = _make_jsonl_audit_sink(audit_jsonl) if audit_jsonl else None
    policy_registry = CentralPolicyRegistry(session_store=store)
    if args.policy:
        policy_registry.load_file(args.policy, replace=True)
    escalation_router = EscalationRouter(session_store=store, redactor=redactor)

    upstream_headers = parse_upstream_headers(getattr(args, "upstream_header", None))
    clients: List[MCPUpstream] = []
    parsed_specs = [parse_upstream_spec(s) for s in (args.upstream or [])]

    upstream: Union[MCPUpstream, Dict[str, MCPUpstream]]
    if len(parsed_specs) == 1 and parsed_specs[0][0] is None:
        client = _make_upstream_client(parsed_specs[0][1], headers=upstream_headers)
        clients.append(client)
        upstream = client
    elif len(parsed_specs) >= 1:
        federated: Dict[str, MCPUpstream] = {}
        for idx, (alias, cmd) in enumerate(parsed_specs):
            name = alias or f"upstream_{idx + 1}"
            client = _make_upstream_client(cmd, headers=upstream_headers)
            clients.append(client)
            federated[name] = client
        upstream = federated
    else:
        raise ValueError("At least one --upstream command or HTTP URL must be supplied to run proxy mode.")

    proxy = MCPTransactionProxy(
        upstream=upstream,
        session_store=store,
        policy_registry=policy_registry,
        escalation_router=escalation_router,
        strict_provenance=not args.no_strict_provenance,
        auto_rollback_on_block=args.auto_rollback_on_block,
        auto_rollback_on_error=not args.no_auto_rollback_on_error,
        default_session_id=args.session_id,
        redactor=redactor,
        audit_sink=audit_sink,
        shadow_mode=bool(getattr(args, "shadow", False)),
        require_user_intent=bool(getattr(args, "require_user_intent", False)),
    )
    return proxy, store, clients


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gatekeep",
        description="Gatekeep — Transaction & Safety Proxy for AI Agent Tool Calls (MCP)",
    )
    parser.add_argument(
        "--upstream",
        action="append",
        default=[],
        help="Upstream MCP stdio command or HTTP(S) URL (or 'name=target' for federated mode). Repeatable.",
    )
    parser.add_argument(
        "--upstream-header",
        action="append",
        default=[],
        help="Custom HTTP header ('Key: Value') sent to remote http(s):// upstreams. Repeatable.",
    )
    parser.add_argument(
        "--policy",
        default=None,
        help="Path to JSON CentralPolicyRegistry configuration file.",
    )
    parser.add_argument(
        "--init-policy",
        nargs="?",
        const="-",
        default=None,
        help="Inspect upstream tools/list catalog, generate starter policies.json (to file or stdout '-'), and exit.",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="Path to SQLite WAL database for durable session, Saga, Control Plane, and AuditVault persistence.",
    )
    parser.add_argument(
        "--pg-dsn",
        default=None,
        help="PostgreSQL connection DSN for multi-worker ACID SessionStateStore persistence.",
    )
    parser.add_argument(
        "--redis-url",
        default=None,
        help="Redis URL (e.g. redis://localhost:6379/0) for distributed SessionStateStore persistence.",
    )
    parser.add_argument(
        "--http",
        default=None,
        help="Run networked Streamable-HTTP/SSE MCP Gateway + Control Plane on HOST:PORT (e.g. 0.0.0.0:8080).",
    )
    parser.add_argument(
        "--asgi",
        action="store_true",
        help="Serve --http using uvicorn ASGI instead of stdlib ThreadingHTTPServer (recommended for high QPS).",
    )
    parser.add_argument(
        "--api-key",
        action="append",
        default=[],
        help="Multi-tenant admin Bearer API key ('tenant=secret', 'tenant:role[:actor]=secret', or 'secret') when running --http.",
    )
    parser.add_argument(
        "--agent-key",
        action="append",
        default=[],
        help="Role-scoped API key permitted ONLY on MCP runtime endpoints (/mcp, /sse, /messages). Form: 'tenant=secret' or 'tenant:actor_id=secret'.",
    )
    parser.add_argument(
        "--policy-admin-key",
        action="append",
        default=[],
        help="Role-scoped API key for policy management (/admin/policies, /admin/recovery/sweep).",
    )
    parser.add_argument(
        "--approver-key",
        action="append",
        default=[],
        help="Role-scoped API key for HITL escalation approval/rejection (/admin/escalations/*/approve).",
    )
    parser.add_argument(
        "--auditor-key",
        action="append",
        default=[],
        help="Read-only role-scoped API key for AuditVault & queue inspection.",
    )
    parser.add_argument(
        "--jwt-secret",
        default=None,
        help="Shared HS256 JWT secret (or set SLIM_JWT_SECRET) to authenticate OIDC/JWT bearer tokens with sub/tenant/role claims.",
    )
    parser.add_argument(
        "--jwt-issuer",
        default=None,
        help="Expected 'iss' claim when validating HS256 JWT bearer tokens.",
    )
    parser.add_argument(
        "--jwt-audience",
        default=None,
        help="Expected 'aud' claim when validating HS256 JWT bearer tokens.",
    )
    parser.add_argument(
        "--strict-rbac",
        action="store_true",
        help="Enforce strict role separation across /mcp and /admin/* even for single-role credentials.",
    )
    parser.add_argument(
        "--no-redact-pii",
        action="store_true",
        help="Disable automatic PII/secret redaction before writing AuditReceipts and EscalationTickets.",
    )
    parser.add_argument(
        "--audit-jsonl",
        default=None,
        help="Path to an append-only WORM JSONL file receiving every signed AuditReceipt.",
    )
    parser.add_argument(
        "--slack-signing-secret",
        default=None,
        help="Slack Signing Secret enabling verified POST /integrations/slack/actions callbacks.",
    )
    parser.add_argument(
        "--recovery-interval",
        type=float,
        default=None,
        help="Automatically run SagaRecoveryDaemon background sweeps every N seconds when running --http.",
    )
    parser.add_argument(
        "--session-id",
        default="default",
        help="Default session ID when client requests omit _meta.session_id.",
    )
    parser.add_argument(
        "--no-strict-provenance",
        action="store_true",
        help="Disable strict argument entity provenance checking.",
    )
    parser.add_argument(
        "--require-user-intent",
        action="store_true",
        help="Escalate WRITE tools after external READs if caller omitted _meta.user_prompt.",
    )
    parser.add_argument(
        "--auto-rollback-on-block",
        action="store_true",
        help="Automatically roll back pending Saga steps when a permanent Verdict.BLOCK occurs.",
    )
    parser.add_argument(
        "--no-auto-rollback-on-error",
        action="store_true",
        help="Disable automatic Saga rollback when an upstream tool call fails.",
    )
    parser.add_argument(
        "--shadow",
        action="store_true",
        help="Run Gatekeep in Envoy-style Shadow/Dry-Run mode (audit & flag would-block verdicts without blocking upstream calls).",
    )
    parser.add_argument(
        "--learn-from-db",
        nargs="?",
        const="-",
        default=None,
        help="Synthesize recommended CentralPolicyRegistry rules + shadow diagnostics from recorded traces in --db/--pg-dsn/--redis-url (write to file or stdout '-').",
    )
    parser.add_argument(
        "--simulate-policy",
        default=None,
        help="Replay recorded traces in --db/--pg-dsn/--redis-url against a draft policy JSON file and print diff report, then exit.",
    )
    parser.add_argument(
        "--verify-audit",
        action="store_true",
        help="Verify SHA-256 hash chains across all sessions in --db and print JSON summary, then exit.",
    )
    parser.add_argument(
        "--sweep-stale",
        type=float,
        default=None,
        help="Run SagaRecoveryDaemon one-shot sweep on --db for sessions older than N seconds, then exit.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.learn_from_db is not None:
        if not args.db and not getattr(args, "pg_dsn", None) and not getattr(args, "redis_url", None):
            parser.error("--learn-from-db requires --db, --pg-dsn, or --redis-url.")
        store = _open_session_store(args)
        try:
            doc = synthesize_policies_from_store(store)
            rendered = json.dumps(doc, indent=2) + "\n"
            if args.learn_from_db == "-":
                sys.stdout.write(rendered)
            else:
                out_path = Path(args.learn_from_db)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(rendered, encoding="utf-8")
                sys.stderr.write(
                    f"[gatekeep] Synthesized policy from {doc['sessions_analyzed']} sessions at {out_path}\n"
                )
            return 0
        finally:
            if hasattr(store, "close"):
                store.close()  # type: ignore[attr-defined]

    if args.simulate_policy is not None:
        if not args.db and not getattr(args, "pg_dsn", None) and not getattr(args, "redis_url", None):
            parser.error("--simulate-policy requires --db, --pg-dsn, or --redis-url.")
        store = _open_session_store(args)
        try:
            draft = json.loads(Path(args.simulate_policy).read_text(encoding="utf-8"))
            report = simulate_policy_against_traces(store, draft)
            print(json.dumps(report, indent=2))
            return 0
        finally:
            if hasattr(store, "close"):
                store.close()  # type: ignore[attr-defined]

    if args.verify_audit:
        if not args.db and not getattr(args, "pg_dsn", None):
            parser.error("--verify-audit requires --db <sqlite_path> or --pg-dsn <postgres_dsn>.")
        store = _open_session_store(args)
        try:
            vault = AuditVault(store)
            chains = vault.verify_all_chains()
            all_ok = all(chains.values())
            print(json.dumps({"valid": all_ok, "sessions": chains}, indent=2))
            return 0 if all_ok else 2
        finally:
            if hasattr(store, "close"):
                store.close()  # type: ignore[attr-defined]

    if args.sweep_stale is not None:
        if not args.db and not getattr(args, "pg_dsn", None):
            parser.error("--sweep-stale requires --db <sqlite_path> or --pg-dsn <postgres_dsn>.")
        if not args.upstream:
            parser.error("--sweep-stale requires --upstream so compensating MCP tools can be dispatched.")
        proxy, store, clients = build_proxy_from_args(args)
        try:
            daemon = SagaRecoveryDaemon(
                session_store=store,
                registry=proxy.registry,
                policy_registry=proxy.policy_registry,
                stale_after_seconds=args.sweep_stale,
            )
            report = daemon.sweep_once()
            print(
                json.dumps(
                    {
                        "scanned_sessions": report.scanned_sessions,
                        "stale_sessions_found": report.stale_sessions_found,
                        "recovered_sessions": report.recovered_sessions,
                        "failed_sessions": report.failed_sessions,
                        "details": report.details,
                    },
                    indent=2,
                )
            )
            return 0 if report.failed_sessions == 0 else 1
        finally:
            for c in clients:
                c.close()
            if hasattr(store, "close"):
                store.close()  # type: ignore[attr-defined]

    if not args.upstream:
        parser.error("Missing --upstream <cmd_or_url> (or pass --verify-audit / --help).")

    if args.init_policy is not None:
        proxy, store, clients = build_proxy_from_args(args)
        try:
            catalog = [schema for _, (_, _, schema) in sorted(proxy._tool_routes.items())]
            policy_doc = generate_starter_policy(catalog)
            rendered = json.dumps(policy_doc, indent=2) + "\n"
            if args.init_policy == "-":
                sys.stdout.write(rendered)
            else:
                out_path = Path(args.init_policy)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(rendered, encoding="utf-8")
                sys.stderr.write(
                    f"[gatekeep] Generated starter policy for {len(catalog)} tools at {out_path}\n"
                )
            return 0
        finally:
            for c in clients:
                if hasattr(c, "close"):
                    c.close()
            if hasattr(store, "close"):
                store.close()  # type: ignore[attr-defined]

    proxy, store, clients = build_proxy_from_args(args)
    try:
        if getattr(args, "http", None):
            host, port = parse_http_bind(args.http)
            principals = _build_principals_from_args(args)
            slack_secret = (
                args.slack_signing_secret
                or os.environ.get("GATEKEEP_SLACK_SIGNING_SECRET")
                or os.environ.get("SLIM_SLACK_SIGNING_SECRET")
            )
            jwt_secret = (
                args.jwt_secret
                or os.environ.get("GATEKEEP_JWT_SECRET")
                or os.environ.get("SLIM_JWT_SECRET")
            )
            sse_pubsub_client = None
            if getattr(args, "pg_dsn", None) and getattr(args, "redis_url", None):
                try:
                    import redis  # type: ignore

                    sse_pubsub_client = redis.Redis.from_url(
                        args.redis_url, decode_responses=True
                    )
                except ImportError as exc:
                    raise ImportError(
                        "Passing --redis-url with --pg-dsn for multi-replica SSE Pub/Sub requires 'redis'. "
                        "Install with: pip install gatekeep-mcp[redis]"
                    ) from exc
            gateway = MCPHttpGateway(
                proxy,
                principals=principals or None,
                strict_rbac=True if getattr(args, "strict_rbac", False) else None,
                jwt_secret=jwt_secret,
                jwt_issuer=getattr(args, "jwt_issuer", None),
                jwt_audience=getattr(args, "jwt_audience", None),
                slack_signing_secret=slack_secret,
                sse_pubsub_client=sse_pubsub_client,
            )
            if getattr(args, "asgi", False):
                try:
                    import uvicorn  # type: ignore
                except ImportError as exc:
                    raise ImportError(
                        "--asgi requires 'uvicorn'. Install with: pip install gatekeep-mcp[http]"
                    ) from exc
                if args.recovery_interval is not None and args.recovery_interval > 0:
                    gateway.start_recovery_daemon(args.recovery_interval)
                try:
                    uvicorn.run(gateway, host=host, port=port, log_level="info")
                finally:
                    gateway.close()
            else:
                serve_http(
                    gateway,
                    host=host,
                    port=port,
                    recovery_interval_s=args.recovery_interval,
                )
        else:
            proxy.serve_stdio()
        return 0
    finally:
        for c in clients:
            if hasattr(c, "close"):
                c.close()
        if hasattr(store, "close"):
            store.close()  # type: ignore[attr-defined]


if __name__ == "__main__":
    raise SystemExit(main())
