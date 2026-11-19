"""
Gatekeep — Zero-Dependency Pre-Execution Firewall & Saga Proxy for MCP AI Agents.

Deterministic sub-millisecond protection for tool-calling AI agents:
  - Causal entity provenance & indirect prompt injection (IPI) taint tracking
  - Outbound secret/PII DLP, SSRF/DNS-rebinding, sensitive path & SQL/shell guards
  - Durable MCP tool poisoning & mid-session rug-pull schema pinning
  - Sliding rate limits & atomic cross-session cumulative spend caps
  - Automatic LIFO Saga compensation rollback & Idempotency-Key deduplication
  - Dual-control RBAC/SoD human approvals & SHA-256 hash-chained AuditVault
"""

from __future__ import annotations

__version__ = "0.2.1"

from gatekeep.control_plane import (
    AuditVault,
    CentralPolicyRegistry,
    EscalationRouter,
    EscalationTicket,
    SagaRecoveryDaemon,
    SweepReport,
    ToolPolicySpec,
    WebhookEscalationNotifier,
    resolve_effective_tool,
)
from gatekeep.decorator import gatekeep_tool, slim_tool
from gatekeep.gate import AuditReceipt, GateDecision, PreExecutionGate, Verdict
from gatekeep.ledger import LedgerEntry, ToolReturnLedger
from gatekeep.mcp.http_server import (
    ApiPrincipal,
    AuthContext,
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
    AsyncCallableMCPUpstream,
    CallableMCPUpstream,
    HttpMCPUpstream,
    MCPTransactionProxy,
    MCPUpstream,
    RegistryMCPUpstream,
    StdioMCPUpstream,
)
from gatekeep.middleware import GatekeepMiddleware, GatekeepPolicyError
from gatekeep.persistence import (
    ConcurrencyConflictError,
    InMemorySessionStore,
    PostgresSessionStore,
    RedisSessionStore,
    SQLiteSessionStore,
    SessionStateStore,
)
from gatekeep.policy import PolicySyntaxError, SafePolicyEvaluator, evaluate_declarative_policy
from gatekeep.redaction import (
    DEFAULT_SENSITIVE_KEYS,
    SensitiveDataRedactor,
    canonical_action_fingerprint,
    hash_secret_token,
)
from gatekeep.registry import ToolDefinition, ToolRegistry
from gatekeep.saga import RollbackSummary, SagaCoordinator, SagaStep
from gatekeep.security import (
    compute_tool_schema_hash,
    detect_tool_description_poisoning,
    inspect_payload_safety,
    scan_outbound_secrets,
)

__all__ = [
    "__version__",
    "gatekeep_tool",
    "slim_tool",
    "ToolDefinition",
    "ToolRegistry",
    "ToolReturnLedger",
    "LedgerEntry",
    "PreExecutionGate",
    "GateDecision",
    "Verdict",
    "AuditReceipt",
    "GatekeepMiddleware",
    "GatekeepPolicyError",
    "SafePolicyEvaluator",
    "PolicySyntaxError",
    "evaluate_declarative_policy",
    "SagaCoordinator",
    "SagaStep",
    "RollbackSummary",
    "SessionStateStore",
    "InMemorySessionStore",
    "SQLiteSessionStore",
    "RedisSessionStore",
    "PostgresSessionStore",
    "ConcurrencyConflictError",
    "ToolPolicySpec",
    "CentralPolicyRegistry",
    "resolve_effective_tool",
    "EscalationTicket",
    "EscalationRouter",
    "WebhookEscalationNotifier",
    "SagaRecoveryDaemon",
    "SweepReport",
    "AuditVault",
    "DEFAULT_SENSITIVE_KEYS",
    "SensitiveDataRedactor",
    "canonical_action_fingerprint",
    "hash_secret_token",
    "compute_tool_schema_hash",
    "detect_tool_description_poisoning",
    "inspect_payload_safety",
    "scan_outbound_secrets",
    "MCPUpstream",
    "CallableMCPUpstream",
    "AsyncCallableMCPUpstream",
    "RegistryMCPUpstream",
    "StdioMCPUpstream",
    "HttpMCPUpstream",
    "MCPTransactionProxy",
    "MCPHttpGateway",
    "ApiPrincipal",
    "AuthContext",
    "parse_api_principals",
    "serve_http",
    "generate_starter_policy",
    "synthesize_policies_from_store",
    "simulate_policy_against_traces",
]
