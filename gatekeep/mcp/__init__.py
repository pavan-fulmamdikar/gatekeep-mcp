"""
gatekeep/mcp/__init__.py

Framework-agnostic Model Context Protocol (MCP) Transaction & Security Proxy.
"""

from gatekeep.mcp.http_server import (
    ApiPrincipal,
    AuthContext,
    MCPHttpGateway,
    VALID_ROLES,
    create_http_server,
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
    MCP_PROTOCOL_VERSION,
    RegistryMCPUpstream,
    StdioMCPUpstream,
)

__all__ = [
    "MCP_PROTOCOL_VERSION",
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
    "VALID_ROLES",
    "parse_api_principals",
    "create_http_server",
    "serve_http",
    "generate_starter_policy",
    "synthesize_policies_from_store",
    "simulate_policy_against_traces",
]
