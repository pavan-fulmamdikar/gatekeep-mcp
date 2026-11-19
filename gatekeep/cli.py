"""Top-level `gatekeep` CLI shim forwarding to `gatekeep.mcp.cli`."""

from gatekeep.mcp.cli import build_parser, main

__all__ = ["build_parser", "main"]
