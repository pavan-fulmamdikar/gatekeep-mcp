"""
gatekeep/mcp/proxy.py

Framework-Agnostic MCP (Model Context Protocol) Transaction & Security Proxy.
Sits between any MCP client (Claude Desktop, Cursor, LangGraph, OpenAI Agents SDK)
and any upstream MCP server or tool executor:

  - Protocol-level tool enforcement (`PreExecutionGate`) + `CentralPolicyRegistry` overlays
  - Stateful cross-request `ToolReturnLedger` persisted to `SessionStateStore`
  - Automatic Saga LIFO compensation rollback on upstream execution failures / fatal BLOCKs
  - HITL escalation routing (`EscalationRouter`) for `Verdict.ESCALATE`
  - Optional JIT `tools/list` schema pruning via `SlimAdvisor`
  - Zero-dependency JSON-RPC 2.0 `handle_jsonrpc()` & `serve_stdio()` runtime
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import logging
import queue
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from abc import ABC, abstractmethod
from typing import Any, Awaitable, Callable, Dict, IO, List, Optional, Tuple, Union

from gatekeep.control_plane import (
    CentralPolicyRegistry,
    EscalationRouter,
    resolve_effective_tool,
)
from gatekeep.gate import GateDecision, PreExecutionGate, Verdict
from gatekeep.persistence import InMemorySessionStore, SessionStateStore
from gatekeep.redaction import (
    SensitiveDataRedactor,
    canonical_action_fingerprint,
)
from gatekeep.security import (
    compute_tool_schema_hash,
    detect_tool_description_poisoning,
)
from gatekeep.mcp.onboarding import generate_starter_policy

_UNSET_REDACTOR: Any = object()
from gatekeep.registry import ToolRegistry

logger = logging.getLogger("gatekeep.mcp")

MCP_PROTOCOL_VERSION = "2024-11-05"


def _jsonrpc_ok(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


class MCPUpstream(ABC):
    """Abstract upstream MCP server or tool execution target."""

    @abstractmethod
    def list_tools(self) -> List[Dict[str, Any]]:
        """Return MCP-formatted tool dicts (`name`, `description`, `inputSchema`)."""

    @abstractmethod
    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Execute `name` upstream with `arguments` and return its result payload."""

    async def acall_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Async tool execution wrapper defaulting to a worker thread."""
        return await asyncio.to_thread(self.call_tool, name, arguments)

    def list_resources(self) -> List[Dict[str, Any]]:
        """Return MCP-formatted resource descriptors (`uri`, `name`, `mimeType`)."""
        return []

    def read_resource(self, uri: str) -> Any:
        """Read an upstream MCP resource by URI."""
        raise NotImplementedError("Upstream MCP server does not implement resources/read.")

    async def alist_resources(self) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self.list_resources)

    async def aread_resource(self, uri: str) -> Any:
        return await asyncio.to_thread(self.read_resource, uri)


class CallableMCPUpstream(MCPUpstream):
    """In-process MCP upstream backed by declarative tool schemas and a Python executor."""

    def __init__(
        self,
        tools: List[Dict[str, Any]],
        executor: Callable[[str, Dict[str, Any]], Any],
        *,
        resources: Optional[List[Dict[str, Any]]] = None,
        resource_reader: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self._tools = [dict(t) for t in tools]
        self._executor = executor
        self._resources = [dict(r) for r in (resources or [])]
        self._resource_reader = resource_reader

    def list_tools(self) -> List[Dict[str, Any]]:
        return [dict(t) for t in self._tools]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return self._executor(name, dict(arguments or {}))

    def list_resources(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._resources]

    def read_resource(self, uri: str) -> Any:
        if self._resource_reader is not None:
            return self._resource_reader(uri)
        return super().read_resource(uri)


class AsyncCallableMCPUpstream(MCPUpstream):
    """
    In-process MCP upstream supporting both ``async def`` and synchronous Python executors.
    """

    def __init__(
        self,
        tools: List[Dict[str, Any]],
        executor: Callable[[str, Dict[str, Any]], Union[Any, Awaitable[Any]]],
    ) -> None:
        self._tools = [dict(t) for t in tools]
        self._executor = executor

    def list_tools(self) -> List[Dict[str, Any]]:
        return [dict(t) for t in self._tools]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        result = self._executor(name, dict(arguments or {}))
        if inspect.isawaitable(result):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(result)
            if inspect.iscoroutine(result):
                result.close()
            raise RuntimeError(
                "AsyncCallableMCPUpstream.call_tool() cannot await inside a running event loop; "
                "use ahandle_tools_call() / ahandle_jsonrpc() instead."
            )
        return result

    async def acall_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        result = self._executor(name, dict(arguments or {}))
        if inspect.isawaitable(result):
            return await result
        return result


class RegistryMCPUpstream(MCPUpstream):
    """Exposes any Slim `ToolRegistry` directly as an MCP upstream target."""

    def __init__(self, registry: Optional[ToolRegistry] = None) -> None:
        self._registry = registry if registry is not None else ToolRegistry.instance()

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": td.name,
                "description": td.description,
                "inputSchema": dict(td.parameters),
                "_slim_meta": {
                    "mode": td.mode,
                    "provides": list(td.provides) if td.provides else None,
                    "requires": list(td.requires) if td.requires else None,
                    "provenance_args": list(td.provenance_args) if td.provenance_args else None,
                    "policy": td.policy,
                    "requires_approval": td.requires_approval,
                    "compensates_with": td.compensates_with,
                    "compensation_args": td.compensation_args,
                },
            }
            for td in self._registry.get_all()
        ]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        td = self._registry.get(name)
        if td is None:
            raise KeyError(f"Tool '{name}' not found in ToolRegistry.")
        return td.fn(**dict(arguments or {}))


class StdioMCPUpstream(MCPUpstream):
    """
    Subprocess stdio JSON-RPC 2.0 client connecting to an external MCP server
    (e.g. `["npx", "@modelcontextprotocol/server-postgres", ...]`).
    """

    def __init__(
        self,
        command: List[str],
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> None:
        self.command = command
        self.env = env
        self.cwd = cwd
        self._lock = threading.RLock()
        self._next_id = 1
        self._proc: Optional[subprocess.Popen[str]] = None
        self._initialized = False

    def start(self) -> None:
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return
            cmd = list(self.command)
            if cmd:
                search_path = (self.env or {}).get("PATH") if self.env else None
                resolved = shutil.which(cmd[0], path=search_path)
                if resolved:
                    cmd[0] = resolved
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                env=self.env,
                cwd=self.cwd,
            )
            self._initialized = False

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        self.start()
        assert self._proc is not None and self._proc.stdin is not None and self._proc.stdout is not None
        with self._lock:
            if not self._initialized and method != "initialize":
                self._initialized = True
                self._send_and_recv(
                    "initialize",
                    {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "gatekeep-mcp-proxy", "version": "0.2.0"},
                    },
                )
                notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
                self._proc.stdin.write(notif)
                self._proc.stdin.flush()
            return self._send_and_recv(method, params or {})

    def _send_and_recv(self, method: str, params: Dict[str, Any]) -> Any:
        assert self._proc is not None and self._proc.stdin is not None and self._proc.stdout is not None
        req_id = self._next_id
        self._next_id += 1
        frame = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}) + "\n"
        self._proc.stdin.write(frame)
        self._proc.stdin.flush()

        while True:
            line = self._proc.stdout.readline()
            if not line:
                stderr_out = self._proc.stderr.read() if self._proc.stderr else ""
                raise RuntimeError(f"Upstream MCP server closed stdout unexpectedly: {stderr_out}")
            msg = json.loads(line)
            if msg.get("id") == req_id:
                if "error" in msg and msg["error"] is not None:
                    raise RuntimeError(f"Upstream MCP error: {msg['error']}")
                return msg.get("result")

    def list_tools(self) -> List[Dict[str, Any]]:
        res = self._request("tools/list", {}) or {}
        return list(res.get("tools", []))

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return self._request("tools/call", {"name": name, "arguments": dict(arguments or {})})

    def list_resources(self) -> List[Dict[str, Any]]:
        res = self._request("resources/list", {}) or {}
        return list(res.get("resources", []))

    def read_resource(self, uri: str) -> Any:
        return self._request("resources/read", {"uri": uri})

    def close(self) -> None:
        with self._lock:
            if self._proc is not None:
                try:
                    self._proc.terminate()
                    self._proc.wait(timeout=3.0)
                except Exception:
                    try:
                        self._proc.kill()
                    except Exception:
                        pass
                self._proc = None

    def __enter__(self) -> "StdioMCPUpstream":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def _parse_sse_jsonrpc_messages(raw_text: str) -> List[Dict[str, Any]]:
    """Extract JSON-RPC objects from an SSE `text/event-stream` response body."""
    messages: List[Dict[str, Any]] = []
    data_lines: List[str] = []
    for line in raw_text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
        elif line == "" and data_lines:
            payload = "\n".join(data_lines).strip()
            data_lines = []
            if payload:
                try:
                    parsed = json.loads(payload)
                    if isinstance(parsed, dict):
                        messages.append(parsed)
                except json.JSONDecodeError:
                    pass
    if data_lines:
        payload = "\n".join(data_lines).strip()
        if payload:
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    messages.append(parsed)
            except json.JSONDecodeError:
                pass
    return messages


class HttpMCPUpstream(MCPUpstream):
    """
    Production outbound MCP HTTP client implementing the `MCPUpstream` interface.

    Supports both:
    - **Streamable HTTP** (POST JSON-RPC 2.0 to `/mcp` with `application/json` or
      `text/event-stream` responses and automatic `Mcp-Session-Id` propagation)
    - **Legacy HTTP+SSE** (`GET /sse` discovering `event: endpoint` + `POST` messages)
    """

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout_s: float = 30.0,
        transport: str = "auto",
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"HttpMCPUpstream URL must start with http:// or https://, got '{url}'.")
        mode = transport.lower().strip()
        if mode not in ("auto", "streamable", "sse"):
            raise ValueError(f"Unsupported transport '{transport}'. Use 'auto', 'streamable', or 'sse'.")

        self.url = url
        self.headers = dict(headers or {})
        self.timeout_s = float(timeout_s)
        parsed = urllib.parse.urlparse(url)
        if mode == "auto":
            mode = "sse" if parsed.path.rstrip("/").endswith("/sse") else "streamable"
        self.transport = mode

        self._lock = threading.RLock()
        self._next_id = 1
        self._initialized = False
        self._session_id: Optional[str] = None

        # SSE client state
        self._sse_post_url: Optional[str] = None
        self._sse_resp: Optional[Any] = None
        self._sse_thread: Optional[threading.Thread] = None
        self._sse_closed = threading.Event()
        self._sse_waiters: Dict[Any, queue.Queue] = {}

        # Optional per-event-loop pooled `httpx.AsyncClient` for non-blocking Streamable HTTP
        self._async_clients: Dict[int, Tuple[Any, asyncio.Lock]] = {}

    def _build_headers(self, accept: str = "application/json, text/event-stream") -> Dict[str, str]:
        req_headers = {
            "Content-Type": "application/json",
            "Accept": accept,
        }
        req_headers.update(self.headers)
        if self._session_id:
            req_headers["Mcp-Session-Id"] = self._session_id
        return req_headers

    def _start_sse_if_needed(self) -> None:
        if self._sse_post_url is not None and not self._sse_closed.is_set():
            return

        endpoint_ready = threading.Event()
        endpoint_holder: Dict[str, str] = {}
        error_holder: List[BaseException] = []

        req = urllib.request.Request(
            self.url,
            headers=self._build_headers(accept="text/event-stream"),
            method="GET",
        )
        resp = urllib.request.urlopen(req, timeout=self.timeout_s)
        self._sse_resp = resp
        self._sse_closed.clear()

        def _reader() -> None:
            event_name = "message"
            data_buf: List[str] = []
            try:
                while not self._sse_closed.is_set():
                    raw = resp.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("event:"):
                        event_name = line[6:].strip()
                    elif line.startswith("data:"):
                        data_buf.append(line[5:].lstrip())
                    elif line == "" and data_buf:
                        payload = "\n".join(data_buf).strip()
                        data_buf = []
                        if event_name == "endpoint":
                            endpoint_holder["url"] = urllib.parse.urljoin(self.url, payload)
                            endpoint_ready.set()
                        elif event_name == "message" and payload:
                            try:
                                msg = json.loads(payload)
                                req_id = msg.get("id")
                                waiter = self._sse_waiters.get(req_id)
                                if waiter is not None:
                                    waiter.put(msg)
                            except json.JSONDecodeError:
                                pass
                        event_name = "message"
            except Exception as exc:
                error_holder.append(exc)
            finally:
                endpoint_ready.set()

        self._sse_thread = threading.Thread(
            target=_reader,
            name="slim-mcp-sse-upstream",
            daemon=True,
        )
        self._sse_thread.start()
        if not endpoint_ready.wait(timeout=self.timeout_s):
            self.close()
            raise TimeoutError(f"Timed out waiting for SSE endpoint event from {self.url}")
        if "url" not in endpoint_holder:
            err = error_holder[0] if error_holder else "no endpoint event received"
            self.close()
            raise RuntimeError(f"Failed to negotiate SSE endpoint with {self.url}: {err}")
        self._sse_post_url = endpoint_holder["url"]

    def _post_frame(self, target_url: str, body: Dict[str, Any], expect_reply: bool = True) -> Optional[Dict[str, Any]]:
        encoded = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            target_url,
            data=encoded,
            headers=self._build_headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
                if sid:
                    self._session_id = sid
                if not expect_reply or resp.status == 202:
                    return None
                raw_text = resp.read().decode("utf-8", errors="replace").strip()
                if not raw_text:
                    return None
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if "text/event-stream" in ctype or raw_text.startswith("event:") or raw_text.startswith("data:"):
                    msgs = _parse_sse_jsonrpc_messages(raw_text)
                    target_id = body.get("id")
                    for m in msgs:
                        if m.get("id") == target_id:
                            return m
                    return msgs[-1] if msgs else None
                return json.loads(raw_text)
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            try:
                parsed = json.loads(err_body)
                if isinstance(parsed, dict) and "error" in parsed:
                    return parsed
            except Exception:
                pass
            raise RuntimeError(f"Upstream HTTP {exc.code} from {target_url}: {err_body}") from exc

    def _send_and_recv(self, method: str, params: Dict[str, Any]) -> Any:
        req_id = self._next_id
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}

        if self.transport == "sse":
            self._start_sse_if_needed()
            assert self._sse_post_url is not None
            waiter: queue.Queue = queue.Queue(maxsize=1)
            self._sse_waiters[req_id] = waiter
            try:
                immediate = self._post_frame(self._sse_post_url, payload, expect_reply=True)
                msg = immediate if immediate is not None and "id" in immediate else waiter.get(timeout=self.timeout_s)
            finally:
                self._sse_waiters.pop(req_id, None)
        else:
            msg = self._post_frame(self.url, payload, expect_reply=True)

        if not msg:
            raise RuntimeError(f"Empty JSON-RPC response from {self.url} for method '{method}'.")
        if "error" in msg and msg["error"] is not None:
            raise RuntimeError(f"Upstream MCP error: {msg['error']}")
        return msg.get("result")

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        with self._lock:
            if not self._initialized and method != "initialize":
                self._initialized = True
                try:
                    self._send_and_recv(
                        "initialize",
                        {
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": {"name": "gatekeep-mcp-proxy", "version": "0.2.0"},
                        },
                    )
                    target = self._sse_post_url or self.url
                    self._post_frame(
                        target,
                        {"jsonrpc": "2.0", "method": "notifications/initialized"},
                        expect_reply=False,
                    )
                except RuntimeError as exc:
                    # Tolerate stateless JSON-RPC servers that omit `initialize`
                    if "-32601" not in str(exc):
                        self._initialized = False
                        raise
            return self._send_and_recv(method, params or {})

    def _next_request_id(self) -> int:
        with self._lock:
            req_id = self._next_id
            self._next_id += 1
            return req_id

    def _get_async_http_client(self) -> Optional[Tuple[Any, asyncio.Lock]]:
        """Lazily create a per-loop pooled `httpx.AsyncClient` when `httpx` is installed."""
        try:
            import httpx  # type: ignore
        except ImportError:
            return None
        loop_id = id(asyncio.get_running_loop())
        with self._lock:
            existing = self._async_clients.get(loop_id)
            if existing is not None:
                client, init_lock = existing
                if not getattr(client, "is_closed", False):
                    return client, init_lock
            client = httpx.AsyncClient(
                timeout=self.timeout_s,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=40),
            )
            init_lock = asyncio.Lock()
            self._async_clients[loop_id] = (client, init_lock)
            return client, init_lock

    async def _apost_frame(
        self,
        client: Any,
        target_url: str,
        payload: Dict[str, Any],
        *,
        expect_reply: bool = True,
    ) -> Optional[Dict[str, Any]]:
        resp = await client.post(
            target_url,
            content=json.dumps(payload).encode("utf-8"),
            headers=self._build_headers(),
        )
        sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
        if sid:
            self._session_id = sid
        ctype = (resp.headers.get("Content-Type") or "").lower()
        body_text = resp.text

        if resp.status_code >= 400:
            try:
                parsed = json.loads(body_text)
                if isinstance(parsed, dict) and "error" in parsed:
                    return parsed
            except Exception:
                pass
            raise RuntimeError(
                f"Upstream HTTP {resp.status_code} from {target_url}: {body_text}"
            )

        if not expect_reply or not body_text.strip():
            return None
        if "text/event-stream" in ctype:
            msgs = _parse_sse_json_messages(body_text)
            req_id = payload.get("id")
            for msg in msgs:
                if req_id is not None and msg.get("id") == req_id:
                    return msg
            return msgs[-1] if msgs else None
        return json.loads(body_text)

    async def _arequest_streamable(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        pair = self._get_async_http_client()
        if pair is None:
            return await asyncio.to_thread(self._request, method, params)
        client, init_lock = pair

        if not self._initialized and method != "initialize":
            async with init_lock:
                if not self._initialized:
                    self._initialized = True
                    try:
                        init_id = self._next_request_id()
                        init_msg = await self._apost_frame(
                            client,
                            self.url,
                            {
                                "jsonrpc": "2.0",
                                "id": init_id,
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": MCP_PROTOCOL_VERSION,
                                    "capabilities": {},
                                    "clientInfo": {
                                        "name": "gatekeep-mcp-proxy",
                                        "version": "0.2.0",
                                    },
                                },
                            },
                            expect_reply=True,
                        )
                        if init_msg and "error" in init_msg and init_msg["error"] is not None:
                            raise RuntimeError(f"Upstream MCP error: {init_msg['error']}")
                        await self._apost_frame(
                            client,
                            self.url,
                            {"jsonrpc": "2.0", "method": "notifications/initialized"},
                            expect_reply=False,
                        )
                    except RuntimeError as exc:
                        if "-32601" not in str(exc):
                            self._initialized = False
                            raise

        req_id = self._next_request_id()
        msg = await self._apost_frame(
            client,
            self.url,
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params or {},
            },
            expect_reply=True,
        )
        if not msg:
            raise RuntimeError(
                f"Empty JSON-RPC response from {self.url} for method '{method}'."
            )
        if "error" in msg and msg["error"] is not None:
            raise RuntimeError(f"Upstream MCP error: {msg['error']}")
        return msg.get("result")

    def list_tools(self) -> List[Dict[str, Any]]:
        res = self._request("tools/list", {}) or {}
        if isinstance(res, list):
            return list(res)
        return list(res.get("tools", []))

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return self._request("tools/call", {"name": name, "arguments": dict(arguments or {})})

    async def acall_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        if self.transport == "streamable":
            return await self._arequest_streamable(
                "tools/call", {"name": name, "arguments": dict(arguments or {})}
            )
        return await asyncio.to_thread(self.call_tool, name, arguments)

    def list_resources(self) -> List[Dict[str, Any]]:
        res = self._request("resources/list", {}) or {}
        return list(res.get("resources", []))

    def read_resource(self, uri: str) -> Any:
        return self._request("resources/read", {"uri": uri})

    async def aread_resource(self, uri: str) -> Any:
        if self.transport == "streamable":
            return await self._arequest_streamable("resources/read", {"uri": uri})
        return await asyncio.to_thread(self.read_resource, uri)

    async def aclose(self) -> None:
        with self._lock:
            clients = list(self._async_clients.values())
            self._async_clients.clear()
        for client, _lock in clients:
            try:
                await client.aclose()
            except Exception:
                pass
        self.close()

    def close(self) -> None:
        self._sse_closed.set()
        if self._sse_resp is not None:
            try:
                self._sse_resp.close()
            except Exception:
                pass
            self._sse_resp = None
        self._sse_post_url = None
        with self._lock:
            self._async_clients.clear()

    def __enter__(self) -> "HttpMCPUpstream":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class MCPTransactionProxy:
    """
    Universal MCP Transaction & Governance Gateway.

    Inspects upstream tool catalogs, overlays `CentralPolicyRegistry` rules, enforces
    `PreExecutionGate` checks, persists durable session state + Saga compensations across
    calls, optionally prunes `tools/list` via `SlimAdvisor`, and exposes MCP JSON-RPC 2.0.
    """

    def __init__(
        self,
        upstream: Union[MCPUpstream, Dict[str, MCPUpstream]],
        session_store: Optional[SessionStateStore] = None,
        policy_registry: Optional[CentralPolicyRegistry] = None,
        escalation_router: Optional[EscalationRouter] = None,
        registry: Optional[ToolRegistry] = None,
        advisor: Optional[Any] = None,
        strict_provenance: bool = True,
        max_tool_retries: int = 3,
        auto_rollback_on_block: bool = False,
        auto_rollback_on_error: bool = True,
        default_session_id: str = "default",
        redactor: Optional[SensitiveDataRedactor] = _UNSET_REDACTOR,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        shadow_mode: bool = False,
        require_user_intent: bool = False,
        pin_tool_schemas: bool = True,
        detect_tool_poisoning: bool = True,
        block_outbound_secrets: bool = True,
        block_ssrf_and_sensitive_paths: bool = True,
        federated_separator: str = ".",
        default_max_calls_per_minute: Optional[int] = None,
        default_session_spend_limit: Optional[float] = None,
        global_max_calls_per_minute: Optional[int] = None,
        global_actor_spend_limit: Optional[float] = None,
        resolve_dns_for_ssrf: bool = False,
    ) -> None:
        self._lock = threading.RLock()
        if isinstance(upstream, dict):
            self._upstreams: Dict[str, MCPUpstream] = dict(upstream)
            self._federated = True
        else:
            self._upstreams = {"default": upstream}
            self._federated = False

        self.redactor: Optional[SensitiveDataRedactor] = (
            SensitiveDataRedactor() if redactor is _UNSET_REDACTOR else redactor
        )
        self.audit_sink: Optional[Callable[[Dict[str, Any]], None]] = audit_sink
        self.shadow_mode: bool = bool(shadow_mode)
        self.require_user_intent: bool = bool(require_user_intent)
        self.pin_tool_schemas: bool = bool(pin_tool_schemas)
        self.detect_tool_poisoning: bool = bool(detect_tool_poisoning)
        self.block_outbound_secrets: bool = bool(block_outbound_secrets)
        self.block_ssrf_and_sensitive_paths: bool = bool(block_ssrf_and_sensitive_paths)
        self.federated_separator: str = str(federated_separator or ".")
        self.default_max_calls_per_minute: Optional[int] = default_max_calls_per_minute
        self.default_session_spend_limit: Optional[float] = default_session_spend_limit
        self.global_max_calls_per_minute: Optional[int] = global_max_calls_per_minute
        self.global_actor_spend_limit: Optional[float] = global_actor_spend_limit
        self.resolve_dns_for_ssrf: bool = bool(resolve_dns_for_ssrf)
        self.session_store: SessionStateStore = session_store or InMemorySessionStore()
        self.policy_registry: CentralPolicyRegistry = policy_registry or CentralPolicyRegistry()
        if escalation_router is not None:
            self.escalation_router = escalation_router
            if self.escalation_router.redactor is None and self.redactor is not None:
                self.escalation_router.redactor = self.redactor
        else:
            self.escalation_router = EscalationRouter(
                session_store=self.session_store,
                redactor=self.redactor,
            )
        self.registry: ToolRegistry = registry if registry is not None else ToolRegistry()
        self.advisor: Optional[Any] = advisor
        self.strict_provenance: bool = strict_provenance
        self.max_tool_retries: int = max_tool_retries
        self.auto_rollback_on_block: bool = auto_rollback_on_block
        self.auto_rollback_on_error: bool = auto_rollback_on_error
        self.default_session_id: str = default_session_id

        # Tool name -> (upstream_key, raw_upstream_tool_name, mcp_schema_dict)
        self._tool_routes: Dict[str, Tuple[str, str, Dict[str, Any]]] = {}
        self._pinned_tool_hashes: Dict[str, str] = {}
        self._compromised_tools: Dict[str, Tuple[str, str]] = {}
        self._load_pinned_schemas_from_store()
        self.sync_tools()

    _PINNED_SCHEMAS_NAMESPACE = "mcp_pinned_tool_schemas"

    def _load_pinned_schemas_from_store(self) -> None:
        if not (
            hasattr(self.session_store, "load_control_doc")
            and hasattr(self.session_store, "save_control_doc")
        ):
            return
        doc = self.session_store.load_control_doc(self._PINNED_SCHEMAS_NAMESPACE)
        if not isinstance(doc, dict):
            return
        raw_hashes = doc.get("hashes")
        if isinstance(raw_hashes, dict):
            for k, v in raw_hashes.items():
                self._pinned_tool_hashes.setdefault(str(k), str(v))
        raw_comp = doc.get("compromised")
        if isinstance(raw_comp, dict):
            for k, v in raw_comp.items():
                if isinstance(v, (list, tuple)) and len(v) == 2:
                    self._compromised_tools.setdefault(str(k), (str(v[0]), str(v[1])))

    def _save_pinned_schemas_to_store(self) -> None:
        if not hasattr(self.session_store, "save_control_doc"):
            return
        self.session_store.save_control_doc(
            self._PINNED_SCHEMAS_NAMESPACE,
            {
                "hashes": dict(self._pinned_tool_hashes),
                "compromised": {k: [v[0], v[1]] for k, v in self._compromised_tools.items()},
            },
        )

    def sync_tools(self) -> int:
        """
        Refresh tool catalog from upstream MCP server(s), synchronize proxy `ToolRegistry`,
        verify pinned schema hashes / tool poisoning, and bind upstream forwarders.
        """
        with self._lock:
            self._load_pinned_schemas_from_store()
            new_routes: Dict[str, Tuple[str, str, Dict[str, Any]]] = {}
            self.registry._tools.clear()

            for upstream_key, client in self._upstreams.items():
                for raw_tool in client.list_tools():
                    raw_name = str(raw_tool["name"])
                    exposed_name = (
                        f"{upstream_key}{self.federated_separator}{raw_name}"
                        if self._federated
                        else raw_name
                    )
                    schema = dict(raw_tool)
                    schema["name"] = exposed_name
                    meta = dict(raw_tool.get("_slim_meta") or {})
                    description_text = str(raw_tool.get("description") or "")
                    input_schema_dict = dict(
                        raw_tool.get("inputSchema") or {"type": "object", "properties": {}}
                    )
                    schema_hash = compute_tool_schema_hash(
                        {
                            "name": exposed_name,
                            "description": description_text,
                            "inputSchema": input_schema_dict,
                        }
                    )

                    if self.detect_tool_poisoning:
                        poison_reason = detect_tool_description_poisoning(
                            exposed_name, description_text, input_schema_dict
                        )
                        if poison_reason:
                            self._compromised_tools[exposed_name] = (
                                "mcp_tool_poisoning",
                                f"Tool '{exposed_name}' quarantined due to description/schema poisoning: {poison_reason}",
                            )
                            logger.warning(
                                "Quarantined poisoned MCP tool '%s': %s", exposed_name, poison_reason
                            )

                    if self.pin_tool_schemas:
                        pinned_hash = self._pinned_tool_hashes.get(exposed_name)
                        if pinned_hash is None:
                            self._pinned_tool_hashes[exposed_name] = schema_hash
                        elif pinned_hash != schema_hash and exposed_name not in self._compromised_tools:
                            self._compromised_tools[exposed_name] = (
                                "mcp_tool_rug_pull",
                                (
                                    f"Tool '{exposed_name}' schema/description changed mid-session "
                                    f"(pinned sha256:{pinned_hash[:12]}..., observed sha256:{schema_hash[:12]}...)."
                                ),
                            )
                            logger.warning(
                                "Quarantined rug-pulled MCP tool '%s' (schema hash mismatch)",
                                exposed_name,
                            )

                    def _make_forwarder(c: MCPUpstream, r_name: str) -> Callable[..., Any]:
                        def _forward(**kwargs: Any) -> Any:
                            return c.call_tool(r_name, kwargs)
                        return _forward

                    def _make_aforwarder(c: MCPUpstream, r_name: str) -> Callable[..., Awaitable[Any]]:
                        async def _aforward(**kwargs: Any) -> Any:
                            return await c.acall_tool(r_name, kwargs)
                        return _aforward

                    fwd = _make_forwarder(client, raw_name)
                    setattr(fwd, "afn", _make_aforwarder(client, raw_name))

                    self.registry.register(
                        fn=fwd,
                        name=exposed_name,
                        description=description_text or f"Execute MCP tool {exposed_name}",
                        parameters=input_schema_dict,
                        tags=list(raw_tool.get("tags") or ([upstream_key] if self._federated else [])),
                        mode=meta.get("mode"),
                        provides=meta.get("provides"),
                        requires=meta.get("requires"),
                        provenance_args=meta.get("provenance_args"),
                        policy=meta.get("policy"),
                        requires_approval=bool(meta.get("requires_approval", False)),
                        compensates_with=meta.get("compensates_with"),
                        compensation_args=meta.get("compensation_args"),
                    )
                    new_routes[exposed_name] = (upstream_key, raw_name, schema)

            self._tool_routes = new_routes
            self._save_pinned_schemas_to_store()
            if self.advisor is not None:
                self.advisor._registry = self.registry
                if hasattr(self.advisor, "compile_vector_matrix"):
                    self.advisor.compile_vector_matrix()
            return len(new_routes)

    def trust_updated_tool(self, tool_name: str) -> bool:
        """Explicitly approve an updated/quarantined MCP tool schema and re-pin its current hash."""
        with self._lock:
            route = self._tool_routes.get(tool_name)
            self._compromised_tools.pop(tool_name, None)
            if route is None:
                self._save_pinned_schemas_to_store()
                return False
            _, _, schema = route
            self._pinned_tool_hashes[tool_name] = compute_tool_schema_hash(
                {
                    "name": tool_name,
                    "description": str(schema.get("description") or ""),
                    "inputSchema": dict(schema.get("inputSchema") or {}),
                }
            )
            self._save_pinned_schemas_to_store()
            return True

    def _load_gate(self, session_id: str) -> PreExecutionGate:
        return PreExecutionGate.from_store(
            session_id=session_id,
            session_store=self.session_store,
            registry=self.registry,
            strict_provenance=self.strict_provenance,
            max_tool_retries=self.max_tool_retries,
            policy_registry=self.policy_registry,
            escalation_router=self.escalation_router,
            auto_persist=True,
            redactor=self.redactor,
            audit_sink=self.audit_sink,
            shadow_mode=self.shadow_mode,
            require_user_intent=self.require_user_intent,
            block_outbound_secrets=self.block_outbound_secrets,
            block_ssrf_and_sensitive_paths=self.block_ssrf_and_sensitive_paths,
            default_max_calls_per_minute=self.default_max_calls_per_minute,
            default_session_spend_limit=self.default_session_spend_limit,
            global_max_calls_per_minute=self.global_max_calls_per_minute,
            global_actor_spend_limit=self.global_actor_spend_limit,
            resolve_dns_for_ssrf=self.resolve_dns_for_ssrf,
        )

    @staticmethod
    def _extract_meta(
        params: Dict[str, Any],
    ) -> Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]]:
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            meta = {}
        raw_actor = meta.get("actor_id") or params.get("actor_id")
        raw_idem = meta.get("idempotency_key") or params.get("idempotency_key")
        return (
            str(meta.get("session_id") or params.get("session_id") or "default"),
            meta.get("approval_token"),
            meta.get("user_prompt"),
            str(raw_actor) if raw_actor is not None else None,
            str(raw_idem) if raw_idem not in (None, "") else None,
        )

    @staticmethod
    def _is_upstream_error(result: Any) -> bool:
        if isinstance(result, dict):
            if result.get("isError") is True:
                return True
            if result.get("error"):
                return True
        return False

    @staticmethod
    def _normalize_mcp_result(result: Any) -> Dict[str, Any]:
        """Convert arbitrary Python/upstream return value into a compliant MCP CallToolResult."""
        if isinstance(result, dict) and "content" in result and isinstance(result["content"], list):
            out = dict(result)
            out.setdefault("isError", False)
            return out

        text = result if isinstance(result, str) else json.dumps(result, default=str)
        payload: Dict[str, Any] = {
            "content": [{"type": "text", "text": text}],
            "isError": False,
        }
        if isinstance(result, dict):
            payload["structuredContent"] = result
        return payload

    @staticmethod
    def _extract_structured_payload(result: Any) -> Any:
        """Extract JSON dict from an MCP CallToolResult content block if present for Ledger provenance."""
        if isinstance(result, dict):
            if isinstance(result.get("structuredContent"), dict):
                return result["structuredContent"]
            content = result.get("content")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        try:
                            parsed = json.loads(item["text"])
                            if isinstance(parsed, (dict, list)):
                                return parsed
                        except Exception:
                            pass
        return result

    def handle_tools_list(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle `tools/list` with `CentralPolicyRegistry` filtering and optional JIT pruning."""
        p = params or {}
        meta = p.get("_meta") if isinstance(p.get("_meta"), dict) else {}
        query = p.get("query") or meta.get("query")
        top_k = int(p.get("top_k") or meta.get("top_k") or 5)

        with self._lock:
            enabled_schemas: List[Dict[str, Any]] = []
            schema_by_name: Dict[str, Dict[str, Any]] = {}
            for name, (_ukey, _raw, schema) in self._tool_routes.items():
                if name in self._compromised_tools:
                    continue
                pol = self.policy_registry.get_policy(name)
                if pol is not None and not pol.enabled:
                    continue
                clean_schema = {k: v for k, v in schema.items() if k != "_slim_meta"}
                if pol is not None and pol.description:
                    clean_schema["description"] = pol.description
                enabled_schemas.append(clean_schema)
                schema_by_name[name] = clean_schema

        total_count = len(enabled_schemas)
        returned_schemas = enabled_schemas

        if query and self.advisor is not None:
            advice = self.advisor.prune(str(query), top_k=top_k)
            pruned_tools = getattr(advice, "tools", []) or []
            pruned_names = {t.name for t in pruned_tools}
            if pruned_names:
                returned_schemas = [s for s in enabled_schemas if s["name"] in pruned_names]

        reduction = (
            round((1.0 - (len(returned_schemas) / total_count)) * 100.0, 2)
            if total_count > 0
            else 0.0
        )
        return {
            "tools": returned_schemas,
            "_slim": {
                "total_tools": total_count,
                "returned_tools": len(returned_schemas),
                "reduction_pct": reduction,
            },
        }

    def _prepare_call_context(
        self, params: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any], str, Optional[str], Optional[str], Optional[str], Optional[str]]:
        name = str(params.get("name") or "")
        arguments = dict(params.get("arguments") or {})
        session_id, approval_token, user_prompt, actor_id, idempotency_key = self._extract_meta(params)
        if session_id == "default" and "_meta" not in params and "session_id" not in params:
            session_id = self.default_session_id
        return name, arguments, session_id, approval_token, user_prompt, actor_id, idempotency_key

    def _effective_tool_spec(self, name: str) -> Optional[Any]:
        tool_def = self.registry.get(name)
        policy_spec = self.policy_registry.get_policy(name) if self.policy_registry else None
        if tool_def is not None:
            return resolve_effective_tool(tool_def, policy_spec)
        return policy_spec

    @staticmethod
    def _is_mutating_spec(effective: Optional[Any]) -> bool:
        if effective is None:
            return False
        mode = str(getattr(effective, "mode", "") or "").lower()
        return (
            mode in ("write", "destructive")
            or bool(getattr(effective, "compensates_with", None))
            or callable(getattr(effective, "on_rollback", None))
        )

    def _check_idempotency_before_gate(
        self,
        gate: PreExecutionGate,
        name: str,
        arguments: Dict[str, Any],
        idempotency_key: Optional[str],
        actor_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        if not idempotency_key:
            return None
        fp = canonical_action_fingerprint(name, arguments)
        status, payload = gate.saga.get_idempotent_replay(idempotency_key, fingerprint=fp)
        if status == "HIT" and isinstance(payload, dict):
            return copy.deepcopy(payload)
        if status == "CONFLICT":
            decision = gate._finalize(
                t0=time.perf_counter(),
                tool_name=name,
                args=arguments,
                verdict=Verdict.BLOCK,
                rule_triggered="idempotency_key_conflict",
                reason=(
                    f"Idempotency-Key '{idempotency_key}' was already used with a different "
                    f"tool or argument payload."
                ),
                instruction="Generate a fresh Idempotency-Key for distinct arguments or replay identical parameters.",
                actor_id=actor_id,
            )
            return self._format_blocked_decision(decision, None)
        if status == "IN_FLIGHT":
            decision = gate._finalize(
                t0=time.perf_counter(),
                tool_name=name,
                args=arguments,
                verdict=Verdict.BLOCK,
                rule_triggered="idempotency_key_in_flight",
                reason=f"A mutation with Idempotency-Key '{idempotency_key}' is currently IN_FLIGHT.",
                instruction="Wait for the active call to finish or recover stale sessions before retrying.",
                actor_id=actor_id,
            )
            return self._format_blocked_decision(decision, None)
        return None

    def _begin_wal_if_mutating(
        self,
        gate: PreExecutionGate,
        name: str,
        arguments: Dict[str, Any],
        idempotency_key: Optional[str],
        *,
        persist: bool = True,
    ) -> Optional[str]:
        effective = self._effective_tool_spec(name)
        if not (self._is_mutating_spec(effective) or idempotency_key):
            return None
        wal_id = f"wal_{uuid.uuid4().hex[:12]}"
        stored_args = self.redactor.redact_dict(arguments) if self.redactor is not None else dict(arguments)
        gate.saga.begin_in_flight(
            wal_id=wal_id,
            tool_name=name,
            forward_args=stored_args,
            idempotency_key=idempotency_key,
            compensating_tool=getattr(effective, "compensates_with", None) if effective else None,
            compensation_args=getattr(effective, "compensation_args", None) if effective else None,
            fingerprint=canonical_action_fingerprint(name, arguments),
        )
        if persist:
            gate.save()
        else:
            gate._auto_save_dirty = True
        return wal_id

    def _should_rollback_on_block(
        self, gate: PreExecutionGate, decision: GateDecision
    ) -> bool:
        return (
            decision.verdict == Verdict.BLOCK
            and self.auto_rollback_on_block
            and gate.saga.pending_count > 0
        )

    @staticmethod
    def _format_blocked_decision(
        decision: GateDecision, rollback_summary: Optional[Any]
    ) -> Dict[str, Any]:
        err_payload: Dict[str, Any] = {
            "verdict": decision.verdict.value,
            "rule_triggered": decision.rule_triggered,
            "reason": decision.reason,
            "instruction": decision.instruction,
            "ledger_facts": decision.ledger_facts,
        }
        if rollback_summary is not None:
            err_payload["rollback"] = {
                "success": rollback_summary.success,
                "compensated_steps": rollback_summary.compensated_steps,
                "failed_steps": rollback_summary.failed_steps,
            }
        return {
            "isError": True,
            "content": [{"type": "text", "text": json.dumps(err_payload)}],
            "structuredContent": err_payload,
        }

    @staticmethod
    def _format_upstream_failure(
        gate: PreExecutionGate,
        name: str,
        err_value: Any,
        rollback_summary: Optional[Any],
        *,
        is_exception: bool = False,
    ) -> Dict[str, Any]:
        rollback_info = None
        if rollback_summary is not None:
            rollback_info = {
                "success": rollback_summary.success,
                "compensated_steps": rollback_summary.compensated_steps,
                "failed_steps": rollback_summary.failed_steps,
            }
            if is_exception:
                rollback_info["details"] = rollback_summary.details
        gate.save()

        if is_exception:
            err_payload: Dict[str, Any] = {
                "error": str(err_value),
                "tool": name,
                "auto_rollback": rollback_info,
            }
        else:
            err_payload = {
                "error": err_value.get("error") if isinstance(err_value, dict) else str(err_value),
                "raw_result": err_value,
                "auto_rollback": rollback_info,
            }
        if rollback_info is not None:
            err_payload["transaction_aborted"] = True
            err_payload["instruction"] = (
                "Upstream failure triggered automatic Saga rollback; do NOT retry rolled-back mutations "
                "in this turn. Inform the user of the failure and rollback."
            )
        return {
            "isError": True,
            "content": [{"type": "text", "text": json.dumps(err_payload)}],
            "structuredContent": err_payload,
        }

    def _absorb_and_normalize(
        self,
        gate: PreExecutionGate,
        name: str,
        arguments: Dict[str, Any],
        raw_result: Any,
        *,
        wal_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        decision: Optional[GateDecision] = None,
    ) -> Dict[str, Any]:
        effective = self._effective_tool_spec(name)
        ledger_payload = self._extract_structured_payload(raw_result)
        stored_args = self.redactor.redact_dict(arguments) if self.redactor is not None else arguments
        stored_result = (
            self.redactor.redact_value(ledger_payload)
            if self.redactor is not None
            else ledger_payload
        )
        with gate.batch_save():
            gate.ledger.absorb_tool_return(
                tool_name=name,
                args=stored_args,
                result=stored_result,
                mode=getattr(effective, "mode", None) if effective else None,
                provides=getattr(effective, "provides", None) if effective else None,
                compensates_with=getattr(effective, "compensates_with", None) if effective else None,
                compensation_args=getattr(effective, "compensation_args", None) if effective else None,
                on_rollback=getattr(effective, "on_rollback", None) if effective else None,
                registry=self.registry,
            )
            normalized = self._normalize_mcp_result(raw_result)
            if decision is not None and decision.ledger_facts.get("shadow_would_verdict"):
                normalized["_shadow"] = {
                    "would_verdict": decision.ledger_facts["shadow_would_verdict"],
                    "rule_triggered": decision.rule_triggered,
                    "reason": decision.reason,
                }
            if wal_id is not None:
                gate.saga.finish_in_flight(
                    wal_id,
                    success=True,
                    idempotency_key=idempotency_key,
                    fingerprint=canonical_action_fingerprint(name, arguments),
                    cached_result=normalized,
                )
            if not gate.auto_persist:
                gate.save()
            else:
                gate._auto_save_dirty = True
        return normalized

    def _check_compromised_tool(
        self,
        gate: PreExecutionGate,
        name: str,
        arguments: Dict[str, Any],
        actor_id: Optional[str],
    ) -> Optional[GateDecision]:
        with self._lock:
            compromised = self._compromised_tools.get(name)
        if compromised is None:
            return None
        rule_triggered, reason = compromised
        return gate._finalize(
            t0=time.perf_counter(),
            tool_name=name,
            args=arguments,
            verdict=Verdict.BLOCK,
            rule_triggered=rule_triggered,
            reason=reason,
            instruction=(
                "Tool is quarantined due to metadata poisoning or mid-session schema mutation. "
                "Do not invoke it without administrator review (`trust_updated_tool`)."
            ),
            actor_id=actor_id,
        )

    def handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP `tools/call` synchronously with full Gatekeep & Saga lifecycle."""
        (
            name,
            arguments,
            session_id,
            approval_token,
            user_prompt,
            actor_id,
            idempotency_key,
        ) = self._prepare_call_context(params)

        with self.session_store.session_lock(session_id):
            gate = self._load_gate(session_id)
            if user_prompt:
                gate.ledger.observe_user_input(str(user_prompt))

            replay_resp = self._check_idempotency_before_gate(
                gate, name, arguments, idempotency_key, actor_id
            )
            if replay_resp is not None:
                return replay_resp

            decision = self._check_compromised_tool(gate, name, arguments, actor_id)
            if decision is None:
                decision = gate.evaluate(
                    tool_name=name,
                    arguments=arguments,
                    approval_token=approval_token,
                    actor_id=actor_id,
                )
            if not decision.allowed:
                rb = gate.rollback() if self._should_rollback_on_block(gate, decision) else None
                return self._format_blocked_decision(decision, rb)

            route = self._tool_routes.get(name)
            if route is None:
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Unknown tool route '{name}'."}],
                }

            upstream_key, raw_name, _schema = route
            client = self._upstreams[upstream_key]
            wal_id = self._begin_wal_if_mutating(gate, name, arguments, idempotency_key)

            try:
                raw_result = client.call_tool(raw_name, arguments)
            except Exception as exc:
                if wal_id is not None:
                    gate.saga.finish_in_flight(wal_id, success=False)
                rb = (
                    gate.rollback()
                    if self.auto_rollback_on_error and (gate.saga.pending_count > 0 or gate.saga.in_flight_count > 0)
                    else None
                )
                return self._format_upstream_failure(gate, name, exc, rb, is_exception=True)

            if self._is_upstream_error(raw_result):
                if wal_id is not None:
                    gate.saga.finish_in_flight(wal_id, success=False)
                rb = (
                    gate.rollback()
                    if self.auto_rollback_on_error and (gate.saga.pending_count > 0 or gate.saga.in_flight_count > 0)
                    else None
                )
                return self._format_upstream_failure(
                    gate, name, raw_result, rb, is_exception=False
                )

            return self._absorb_and_normalize(
                gate,
                name,
                arguments,
                raw_result,
                wal_id=wal_id,
                idempotency_key=idempotency_key,
                decision=decision,
            )

    def _store_needs_thread_offload(self) -> bool:
        """Return True if persistence operations perform blocking disk/network I/O."""
        return not isinstance(self.session_store, InMemorySessionStore)

    async def _run_store_op(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if self._store_needs_thread_offload():
            return await asyncio.to_thread(fn, *args, **kwargs)
        return fn(*args, **kwargs)

    async def ahandle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP `tools/call` asynchronously with full Gatekeep & Saga lifecycle."""
        (
            name,
            arguments,
            session_id,
            approval_token,
            user_prompt,
            actor_id,
            idempotency_key,
        ) = self._prepare_call_context(params)

        async with self.session_store.async_session_lock(session_id):
            def _load_and_precheck() -> Tuple[PreExecutionGate, Optional[Dict[str, Any]], Optional[GateDecision]]:
                g = self._load_gate(session_id)
                if user_prompt:
                    g.ledger.observe_user_input(str(user_prompt))
                replay = self._check_idempotency_before_gate(
                    g, name, arguments, idempotency_key, actor_id
                )
                if replay is not None:
                    return g, replay, None
                comp_dec = self._check_compromised_tool(g, name, arguments, actor_id)
                return g, None, comp_dec

            gate, replay_resp, decision = await self._run_store_op(_load_and_precheck)
            if replay_resp is not None:
                return replay_resp

            with gate.batch_save(flush=False):
                if decision is None:
                    decision = await gate.aevaluate(
                        tool_name=name,
                        arguments=arguments,
                        approval_token=approval_token,
                        actor_id=actor_id,
                    )
                if not decision.allowed:
                    wal_id = None
                else:
                    route = self._tool_routes.get(name)
                    wal_id = (
                        self._begin_wal_if_mutating(
                            gate, name, arguments, idempotency_key, persist=False
                        )
                        if route is not None
                        else None
                    )
            if gate._consume_dirty_save():
                await self._run_store_op(gate.save)
            if not decision.allowed:
                rb = (
                    await gate.arollback()
                    if self._should_rollback_on_block(gate, decision)
                    else None
                )
                return self._format_blocked_decision(decision, rb)

            route = self._tool_routes.get(name)
            if route is None:
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Unknown tool route '{name}'."}],
                }

            upstream_key, raw_name, _schema = route
            client = self._upstreams[upstream_key]

            try:
                raw_result = await client.acall_tool(raw_name, arguments)
            except Exception as exc:
                if wal_id is not None:
                    gate.saga.finish_in_flight(wal_id, success=False)
                rb = (
                    await gate.arollback()
                    if self.auto_rollback_on_error
                    and (gate.saga.pending_count > 0 or gate.saga.in_flight_count > 0)
                    else None
                )
                return await self._run_store_op(
                    self._format_upstream_failure,
                    gate,
                    name,
                    exc,
                    rb,
                    is_exception=True,
                )

            if self._is_upstream_error(raw_result):
                if wal_id is not None:
                    gate.saga.finish_in_flight(wal_id, success=False)
                rb = (
                    await gate.arollback()
                    if self.auto_rollback_on_error
                    and (gate.saga.pending_count > 0 or gate.saga.in_flight_count > 0)
                    else None
                )
                return await self._run_store_op(
                    self._format_upstream_failure,
                    gate,
                    name,
                    raw_result,
                    rb,
                    is_exception=False,
                )

            return await self._run_store_op(
                self._absorb_and_normalize,
                gate,
                name,
                arguments,
                raw_result,
                wal_id=wal_id,
                idempotency_key=idempotency_key,
                decision=decision,
            )

    def handle_resources_list(self) -> Dict[str, Any]:
        """List MCP resources exposed across upstream servers."""
        resources: List[Dict[str, Any]] = []
        for upstream_key, client in self._upstreams.items():
            for raw_res in client.list_resources():
                item = dict(raw_res)
                if self._federated and "uri" in item:
                    item.setdefault("_upstream", upstream_key)
                resources.append(item)
        return {"resources": resources}

    def _record_resource_read(
        self,
        params: Dict[str, Any],
        uri: str,
        raw_res: Any,
    ) -> Dict[str, Any]:
        session_id, _tok, _prompt, actor_id, _idem = self._extract_meta(params)
        if session_id == "default" and "_meta" not in params and "session_id" not in params:
            session_id = self.default_session_id
        with self.session_store.session_lock(session_id):
            gate = self._load_gate(session_id)
            gate._record_receipt(
                tool_name="resources/read",
                args={"uri": uri},
                verdict=Verdict.ALLOW,
                rule_triggered="mcp_resource_read",
                reason="Untrusted external MCP resource read quarantined from entity provenance.",
                actor_id=actor_id,
            )
            gate.save()
        if isinstance(raw_res, dict) and "contents" in raw_res:
            return raw_res
        return {"contents": [{"uri": uri, "text": raw_res if isinstance(raw_res, str) else json.dumps(raw_res, default=str)}]}

    def handle_resources_read(self, params: Dict[str, Any]) -> Dict[str, Any]:
        uri = str(params.get("uri") or "")
        for client in self._upstreams.values():
            try:
                raw_res = client.read_resource(uri)
                return self._record_resource_read(params, uri, raw_res)
            except NotImplementedError:
                continue
        raise ValueError(f"No upstream server could read MCP resource '{uri}'.")

    async def ahandle_resources_read(self, params: Dict[str, Any]) -> Dict[str, Any]:
        uri = str(params.get("uri") or "")
        for client in self._upstreams.values():
            try:
                raw_res = await client.aread_resource(uri)
                return await self._run_store_op(self._record_resource_read, params, uri, raw_res)
            except NotImplementedError:
                continue
        raise ValueError(f"No upstream server could read MCP resource '{uri}'.")

    def _handle_non_call_jsonrpc(
        self, req_id: Any, method: str, params: Dict[str, Any]
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Dispatch non-`tools/call` JSON-RPC methods identically for sync and async paths."""
        if method == "notifications/initialized":
            return True, (None if req_id is None else _jsonrpc_ok(req_id, {}))

        if method == "initialize":
            return True, _jsonrpc_ok(
                req_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": True}, "resources": {}},
                    "serverInfo": {"name": "gatekeep-mcp-proxy", "version": "0.2.0"},
                },
            )

        if method == "ping":
            return True, _jsonrpc_ok(req_id, {})

        if method == "tools/list":
            return True, _jsonrpc_ok(req_id, self.handle_tools_list(params))

        if method == "resources/list":
            return True, _jsonrpc_ok(req_id, self.handle_resources_list())

        if method == "resources/read":
            if "uri" not in params:
                return True, _jsonrpc_error(req_id, -32602, "Missing required parameter 'uri'.")
            try:
                return True, _jsonrpc_ok(req_id, self.handle_resources_read(params))
            except Exception as exc:
                return True, _jsonrpc_error(req_id, -32602, str(exc))

        if method == "slim/observe_user":
            session_id = str(params.get("session_id") or self.default_session_id)
            text = str(params.get("text") or "")
            advance_turn = bool(params.get("advance_turn", True))
            with self.session_store.session_lock(session_id):
                gate = self._load_gate(session_id)
                if advance_turn:
                    gate.ledger.advance_turn()
                gate.ledger.observe_user_input(text)
                gate.save()
                return True, _jsonrpc_ok(
                    req_id, {"session_id": session_id, "turn": gate.ledger.turn}
                )

        if method == "slim/rollback":
            session_id = str(params.get("session_id") or self.default_session_id)
            with self.session_store.session_lock(session_id):
                gate = self._load_gate(session_id)
                summary = gate.rollback(stop_on_error=bool(params.get("stop_on_error", False)))
                return True, _jsonrpc_ok(
                    req_id,
                    {
                        "session_id": session_id,
                        "success": summary.success,
                        "total_steps": summary.total_steps,
                        "compensated_steps": summary.compensated_steps,
                        "failed_steps": summary.failed_steps,
                        "details": summary.details,
                    },
                )

        if method == "slim/commit":
            session_id = str(params.get("session_id") or self.default_session_id)
            with self.session_store.session_lock(session_id):
                gate = self._load_gate(session_id)
                gate.commit()
                return True, _jsonrpc_ok(
                    req_id,
                    {"session_id": session_id, "pending_saga_steps": gate.saga.pending_count},
                )

        if method == "slim/audit_verify":
            session_id = str(params.get("session_id") or self.default_session_id)
            with self.session_store.session_lock(session_id):
                gate = self._load_gate(session_id)
                return True, _jsonrpc_ok(
                    req_id,
                    {
                        "session_id": session_id,
                        "chain_valid": gate.verify_audit_chain(),
                        "receipt_count": len(gate.receipts),
                    },
                )

        return False, None

    def handle_jsonrpc(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single MCP JSON-RPC 2.0 request frame (returns None for notifications)."""
        req_id = request.get("id")
        method = str(request.get("method") or "")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return _jsonrpc_error(req_id, -32602, "Invalid params: expected JSON object.")

        if method == "tools/call":
            if "name" not in params:
                return _jsonrpc_error(req_id, -32602, "Missing required parameter 'name'.")
            return _jsonrpc_ok(req_id, self.handle_tools_call(params))

        handled, response = self._handle_non_call_jsonrpc(req_id, method, params)
        if handled:
            return response
        return _jsonrpc_error(req_id, -32601, f"Method not found: '{method}'.")

    async def ahandle_jsonrpc(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Async variant of `handle_jsonrpc()` using non-blocking `ahandle_tools_call()`."""
        req_id = request.get("id")
        method = str(request.get("method") or "")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return _jsonrpc_error(req_id, -32602, "Invalid params: expected JSON object.")

        if method == "tools/call":
            if "name" not in params:
                return _jsonrpc_error(req_id, -32602, "Missing required parameter 'name'.")
            return _jsonrpc_ok(req_id, await self.ahandle_tools_call(params))

        if method == "resources/read":
            if "uri" not in params:
                return _jsonrpc_error(req_id, -32602, "Missing required parameter 'uri'.")
            try:
                return _jsonrpc_ok(req_id, await self.ahandle_resources_read(params))
            except Exception as exc:
                return _jsonrpc_error(req_id, -32602, str(exc))

        if method == "slim/rollback":
            session_id = str(params.get("session_id") or self.default_session_id)
            async with self.session_store.async_session_lock(session_id):
                gate = await self._run_store_op(self._load_gate, session_id)
                summary = await gate.arollback(
                    stop_on_error=bool(params.get("stop_on_error", False))
                )
                return _jsonrpc_ok(
                    req_id,
                    {
                        "session_id": session_id,
                        "success": summary.success,
                        "total_steps": summary.total_steps,
                        "compensated_steps": summary.compensated_steps,
                        "failed_steps": summary.failed_steps,
                        "details": summary.details,
                    },
                )

        if method == "slim/observe_user":
            session_id = str(params.get("session_id") or self.default_session_id)
            text = str(params.get("text") or "")
            advance_turn = bool(params.get("advance_turn", True))

            def _do_observe() -> Dict[str, Any]:
                gate = self._load_gate(session_id)
                if advance_turn:
                    gate.ledger.advance_turn()
                gate.ledger.observe_user_input(text)
                gate.save()
                return _jsonrpc_ok(req_id, {"session_id": session_id, "turn": gate.ledger.turn})

            async with self.session_store.async_session_lock(session_id):
                return await self._run_store_op(_do_observe)

        if method == "slim/commit":
            session_id = str(params.get("session_id") or self.default_session_id)

            def _do_commit() -> Dict[str, Any]:
                gate = self._load_gate(session_id)
                gate.commit()
                return _jsonrpc_ok(
                    req_id,
                    {"session_id": session_id, "pending_saga_steps": gate.saga.pending_count},
                )

            async with self.session_store.async_session_lock(session_id):
                return await self._run_store_op(_do_commit)

        if method == "slim/audit_verify":
            session_id = str(params.get("session_id") or self.default_session_id)

            def _do_verify() -> Dict[str, Any]:
                gate = self._load_gate(session_id)
                return _jsonrpc_ok(
                    req_id,
                    {
                        "session_id": session_id,
                        "chain_valid": gate.verify_audit_chain(),
                        "receipt_count": len(gate.receipts),
                    },
                )

            async with self.session_store.async_session_lock(session_id):
                return await self._run_store_op(_do_verify)

        handled, response = self._handle_non_call_jsonrpc(req_id, method, params)
        if handled:
            return response
        return _jsonrpc_error(req_id, -32601, f"Method not found: '{method}'.")

    def serve_stdio(
        self,
        stdin: Optional[IO[str]] = None,
        stdout: Optional[IO[str]] = None,
    ) -> None:
        """
        Run a synchronous newline-delimited JSON-RPC 2.0 MCP server loop over stdio
        (compatible with Claude Desktop, Cursor, Windsurf, and MCP CLI clients).
        """
        in_stream = stdin or sys.stdin
        out_stream = stdout or sys.stdout

        for raw_line in in_stream:
            line = raw_line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_jsonrpc(req)
            except json.JSONDecodeError as exc:
                resp = _jsonrpc_error(None, -32700, f"Parse error: {exc}")
            except Exception as exc:
                resp = _jsonrpc_error(None, -32603, f"Internal error: {exc}")

            if resp is not None:
                out_stream.write(json.dumps(resp) + "\n")
                out_stream.flush()
