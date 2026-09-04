#!/usr/bin/env python3
"""Proxy Splunk MCP while removing JSON Schema regexes OpenAI rejects."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Sequence
from typing import Any

from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.middleware import Middleware
from fastmcp.server.middleware.response_limiting import ResponseLimitingMiddleware
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.providers.proxy import FastMCPProxy, ProxyClient
from fastmcp.server.transforms import Transform
from fastmcp.tools import Tool


UPSTREAM_CALL_TIMEOUT_SECONDS = 90.0
UPSTREAM_CLOSE_TIMEOUT_SECONDS = 5.0
_DETACHED_TASKS: set[asyncio.Task[Any]] = set()


def detach_cancelled_task(task: asyncio.Task[Any]) -> None:
    """Cancel without awaiting a task that may suppress cancellation."""
    task.cancel()
    _DETACHED_TASKS.add(task)

    def consume(done: asyncio.Task[Any]) -> None:
        _DETACHED_TASKS.discard(done)
        if not done.cancelled():
            done.exception()

    task.add_done_callback(consume)


def sanitize_schema(value: Any) -> Any:
    """Remove regex extensions unsupported by OpenAI's JSON Schema subset."""
    if isinstance(value, dict):
        return {
            key: sanitize_schema(child)
            for key, child in value.items()
            if not (key == "pattern" and isinstance(child, str) and "(?" in child)
        }
    if isinstance(value, list):
        return [sanitize_schema(child) for child in value]
    return value


def sanitize_tool(tool: Tool) -> Tool:
    parameters = sanitize_schema(tool.parameters)
    if tool.name == "splunk_run_query":
        # These optional routing hints are unnecessary for this single-app gym.
        # Some OpenAI models populate optional strings with "", which Splunk's
        # server-side validation correctly rejects instead of treating as absent.
        parameters = dict(parameters)
        properties = dict(parameters.get("properties", {}))
        properties.pop("app", None)
        properties.pop("workload_pool", None)
        row_limit = dict(properties.get("row_limit", {}))
        row_limit.update({"default": 50, "maximum": 100})
        properties["row_limit"] = row_limit
        parameters["properties"] = properties
    if parameters == tool.parameters:
        return tool
    return tool.model_copy(update={"parameters": parameters}, deep=True)


class OpenAIJsonSchemaCompatibility(Transform):
    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        return [sanitize_tool(tool) for tool in tools]

    async def get_tool(
        self, name: str, call_next: Any, *, version: Any = None
    ) -> Tool | None:
        tool = await call_next(name, version=version)
        return sanitize_tool(tool) if tool is not None else None


class SplunkQueryGuard(Middleware):
    """Keep agent-authored search responses within an interactive envelope."""

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        if context.message.name != "splunk_run_query":
            return await call_next(context)
        arguments = dict(context.message.arguments or {})
        try:
            requested = int(arguments.get("row_limit", 50))
        except (TypeError, ValueError):
            requested = 50
        arguments["row_limit"] = max(1, min(requested, 100))
        message = context.message.model_copy(update={"arguments": arguments})
        return await call_next(context.copy(message=message))


class BoundedProxyClient(ProxyClient):
    """Apply a request deadline even though FastMCP's proxy passes None."""

    async def call_tool_mcp(
        self,
        name: str,
        arguments: dict[str, Any],
        progress_handler: Any = None,
        timeout: Any = None,
        meta: dict[str, Any] | None = None,
    ) -> Any:
        effective_timeout = (
            UPSTREAM_CALL_TIMEOUT_SECONDS if timeout is None else timeout
        )
        scope_seconds = (
            effective_timeout.total_seconds()
            if hasattr(effective_timeout, "total_seconds")
            else float(effective_timeout)
        )
        # The pinned FastMCP stream transport can suppress cancellation while
        # unwinding a wedged SSE request. Race the coroutine and deliberately
        # do not await its cancellation-resistant cleanup on timeout.
        call = asyncio.create_task(
            super().call_tool_mcp(
                name=name,
                arguments=arguments,
                progress_handler=progress_handler,
                timeout=effective_timeout,
                meta=meta,
            )
        )
        done, _ = await asyncio.wait({call}, timeout=scope_seconds)
        if not done:
            detach_cancelled_task(call)
            raise TimeoutError(
                f"upstream Splunk MCP call {name!r} exceeded {scope_seconds:g} seconds"
            )
        return call.result()

    async def __aexit__(self, *args: Any) -> Any:
        cleanup = asyncio.create_task(super().__aexit__(*args))
        done, _ = await asyncio.wait({cleanup}, timeout=UPSTREAM_CLOSE_TIMEOUT_SECONDS)
        if not done:
            detach_cancelled_task(cleanup)
            return None
        return cleanup.result()


def upstream_client() -> ProxyClient:
    """Forward only the caller's bearer credential to the official endpoint."""
    authorization = get_http_headers(include={"authorization"}).get("authorization")
    headers = {"Authorization": authorization} if authorization else None
    transport = StreamableHttpTransport(
        url=os.environ["SPLUNK_MCP_UPSTREAM_URL"],
        headers=headers,
    )
    # The Splunk app normally aborts searches at 60 seconds, but a transport
    # failure can otherwise leave an MCP request open indefinitely. Keep this
    # outer deadline above the app limit and well below the evaluator's
    # 45-minute per-investigation deadline.
    return BoundedProxyClient(transport)


server = FastMCPProxy(
    client_factory=upstream_client,
    name="Splunk MCP OpenAI schema compatibility proxy",
)
server.add_transform(OpenAIJsonSchemaCompatibility())
server.add_middleware(SplunkQueryGuard())
server.add_middleware(
    ResponseLimitingMiddleware(max_size=200_000, tools=["splunk_run_query"])
)


def main() -> None:
    server.run(
        transport="http",
        host="0.0.0.0",
        port=8000,
        path="/mcp",
        show_banner=False,
    )


if __name__ == "__main__":
    main()
