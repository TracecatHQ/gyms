"""Fail-closed DuckDB query-source policy for objective evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


MAX_SQL_BYTES = 20_000
MAX_AST_NODES = 20_000
MAX_AST_DEPTH = 128


@dataclass
class _AuditState:
    visited_nodes: int = 0
    cte_memo: dict[tuple[int, tuple[tuple[str, int], ...]], frozenset[str]] = field(
        default_factory=dict
    )

    def visit(self, depth: int) -> None:
        if depth > MAX_AST_DEPTH:
            raise ValueError(
                f"DuckDB SQL exceeds the {MAX_AST_DEPTH}-level AST depth limit"
            )
        self.visited_nodes += 1
        if self.visited_nodes > MAX_AST_NODES:
            raise ValueError(
                f"DuckDB SQL exceeds the {MAX_AST_NODES}-node AST audit limit"
            )


def _cte_scope_key(ctes: dict[str, dict[str, Any]]) -> tuple[tuple[str, int], ...]:
    return tuple(sorted((name, id(node)) for name, node in ctes.items()))


def _is_io_function(name: str) -> bool:
    return (
        name == "glob"
        or name.startswith("read_")
        or name.endswith("_scan")
        or name
        in {
            "http_get",
            "http_post",
            "query",
            "query_table",
            "sqlite_query",
            "postgres_query",
            "mysql_query",
        }
    )


def _serialized_sql_statement(sql: str) -> dict[str, Any]:
    """Parse SQL with the evaluator's pinned DuckDB without executing it."""

    try:
        import duckdb
    except ImportError as exc:  # pragma: no cover - the control image owns DuckDB
        raise ValueError("DuckDB SQL parser is unavailable") from exc

    connection = duckdb.connect()
    try:
        raw = connection.execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0]
    except Exception as exc:
        raise ValueError(f"DuckDB could not parse SQL: {exc}") from exc
    finally:
        connection.close()
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("DuckDB returned an invalid serialized SQL tree") from exc
    if not isinstance(parsed, dict) or parsed.get("error") is not False:
        message = parsed.get("error_message") if isinstance(parsed, dict) else None
        raise ValueError(f"DuckDB could not parse SQL: {message or 'unknown error'}")
    statements = parsed.get("statements")
    if not isinstance(statements, list) or len(statements) != 1:
        raise ValueError("exactly one SQL statement is required")
    statement = statements[0]
    if not isinstance(statement, dict) or statement.get("named_param_map"):
        raise ValueError("SQL parameters are forbidden")
    node = statement.get("node")
    if not isinstance(node, dict):
        raise ValueError("DuckDB SQL tree is missing its statement node")
    return node


def _cte_queries(node: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cte_map = node.get("cte_map")
    if not isinstance(cte_map, dict) or not isinstance(cte_map.get("map"), list):
        raise ValueError("DuckDB SQL tree has an invalid CTE map")
    queries: dict[str, dict[str, Any]] = {}
    for entry in cte_map["map"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("key"), str):
            raise ValueError("DuckDB SQL tree has an invalid CTE definition")
        value = entry.get("value")
        query = value.get("query") if isinstance(value, dict) else None
        query_node = query.get("node") if isinstance(query, dict) else None
        if not isinstance(query_node, dict) or query.get("named_param_map"):
            raise ValueError("DuckDB SQL tree has an invalid CTE query")
        name = entry["key"].casefold()
        if name in queries:
            raise ValueError(f"duplicate CTE name {entry['key']!r}")
        queries[name] = query_node
    return queries


def _literal_value(expression: Any) -> Any:
    if not isinstance(expression, dict) or expression.get("class") != "CONSTANT":
        raise ValueError("read_json_auto source must be one literal URL")
    value = expression.get("value")
    if not isinstance(value, dict) or value.get("is_null") is not False:
        raise ValueError("read_json_auto source must be one literal URL")
    return value.get("value")


def _audit_read_json_function(function: Any, exact_url: str) -> str:
    if not isinstance(function, dict) or function.get("class") != "FUNCTION":
        raise ValueError("DuckDB table source is missing its function")
    name = function.get("function_name")
    if name != "read_json_auto" or function.get("schema") not in {None, ""}:
        raise ValueError(f"table function {name!r} is forbidden")
    children = function.get("children")
    if not isinstance(children, list) or not children:
        raise ValueError("read_json_auto source must be one literal URL")
    url = _literal_value(children[0])
    if not isinstance(url, str) or url != exact_url:
        raise ValueError(f"read_json_auto source {url!r} is not the exact object")
    for option in children[1:]:
        if not isinstance(option, dict) or option.get("type") != "COMPARE_EQUAL":
            raise ValueError("read_json_auto accepts only literal named options")
        left = option.get("left")
        right = option.get("right")
        if (
            not isinstance(left, dict)
            or left.get("class") != "COLUMN_REF"
            or not isinstance(left.get("column_names"), list)
            or len(left["column_names"]) != 1
        ):
            raise ValueError("read_json_auto option name is invalid")
        _literal_value(right)
    return url


def _audit_nested_queries(
    value: Any,
    exact_url: str,
    ctes: dict[str, dict[str, Any]],
    active_ctes: frozenset[int],
    state: _AuditState,
    depth: int,
) -> set[str]:
    """Audit scalar subqueries and reject secondary I/O functions."""

    if isinstance(value, list):
        state.visit(depth)
        urls: set[str] = set()
        for item in value:
            urls.update(
                _audit_nested_queries(
                    item, exact_url, ctes, active_ctes, state, depth + 1
                )
            )
        return urls
    if not isinstance(value, dict):
        return set()
    state.visit(depth)
    wrapped_node = value.get("node")
    node_type = wrapped_node.get("type") if isinstance(wrapped_node, dict) else None
    if isinstance(node_type, str) and node_type.endswith("_NODE"):
        if value.get("named_param_map"):
            raise ValueError("SQL parameters are forbidden")
        return _audit_query_node(
            wrapped_node, exact_url, ctes, active_ctes, state, depth + 1
        )
    if value.get("class") == "FUNCTION":
        name = value.get("function_name")
        if isinstance(name, str) and _is_io_function(name):
            raise ValueError(f"I/O function {name!r} is forbidden")
    urls = set()
    for nested in value.values():
        urls.update(
            _audit_nested_queries(
                nested, exact_url, ctes, active_ctes, state, depth + 1
            )
        )
    return urls


def _audit_table_source(
    source: Any,
    exact_url: str,
    ctes: dict[str, dict[str, Any]],
    active_ctes: frozenset[int],
    state: _AuditState,
    depth: int,
) -> set[str]:
    state.visit(depth)
    if not isinstance(source, dict) or not isinstance(source.get("type"), str):
        raise ValueError("DuckDB SQL tree has an invalid table source")
    source_type = source["type"]
    if source_type == "EMPTY":
        return set()
    if source_type == "TABLE_FUNCTION":
        return {_audit_read_json_function(source.get("function"), exact_url)}
    if source_type == "BASE_TABLE":
        name = source.get("table_name")
        if (
            not isinstance(name, str)
            or source.get("schema_name") not in {None, ""}
            or source.get("catalog_name") not in {None, ""}
        ):
            raise ValueError(f"qualified table source {name!r} is forbidden")
        cte_node = ctes.get(name.casefold())
        if cte_node is None:
            raise ValueError(f"persistent or undeclared table {name!r} is forbidden")
        identity = id(cte_node)
        if identity in active_ctes:
            raise ValueError(f"recursive CTE {name!r} is forbidden")
        memo_key = (identity, _cte_scope_key(ctes))
        if memo_key in state.cte_memo:
            return set(state.cte_memo[memo_key])
        urls = _audit_query_node(
            cte_node,
            exact_url,
            ctes,
            active_ctes | {identity},
            state,
            depth + 1,
        )
        state.cte_memo[memo_key] = frozenset(urls)
        return urls
    if source_type == "JOIN":
        urls = _audit_table_source(
            source.get("left"), exact_url, ctes, active_ctes, state, depth + 1
        )
        urls.update(
            _audit_table_source(
                source.get("right"),
                exact_url,
                ctes,
                active_ctes,
                state,
                depth + 1,
            )
        )
        for key, nested in source.items():
            if key not in {"left", "right"}:
                urls.update(
                    _audit_nested_queries(
                        nested,
                        exact_url,
                        ctes,
                        active_ctes,
                        state,
                        depth + 1,
                    )
                )
        return urls
    if source_type == "SUBQUERY":
        query = source.get("subquery")
        query_node = query.get("node") if isinstance(query, dict) else None
        if not isinstance(query_node, dict) or query.get("named_param_map"):
            raise ValueError("DuckDB SQL tree has an invalid table subquery")
        return _audit_query_node(
            query_node, exact_url, ctes, active_ctes, state, depth + 1
        )
    raise ValueError(f"table source type {source_type!r} is forbidden")


def _audit_query_node(
    node: dict[str, Any],
    exact_url: str,
    inherited_ctes: dict[str, dict[str, Any]],
    active_ctes: frozenset[int],
    state: _AuditState,
    depth: int,
) -> set[str]:
    state.visit(depth)
    local_ctes = dict(inherited_ctes)
    local_ctes.update(_cte_queries(node))
    node_type = node.get("type")
    if node_type == "SELECT_NODE":
        urls = _audit_table_source(
            node.get("from_table"),
            exact_url,
            local_ctes,
            active_ctes,
            state,
            depth + 1,
        )
        for key, nested in node.items():
            if key not in {"cte_map", "from_table"}:
                urls.update(
                    _audit_nested_queries(
                        nested,
                        exact_url,
                        local_ctes,
                        active_ctes,
                        state,
                        depth + 1,
                    )
                )
        return urls
    if node_type == "SET_OPERATION_NODE":
        left = node.get("left")
        right = node.get("right")
        if not isinstance(left, dict) or not isinstance(right, dict):
            raise ValueError("DuckDB set operation is missing a query branch")
        urls = _audit_query_node(
            left, exact_url, local_ctes, active_ctes, state, depth + 1
        )
        urls.update(
            _audit_query_node(
                right, exact_url, local_ctes, active_ctes, state, depth + 1
            )
        )
        for key, nested in node.items():
            if key not in {"cte_map", "left", "right"}:
                urls.update(
                    _audit_nested_queries(
                        nested,
                        exact_url,
                        local_ctes,
                        active_ctes,
                        state,
                        depth + 1,
                    )
                )
        return urls
    raise ValueError(f"SQL statement type {node_type!r} is forbidden")


def audit_sql_source_scope(sql: str, exact_url: str) -> tuple[list[str], str]:
    """Return reachable object URLs when the query uses only the exact object."""

    if len(sql.encode("utf-8")) > MAX_SQL_BYTES:
        raise ValueError(f"DuckDB SQL exceeds the {MAX_SQL_BYTES}-byte audit limit")
    node = _serialized_sql_statement(sql)
    object_urls = _audit_query_node(node, exact_url, {}, frozenset(), _AuditState(), 0)
    if not object_urls:
        raise ValueError(
            "query result does not depend on the exact read_json_auto object"
        )
    return sorted(object_urls), "reachable exact read_json_auto source only"
