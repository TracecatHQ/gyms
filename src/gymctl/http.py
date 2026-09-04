"""Tiny cookie-aware JSON client for dependency-free host-side checks."""

from __future__ import annotations

import json as jsonlib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from typing import Any


@dataclass(frozen=True)
class RequestInfo:
    method: str
    url: urllib.parse.SplitResult


class Response:
    def __init__(self, request: RequestInfo, status: int, content: bytes) -> None:
        self.request = request
        self.status_code = status
        self.content = content

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return jsonlib.loads(self.content)


class Client:
    def __init__(self, *, base_url: str, timeout: float = 120, **_: Any) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers: dict[str, str] = {}
        self.params: dict[str, Any] = {}
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(CookieJar())
        )

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        return None

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json: Any = None,
        timeout: float | None = None,
        **_: Any,
    ) -> Response:
        target = url if "://" in url else f"{self.base_url}/{url.lstrip('/')}"
        query = {**self.params, **(params or {})}
        if query:
            separator = "&" if "?" in target else "?"
            target += separator + urllib.parse.urlencode(query, doseq=True)
        headers = dict(self.headers)
        body: bytes | None = None
        if json is not None:
            body = jsonlib.dumps(json).encode()
            headers["Content-Type"] = "application/json"
        elif data is not None:
            body = (
                urllib.parse.urlencode(data).encode()
                if isinstance(data, dict)
                else data
            )
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(
            target, data=body, headers=headers, method=method
        )
        info = RequestInfo(method=method, url=urllib.parse.urlsplit(target))
        try:
            with self._opener.open(request, timeout=timeout or self.timeout) as result:
                return Response(info, result.status, result.read())
        except urllib.error.HTTPError as exc:
            return Response(info, exc.code, exc.read())

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)
