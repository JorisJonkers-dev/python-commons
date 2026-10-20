"""The Principal as ASGI middleware, for Starlette, FastAPI or any ASGI app: principal_middleware
reads each request's Principal, and the policy helpers guard the routes they wrap."""

import asyncio
import urllib.parse
from collections.abc import Awaitable, Callable, MutableMapping
from datetime import UTC, datetime, timedelta
from typing import Any

from .principal import Principal
from .reader import IdentityUnavailable, PrincipalReader, PrincipalRefused

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
Policy = Callable[[ASGIApp], ASGIApp]

#: The Gate's step-up on the app's own host, which proves two-factor again and comes back.
STEP_UP_PATH = "/.auth/step-up"

_REQUESTS = ("http", "websocket")
# A WebSocket refused before it is accepted closes with 1008, which the server answers as 403.
_POLICY_VIOLATION = 1008


def principal_of(scope: Scope) -> Principal | None:
    """The Principal principal_middleware read for the request, if any; Starlette's
    request.state.principal reads the same."""
    principal = scope.get("state", {}).get("principal")
    return principal if isinstance(principal, Principal) else None


def principal_middleware(app: ASGIApp, reader: PrincipalReader) -> ASGIApp:
    """Reads each request's Principal and passes it on in the request's state. A request whose
    Principal is refused is answered 401, and one identity could not be asked about 503."""

    async def middleware(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in _REQUESTS:
            await app(scope, receive, send)
            return
        headers = _headers(scope)
        try:
            principal = await asyncio.to_thread(reader.read, lambda name: headers.get(name.lower()))
        except PrincipalRefused:
            await _answer(scope, send, 401)
            return
        except IdentityUnavailable:
            await _answer(scope, send, 503)
            return
        await app({**scope, "state": {**scope.get("state", {}), "principal": principal}}, receive, send)

    return middleware


def _guard(allow: Callable[[Principal], bool]) -> Policy:
    """Lets a request through when allow says so of its Principal, answers 403 when it does not,
    and 401 when the request carries none."""

    def policy(app: ASGIApp) -> ASGIApp:
        async def guarded(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] not in _REQUESTS:
                await app(scope, receive, send)
                return
            principal = principal_of(scope)
            if principal is None:
                await _answer(scope, send, 401)
            elif not allow(principal):
                await _answer(scope, send, 403)
            else:
                await app(scope, receive, send)

        return guarded

    return policy


def require_role(role: str) -> Policy:
    """Lets through a caller holding role on the app's Client. It takes the str-typed App Roles
    deploy-kit generates as readily as a plain string."""
    return _guard(lambda p: role in p.roles)


def refuse_tools() -> Policy:
    """Turns away a tool acting for a User, so a tool can read but never, say, delete."""
    return _guard(lambda p: p.via != "tool")


def require_user() -> Policy:
    """Lets through only a person, never a Machine Identity."""
    return _guard(lambda p: p.kind == "user")


def require_machine() -> Policy:
    """Lets through only a Machine Identity, never a person."""
    return _guard(lambda p: p.kind == "machine")


def require_recent_two_factor(minutes: int, now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> Policy:
    """Lets through a session that proved two-factor within minutes. A session whose proof is older,
    or that has none, is sent to the Gate's step-up on the app's own host and comes back to the same
    page; a Personal Token, a tool or a machine, which no browser carries through a step-up, is
    answered 403."""
    window = timedelta(minutes=minutes)

    def policy(app: ASGIApp) -> ASGIApp:
        async def guarded(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] not in _REQUESTS:
                await app(scope, receive, send)
                return
            principal = principal_of(scope)
            if principal is None:
                await _answer(scope, send, 401)
            elif principal.two_factor_at is not None and now() - principal.two_factor_at <= window:
                await app(scope, receive, send)
            elif principal.via == "session":
                query = urllib.parse.urlencode({"minutes": minutes, "rd": _request_uri(scope)})
                await _answer(scope, send, 303, f"{STEP_UP_PATH}?{query}")
            else:
                await _answer(scope, send, 403)

        return guarded

    return policy


def _headers(scope: Scope) -> dict[str, str]:
    return {name.decode("latin-1").lower(): value.decode("latin-1") for name, value in scope.get("headers", [])}


def _request_uri(scope: Scope) -> str:
    path = str(scope.get("path") or "/")
    query = bytes(scope.get("query_string") or b"").decode("latin-1")
    return f"{path}?{query}" if query else path


async def _answer(scope: Scope, send: Send, status: int, location: str | None = None) -> None:
    if scope["type"] == "websocket":
        await send({"type": "websocket.close", "code": _POLICY_VIOLATION})
        return
    headers = [(b"content-length", b"0")]
    if location is not None:
        headers.append((b"location", location.encode("latin-1")))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": b""})
