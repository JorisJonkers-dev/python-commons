import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from jorisjonkers_commons.identity import (
    Actor,
    Headers,
    IdentityUnavailable,
    Principal,
    PrincipalReader,
    PrincipalRefused,
    principal_middleware,
    principal_of,
    refuse_tools,
    require_machine,
    require_recent_two_factor,
    require_role,
    require_user,
)
from jorisjonkers_commons.identity.asgi import Message, Policy, Scope

NOW = datetime(2026, 10, 20, 12, 0, 30, tzinfo=UTC)
ADA = Principal(subject="ada", kind="user", roles=("user",), via="session", two_factor=False, ver="1.1", sid="s")
MACHINE = replace(ADA, kind="machine", via="machine", sid=None)


@dataclass
class Outcome:
    status: int | None = None
    location: str | None = None
    closed: int | None = None
    passed: Scope | None = None


def run(wrap: Policy, kind: str = "http", principal: Principal | None = None, **scope: Any) -> Outcome:
    """What wrap, wrapped around a handler, did with a request: what it answered, or the scope it
    passed on to the handler."""
    outcome = Outcome()

    async def handler(passed: Scope, receive: Any, send: Any) -> None:
        outcome.passed = passed

    async def receive() -> Message:
        return {"type": "http.request"}

    async def send(message: Message) -> None:
        if message["type"] == "http.response.start":
            outcome.status = message["status"]
            outcome.location = dict(message["headers"]).get(b"location", b"").decode() or None
        if message["type"] == "websocket.close":
            outcome.closed = message["code"]

    state = {"principal": principal} if principal else {}
    request = {"type": kind, "path": "/", "headers": [], "state": state, **scope}

    async def serve() -> None:
        await wrap(handler)(request, receive, send)

    asyncio.run(serve())
    return outcome


class Answering(PrincipalReader):
    """A reader answering one outcome, recording the Authorization header it was asked for."""

    def __init__(self, outcome: Principal | Exception) -> None:
        self.outcome = outcome
        self.asked: str | None = None

    def read(self, header: Headers) -> Principal:
        self.asked = header("Authorization")
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def reading(reader: PrincipalReader) -> Policy:
    return lambda app: principal_middleware(app, reader)


def test_the_middleware_passes_the_principal_on_to_the_handler() -> None:
    passed = run(reading(Answering(ADA))).passed

    assert passed is not None and principal_of(passed) == ADA


def test_the_middleware_answers_401_to_a_refused_request() -> None:
    assert run(reading(Answering(PrincipalRefused("missing")))).status == 401


def test_the_middleware_answers_503_when_identity_cannot_be_asked() -> None:
    assert run(reading(Answering(IdentityUnavailable("down")))).status == 503


def test_the_middleware_reads_the_requests_headers_by_name_whatever_their_case() -> None:
    reader = Answering(ADA)

    run(reading(reader), headers=[(b"authorization", b"Bearer t")])

    assert reader.asked == "Bearer t"


def test_the_middleware_closes_a_refused_websocket_before_it_is_accepted() -> None:
    assert run(reading(Answering(PrincipalRefused("missing"))), "websocket").closed == 1008


def test_the_middleware_leaves_lifespan_events_alone() -> None:
    reader = Answering(PrincipalRefused("missing"))

    assert run(reading(reader), "lifespan").passed is not None


def test_require_role_lets_through_a_caller_holding_the_generated_role() -> None:
    assert run(require_role("editor"), "http", replace(ADA, roles=("editor",))).passed is not None


def test_require_role_answers_403_to_a_caller_without_the_role() -> None:
    assert run(require_role("editor"), "http", ADA).status == 403


def test_refuse_tools_answers_403_to_a_tool_acting_for_a_user() -> None:
    tool = replace(ADA, via="tool", actor=Actor(id="mcp_1", name="Claude Code"), sid=None)

    assert run(refuse_tools(), "http", tool).status == 403


def test_refuse_tools_lets_the_user_themselves_through() -> None:
    assert run(refuse_tools(), "http", ADA).passed is not None


def test_require_user_answers_403_to_a_machine() -> None:
    assert run(require_user(), "http", MACHINE).status == 403


def test_require_user_lets_a_person_through() -> None:
    assert run(require_user(), "http", ADA).passed is not None


def test_require_machine_answers_403_to_a_person() -> None:
    assert run(require_machine(), "http", ADA).status == 403


def test_require_machine_lets_a_machine_through() -> None:
    assert run(require_machine(), "http", MACHINE).passed is not None


@pytest.mark.parametrize(
    "policy",
    [require_role("user"), refuse_tools(), require_user(), require_machine(), require_recent_two_factor(5)],
    ids=["require_role", "refuse_tools", "require_user", "require_machine", "require_recent_two_factor"],
)
def test_a_policy_answers_401_without_a_principal(policy: Policy) -> None:
    assert run(policy, "http").status == 401


@pytest.mark.parametrize(
    "policy",
    [require_role("editor"), require_recent_two_factor(5)],
    ids=["require_role", "require_recent_two_factor"],
)
def test_a_policy_leaves_lifespan_events_alone(policy: Policy) -> None:
    assert run(policy, "lifespan").passed is not None


def test_a_policy_closes_a_websocket_it_refuses() -> None:
    assert run(require_role("editor"), "websocket", ADA).closed == 1008


def test_require_recent_two_factor_lets_a_fresh_enough_proof_through() -> None:
    proved = replace(ADA, two_factor=True, two_factor_at=NOW - timedelta(minutes=4))

    assert run(require_recent_two_factor(5, lambda: NOW), "http", proved).passed is not None


def test_require_recent_two_factor_sends_a_stale_session_to_step_up_and_back_to_the_same_page() -> None:
    stale = replace(ADA, two_factor=True, two_factor_at=NOW - timedelta(minutes=6))

    outcome = run(require_recent_two_factor(5, lambda: NOW), "http", stale, path="/pay", query_string=b"amount=3")

    assert (outcome.status, outcome.location) == (303, "/.auth/step-up?minutes=5&rd=%2Fpay%3Famount%3D3")


def test_require_recent_two_factor_sends_a_session_with_no_proof_to_step_up() -> None:
    assert run(require_recent_two_factor(5), "http", ADA).location == "/.auth/step-up?minutes=5&rd=%2F"


def test_require_recent_two_factor_answers_403_to_a_personal_token_it_cannot_step_up() -> None:
    assert run(require_recent_two_factor(5), "http", replace(ADA, via="personal-token", sid=None)).status == 403


def test_require_recent_two_factor_reads_the_real_time_when_given_no_clock() -> None:
    proved = replace(ADA, two_factor=True, two_factor_at=datetime.now(UTC))

    assert run(require_recent_two_factor(5), "http", proved).passed is not None
