from datetime import datetime
from typing import Any

import pytest

from contract import identity, principal_from, vectors
from jorisjonkers_commons.identity import HEADER, Headers, Principal, PrincipalReader, PrincipalRefused


def outcome(reader: PrincipalReader, header: Headers) -> Principal | str:
    try:
        return reader.read(header)
    except PrincipalRefused as refused:
        return refused.reason


def expected(vector: dict[str, Any]) -> Principal | str:
    refusal = vector.get("refusal")
    return refusal if isinstance(refusal, str) else principal_from(vector["principal"])


def reader_for(vector: dict[str, Any]) -> PrincipalReader:
    now = datetime.fromisoformat(vector["now"])
    return PrincipalReader(vector["issuer"], vector["client"], fetch=identity(), now=lambda: now)


def bearer(token: str) -> Headers:
    return lambda name: f"Bearer {token}" if name == "Authorization" else None


@pytest.mark.parametrize(("name", "vector"), vectors("signed-header"), ids=lambda v: v if isinstance(v, str) else "")
def test_every_pinned_signed_header_vector_reads_as_the_contract_says(name: str, vector: dict[str, Any]) -> None:
    assert outcome(reader_for(vector), vector["headers"].get) == expected(vector)


@pytest.mark.parametrize(("name", "vector"), vectors("access-token"), ids=lambda v: v if isinstance(v, str) else "")
def test_every_pinned_access_token_vector_reads_as_the_contract_says(name: str, vector: dict[str, Any]) -> None:
    assert outcome(reader_for(vector), bearer(vector["token"])) == expected(vector)


@pytest.mark.parametrize(("name", "vector"), vectors("introspection"), ids=lambda v: v if isinstance(v, str) else "")
def test_every_pinned_introspection_vector_reads_as_the_contract_says(name: str, vector: dict[str, Any]) -> None:
    fetch = identity(vector["client"], "s3cret", "opaque", vector["answer"])
    reader = PrincipalReader("https://auth.example.test", vector["client"], client_secret="s3cret", fetch=fetch)

    assert outcome(reader, bearer("opaque")) == expected(vector)


def test_an_access_token_presented_as_the_signed_header_is_refused() -> None:
    vector = dict(vectors("access-token"))["session"]

    assert outcome(reader_for(vector), {HEADER: vector["token"]}.get) == "wrong-typ"


def test_a_signed_header_presented_as_a_bearer_token_is_refused() -> None:
    vector = dict(vectors("signed-header"))["session"]

    assert outcome(reader_for(vector), bearer(vector["headers"][HEADER])) == "wrong-typ"
