import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256

from jorisjonkers_commons.identity import (
    Headers,
    IdentityUnavailable,
    PrincipalReader,
    PrincipalRefused,
    Request,
    Response,
)

SIGNED_AT = datetime(2026, 10, 20, 12, tzinfo=UTC)
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def integer(n: int) -> str:
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "k",
            "alg": "RS256",
            "n": integer(KEY.public_key().public_numbers().n),
            "e": integer(KEY.public_key().public_numbers().e),
        }
    ]
}


def claims(**edit: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "iss": "https://auth.example.test",
        "sub": "ada",
        "aud": "web",
        "client_id": "web",
        "exp": int(SIGNED_AT.timestamp()) + 60,
        "ver": "1.1",
        "kind": "user",
        "via": "personal-token",
        "roles": ["user"],
        "two_factor": False,
    }
    c.update(edit)
    return {k: v for k, v in c.items() if v is not None}


def sign(payload: dict[str, Any] | str, typ: str = "JWT", kid: str = "k", alg: str = "RS256") -> str:
    head = b64(json.dumps({"alg": alg, "typ": typ, "kid": kid}).encode())
    body = b64((payload if isinstance(payload, str) else json.dumps(payload)).encode())
    signature = KEY.sign(f"{head}.{body}".encode(), PKCS1v15(), SHA256())
    return f"{head}.{body}.{b64(signature)}"


@dataclass
class Identity:
    """identity as a Fetch, counting each question and answering what a test sets."""

    keys: Response = field(default_factory=lambda: Response(200, json.dumps(JWKS).encode()))
    introspection: Response = field(default_factory=lambda: Response(200, b'{"active":false}'))
    fails: bool = False
    keys_fetched: int = 0
    asked: int = 0
    urls: list[str] = field(default_factory=list)

    def fetch(self, request: Request) -> Response:
        self.urls.append(request.url)
        if self.fails:
            raise IdentityUnavailable("down")
        if request.url.endswith("/oidc/keys"):
            self.keys_fetched += 1
            return self.keys
        self.asked += 1
        return self.introspection


@dataclass
class Clock:
    now: datetime = SIGNED_AT + timedelta(seconds=30)


def reader(identity: Identity, clock: Clock | None = None, secret: str | None = "s3cret") -> PrincipalReader:
    at = clock or Clock()
    return PrincipalReader(
        "https://auth.example.test", "web", client_secret=secret, fetch=identity.fetch, now=lambda: at.now
    )


def bearer(token: str) -> Headers:
    return lambda name: f"Bearer {token}" if name == "Authorization" else None


def reason(read: Callable[[], Any]) -> str:
    try:
        read()
    except PrincipalRefused as refused:
        return refused.reason
    return "read"


def active(**edit: Any) -> Response:
    return Response(200, json.dumps(claims(active=True, **edit)).encode())


def test_the_issuers_keys_are_fetched_once_for_every_token_they_sign() -> None:
    identity = Identity()
    r = reader(identity)

    for _ in range(3):
        r.read(bearer(sign(claims())))

    assert identity.keys_fetched == 1


def test_the_issuers_keys_are_fetched_again_for_an_unknown_key_at_most_once_a_minute() -> None:
    identity = Identity()
    clock = Clock()
    r = reader(identity, clock)
    r.read(bearer(sign(claims())))
    reason(lambda: r.read(bearer(sign(claims(), kid="rotated"))))
    reason(lambda: r.read(bearer(sign(claims(), kid="rotated"))))
    clock.now += timedelta(minutes=1)
    reason(lambda: r.read(bearer(sign(claims(exp=int(clock.now.timestamp()) + 60), kid="rotated"))))

    assert identity.keys_fetched == 2


def test_a_key_id_the_issuer_does_not_publish_is_refused() -> None:
    assert reason(lambda: reader(Identity()).read(bearer(sign(claims(), kid="forged")))) == "unknown-key"


def test_a_key_id_that_is_no_string_is_refused_without_fetching_the_keys() -> None:
    identity = Identity()
    head = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": ["k"]}).encode())

    assert reason(lambda: reader(identity).read(bearer(f"{head}.e30.c2ln"))) == "unknown-key"
    assert identity.keys_fetched == 0


@pytest.mark.parametrize(
    "keys",
    [Response(500, b""), Response(200, b"not json"), Response(200, b'{"keys":[{"kty":"RSA","kid":"k"}]}')],
    ids=["an error", "no JSON", "a key without its numbers"],
)
def test_issuer_keys_that_answer_badly_are_no_refusal(keys: Response) -> None:
    with pytest.raises(IdentityUnavailable):
        reader(Identity(keys=keys)).read(bearer(sign(claims())))


def test_issuer_keys_that_cannot_be_reached_are_no_refusal() -> None:
    with pytest.raises(IdentityUnavailable):
        reader(Identity(fails=True)).read(bearer(sign(claims())))


def test_issuer_keys_may_be_published_without_a_keys_list() -> None:
    identity = Identity(keys=Response(200, b"{}"))

    assert reason(lambda: reader(identity).read(bearer(sign(claims())))) == "unknown-key"


def test_issuer_keys_that_are_not_rsa_are_passed_over() -> None:
    identity = Identity(keys=Response(200, b'{"keys":[{"kty":"EC","kid":"k"}]}'))

    assert reason(lambda: reader(identity).read(bearer(sign(claims())))) == "unknown-key"


def test_an_access_token_that_is_no_jws_is_refused() -> None:
    assert reason(lambda: reader(Identity()).read(bearer("a.b.c"))) == "bad-signature"


def test_an_access_token_not_signed_with_rs256_is_refused() -> None:
    assert reason(lambda: reader(Identity()).read(bearer(sign(claims(), alg="HS256")))) == "bad-signature"


def test_an_access_token_whose_signed_payload_is_no_json_object_is_refused() -> None:
    assert reason(lambda: reader(Identity()).read(bearer(sign("[1]")))) == "bad-signature"


def test_an_access_token_whose_audience_lists_only_the_apps_client_is_read() -> None:
    assert reader(Identity()).read(bearer(sign(claims(aud=["web"])))).subject == "ada"


def test_an_access_token_whose_audience_is_neither_a_string_nor_a_list_is_refused() -> None:
    assert reason(lambda: reader(Identity()).read(bearer(sign(claims(aud=7))))) == "wrong-audience"


def test_an_access_token_stating_a_kind_v1_does_not_know_is_refused() -> None:
    assert reason(lambda: reader(Identity()).read(bearer(sign(claims(kind="robot"))))) == "unknown-major"


def test_an_access_token_stating_no_roles_or_subject_holds_empty_ones() -> None:
    p = reader(Identity()).read(bearer(sign(claims(roles=None, sub=None))))

    assert (p.roles, p.subject) == ((), "")


def test_an_access_token_stating_no_ver_is_refused() -> None:
    assert reason(lambda: reader(Identity()).read(bearer(sign(claims(ver=None))))) == "unknown-major"


def test_an_access_token_stating_no_expiry_is_refused() -> None:
    assert reason(lambda: reader(Identity()).read(bearer(sign(claims(exp=None))))) == "expired"


def test_an_opaque_token_that_is_revoked_stops_working_within_thirty_seconds() -> None:
    identity = Identity(introspection=active())
    clock = Clock(SIGNED_AT)
    r = reader(identity, clock)
    r.read(bearer("idapp_tool"))
    identity.introspection = Response(200, b'{"active":false}')
    clock.now += timedelta(seconds=29)
    r.read(bearer("idapp_tool"))
    clock.now += timedelta(seconds=1)

    assert reason(lambda: r.read(bearer("idapp_tool"))) == "inactive"


def test_an_opaque_token_is_asked_about_once_per_thirty_seconds() -> None:
    identity = Identity(introspection=active())
    r = reader(identity)

    for _ in range(5):
        r.read(bearer("idapp_tool"))

    assert identity.asked == 1


def test_an_opaque_token_refused_once_is_refused_again_without_asking() -> None:
    identity = Identity()
    r = reader(identity)
    reason(lambda: r.read(bearer("idpat_gone")))

    assert (reason(lambda: r.read(bearer("idpat_gone"))), identity.asked) == ("inactive", 1)


def test_an_opaque_token_is_refused_without_asking_by_an_app_without_a_client_secret() -> None:
    identity = Identity()

    assert (reason(lambda: reader(identity, secret=None).read(bearer("idpat_script"))), identity.asked) == (
        "inactive",
        0,
    )


def test_an_opaque_token_that_cannot_be_asked_about_is_no_refusal_and_is_asked_about_again() -> None:
    identity = Identity(introspection=Response(502, b""))
    r = reader(identity)
    with pytest.raises(IdentityUnavailable):
        r.read(bearer("idapp_tool"))
    identity.introspection = active()

    assert r.read(bearer("idapp_tool")).subject == "ada"


@pytest.mark.parametrize("body", [b"not json", b"[]"], ids=["no JSON", "no JSON object"])
def test_an_introspection_answer_that_is_no_json_object_is_no_refusal(body: bytes) -> None:
    with pytest.raises(IdentityUnavailable):
        reader(Identity(introspection=Response(200, body))).read(bearer("idapp_tool"))


def test_the_answers_kept_are_dropped_once_ten_thousand_are_kept_so_the_first_is_asked_about_again() -> None:
    identity = Identity(introspection=active())
    r = reader(identity)
    for i in range(10_001):
        r.read(bearer(f"idapp_{i}"))
    asked = identity.asked

    r.read(bearer("idapp_0"))

    assert identity.asked == asked + 1


@pytest.mark.parametrize(
    "authorization", [None, "Basic dXNlcjpwYXNz", "Bearer ", "Bearer"], ids=["none", "basic", "empty", "bare"]
)
def test_a_request_without_a_bearer_token_carries_no_principal(authorization: str | None) -> None:
    assert (
        reason(lambda: reader(Identity()).read(lambda name: authorization if name == "Authorization" else None))
        == "missing"
    )


def test_a_reader_asks_the_issuers_own_endpoints_by_default() -> None:
    identity = Identity()
    r = PrincipalReader("https://auth.example.test/", "web", client_secret="s3cret", fetch=identity.fetch)
    reason(lambda: r.read(bearer("idpat_script")))
    reason(lambda: r.read(bearer(sign(claims()))))

    assert identity.urls == ["https://auth.example.test/oidc/introspect", "https://auth.example.test/oidc/keys"]


def test_a_reader_names_its_issuer_and_its_client() -> None:
    with pytest.raises(ValueError, match="names its Issuer and its Client"):
        PrincipalReader("", "web")
