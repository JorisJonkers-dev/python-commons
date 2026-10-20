"""Reads who is calling an app from identity's Principal contract: the Gate's signed header, verified
against the Issuer's published keys, never the plain X-Auth-Request-* headers beside it."""

import base64
import binascii
import hashlib
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.hashes import SHA256

from .principal import Actor, Kind, Principal, Via

#: The Gate's signed Principal.
HEADER = "X-Identity-Principal"
#: The signed Principal's JWT typ, which no access token carries.
TYPE = "identity-principal+jwt"
#: The contract major version this package reads.
MAJOR = "1"

# zitadel/oidc signs access and ID tokens alike as JWT; an access token alone names a client_id.
_ACCESS_TOKEN_TYPE = "JWT"
_REFETCH_AFTER = timedelta(minutes=1)
_ANSWER_LIFETIME = timedelta(seconds=30)
_MAX_ANSWERS = 10_000
_KINDS = ("user", "machine")
_VIAS = ("session", "personal-token", "tool", "machine")


class PrincipalRefused(Exception):
    """Why a request carries no Principal. reason is one of the contract's refusals: missing,
    wrong-typ, wrong-issuer, wrong-audience, expired, unknown-key, bad-signature, unknown-major,
    not-an-access-token or inactive."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"the request's Principal is refused: {reason}")
        self.reason = reason


class IdentityUnavailable(Exception):
    """identity could not be asked: its keys or its introspection did not answer."""


@dataclass(frozen=True)
class Request:
    """A request the reader sends identity."""

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None


@dataclass(frozen=True)
class Response:
    """identity's answer to a Request."""

    status: int
    body: bytes


#: Sends a Request to identity; raises IdentityUnavailable when identity does not answer.
Fetch = Callable[[Request], Response]

#: A request's header by name, or None when it has none.
Headers = Callable[[str], str | None]


def urllib_fetch(request: Request, timeout: float = 5.0) -> Response:
    """Sends request with urllib, the default Fetch."""
    sent = urllib.request.Request(request.url, request.body, dict(request.headers), method=request.method)
    try:
        with urllib.request.urlopen(sent, timeout=timeout) as answer:
            return Response(answer.status, answer.read())
    except urllib.error.HTTPError as answer:
        return Response(answer.code, answer.read())
    except OSError as e:
        raise IdentityUnavailable(f"identity did not answer {request.url}") from e


@dataclass(frozen=True)
class _Answer:
    principal: Principal | None
    refusal: str | None
    until: datetime


class PrincipalReader:
    """Reads Principals for one Client: the app's own, which each Principal must be stated for."""

    def __init__(
        self,
        issuer: str,
        client_id: str,
        *,
        client_secret: str | None = None,
        keys_url: str | None = None,
        introspect_url: str | None = None,
        fetch: Fetch = urllib_fetch,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """issuer is identity's URL as each Principal's iss states it. An app without client_secret
        refuses an opaque token as inactive."""
        if not issuer or not client_id:
            raise ValueError("a PrincipalReader names its Issuer and its Client")
        base = issuer.rstrip("/")
        self._issuer = issuer
        self._client_id = client_id
        self._client_secret = client_secret
        self._keys_url = keys_url or f"{base}/oidc/keys"
        self._introspect_url = introspect_url or f"{base}/oidc/introspect"
        self._fetch = fetch
        self._now = now
        self._keys_lock = threading.Lock()
        self._keys: dict[str, RSAPublicKey] = {}
        self._fetched: datetime | None = None
        self._answers_lock = threading.Lock()
        self._answers: dict[bytes, _Answer] = {}

    def read(self, header: Headers) -> Principal:
        """The Principal a request carries: the Gate's signed header when there is one, or else its
        bearer token, a JWT access token verified here or an opaque token introspected. Raises
        PrincipalRefused saying why it carries none, and IdentityUnavailable when identity could not
        be asked."""
        signed = header(HEADER)
        if signed:
            return self._checked(self._verified(signed, TYPE))
        scheme, _, token = (header("Authorization") or "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise PrincipalRefused("missing")
        if token.count(".") == 2:
            claims = self._verified(token, _ACCESS_TOKEN_TYPE)
            if not claims.get("client_id"):
                raise PrincipalRefused("not-an-access-token")
            return self._checked(claims)
        return self._introspected(token)

    def _verified(self, token: str, typ: str) -> dict[str, Any]:
        """The claims of a JWT of typ, signed by one of the Issuer's published keys."""
        try:
            head, payload, signature = token.split(".")
            protected = json.loads(_unbase64(head))
            if not isinstance(protected, dict) or protected.get("alg") != "RS256":
                raise PrincipalRefused("bad-signature")
            if protected.get("typ") != typ:
                raise PrincipalRefused("wrong-typ")
            key = self._key(protected.get("kid"))
            key.verify(_unbase64(signature), f"{head}.{payload}".encode(), PKCS1v15(), SHA256())
            claims = json.loads(_unbase64(payload))
        except (ValueError, binascii.Error, InvalidSignature) as e:
            raise PrincipalRefused("bad-signature") from e
        if not isinstance(claims, dict):
            raise PrincipalRefused("bad-signature")
        return claims

    def _checked(self, claims: dict[str, Any]) -> Principal:
        """claims' Principal, or why claims state none for this reader's Client."""
        exp = claims.get("exp")
        if _major(claims) != MAJOR:
            raise PrincipalRefused("unknown-major")
        if claims.get("iss") != self._issuer:
            raise PrincipalRefused("wrong-issuer")
        if _audience(claims.get("aud")) != [self._client_id]:
            raise PrincipalRefused("wrong-audience")
        if not isinstance(exp, int | float) or self._now() >= datetime.fromtimestamp(exp, UTC):
            raise PrincipalRefused("expired")
        return _principal_of(claims)

    def _key(self, kid: object) -> RSAPublicKey:
        """The Issuer's published key with id kid. An id the reader does not know fetches the keys
        again, at most once a minute, so a rotated key is picked up and a forged id costs little."""
        if not isinstance(kid, str):
            raise PrincipalRefused("unknown-key")
        with self._keys_lock:
            if kid in self._keys:
                return self._keys[kid]
            if self._fetched is not None and self._now() - self._fetched < _REFETCH_AFTER:
                raise PrincipalRefused("unknown-key")
            self._keys = self._published_keys()
            self._fetched = self._now()
            if kid in self._keys:
                return self._keys[kid]
            raise PrincipalRefused("unknown-key")

    def _published_keys(self) -> dict[str, RSAPublicKey]:
        answer = self._fetch(Request("GET", self._keys_url))
        if answer.status != 200:
            raise IdentityUnavailable(f"the Issuer's keys answered {answer.status}")
        try:
            keys = json.loads(answer.body).get("keys") or []
            return {
                k["kid"]: RSAPublicNumbers(_integer(k["e"]), _integer(k["n"])).public_key()
                for k in keys
                if k.get("kty") == "RSA" and "kid" in k
            }
        except (ValueError, AttributeError, KeyError, TypeError) as e:
            raise IdentityUnavailable("the Issuer's keys are no JWKS") from e

    def _introspected(self, token: str) -> Principal:
        """The Principal identity answers for an opaque token, a Personal Token or a Connected App's,
        asked at most once per thirty seconds so a revoked token stops working within them."""
        if not self._client_secret:
            raise PrincipalRefused("inactive")
        key = hashlib.sha256(token.encode()).digest()
        now = self._now()
        with self._answers_lock:
            kept = self._answers.get(key)
        if kept is None or now >= kept.until:
            claims = self._ask(token)
            try:
                kept = _Answer(self._answered(claims), None, now + _ANSWER_LIFETIME)
            except PrincipalRefused as refused:
                kept = _Answer(None, refused.reason, now + _ANSWER_LIFETIME)
            with self._answers_lock:
                if len(self._answers) >= _MAX_ANSWERS:
                    self._answers = {}
                self._answers[key] = kept
        if kept.principal is None:
            raise PrincipalRefused(cast(str, kept.refusal))
        return kept.principal

    def _ask(self, token: str) -> dict[str, Any]:
        """identity's introspection answer about token (RFC 7662), the reader authenticating as its
        own Client."""
        secret = cast(str, self._client_secret)
        credentials = f"{urllib.parse.quote_plus(self._client_id)}:{urllib.parse.quote_plus(secret)}"
        answer = self._fetch(
            Request(
                "POST",
                self._introspect_url,
                {
                    "Authorization": f"Basic {base64.b64encode(credentials.encode()).decode()}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                urllib.parse.urlencode({"token": token}).encode(),
            )
        )
        if answer.status != 200:
            raise IdentityUnavailable(f"introspection answered {answer.status}")
        try:
            claims = json.loads(answer.body)
        except ValueError as e:
            raise IdentityUnavailable("introspection answered no JSON") from e
        if not isinstance(claims, dict):
            raise IdentityUnavailable("introspection answered no JSON object")
        return claims

    def _answered(self, claims: dict[str, Any]) -> Principal:
        """The Principal an introspection answer states for this reader's Client."""
        if claims.get("active") is not True:
            raise PrincipalRefused("inactive")
        if _major(claims) != MAJOR:
            raise PrincipalRefused("unknown-major")
        if claims.get("client_id") != self._client_id or _audience(claims.get("aud")) != [self._client_id]:
            raise PrincipalRefused("wrong-audience")
        return _principal_of(claims)


def _principal_of(claims: dict[str, Any]) -> Principal:
    kind, via = claims.get("kind"), claims.get("via")
    if kind not in _KINDS or via not in _VIAS:
        raise PrincipalRefused("unknown-major")
    act = claims.get("act")
    two_factor_at = claims.get("two_factor_at")
    return Principal(
        subject=str(claims.get("sub") or ""),
        kind=cast(Kind, kind),
        roles=tuple(str(r) for r in claims.get("roles") or ()),
        via=cast(Via, via),
        two_factor=claims.get("two_factor") is True,
        ver=str(claims["ver"]),
        email=claims.get("email"),
        name=claims.get("name"),
        actor=Actor(id=str(act.get("sub")), name=str(act.get("name"))) if isinstance(act, dict) else None,
        two_factor_at=datetime.fromtimestamp(two_factor_at, UTC) if two_factor_at else None,
        sid=claims.get("sid"),
    )


def _major(claims: dict[str, Any]) -> str | None:
    ver = claims.get("ver")
    return ver.split(".")[0] if isinstance(ver, str) else None


def _audience(aud: Any) -> list[str] | None:
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list):
        return [str(a) for a in aud]
    return None


def _unbase64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _integer(text: str) -> int:
    return int.from_bytes(_unbase64(text), "big")
