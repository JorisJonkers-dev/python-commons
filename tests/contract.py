"""The pinned contract, vendored by scripts/pin-contract.sh, and identity as a Fetch serving it."""

import base64
import json
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any

from jorisjonkers_commons.identity import Actor, Fetch, Principal, Request, Response

CONTRACT = Path(__file__).resolve().parent.parent / "contract"


def contract_json(path: str) -> Any:
    return json.loads((CONTRACT / path).read_text())


def vectors(channel: str) -> list[tuple[str, dict[str, Any]]]:
    """Every vector of a channel, by name."""
    return [(f.stem, json.loads(f.read_text())) for f in sorted((CONTRACT / "vectors" / channel).glob("*.json"))]


def principal_from(stated: dict[str, Any]) -> Principal:
    """The Principal a vector states, as the contract's JSON names it."""
    actor = stated.get("actor")
    two_factor_at = stated.get("twoFactorAt")
    return Principal(
        subject=stated["subject"],
        kind=stated["kind"],
        roles=tuple(stated["roles"]),
        via=stated["via"],
        two_factor=stated["twoFactor"],
        ver=stated["ver"],
        email=stated.get("email"),
        name=stated.get("name"),
        actor=Actor(id=actor["id"], name=actor["name"]) if actor else None,
        two_factor_at=datetime.fromisoformat(two_factor_at) if two_factor_at else None,
        sid=stated.get("sid"),
    )


def identity(client: str = "", secret: str = "", token: str = "", answer: Any = None) -> Fetch:
    """identity as a Fetch: its published keys, and an introspection answer for one Client and token."""
    credentials = "Basic " + base64.b64encode(f"{client}:{secret}".encode()).decode()

    def fetch(request: Request) -> Response:
        if request.url.endswith("/oidc/keys"):
            return Response(200, (CONTRACT / "vectors" / "jwks.json").read_bytes())
        asked = urllib.parse.parse_qs((request.body or b"").decode()).get("token", [""])[0]
        if request.headers.get("Authorization") != credentials or asked != token:
            return Response(401, b"")
        return Response(200, json.dumps(answer).encode())

    return fetch
