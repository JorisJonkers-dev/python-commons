"""Reads who is calling an app from identity's Principal contract
(github.com/JorisJonkers-dev/identity/contract/principal), and guards its routes with the result."""

from .asgi import (
    STEP_UP_PATH,
    principal_middleware,
    principal_of,
    refuse_tools,
    require_machine,
    require_recent_two_factor,
    require_role,
    require_user,
)
from .principal import Actor, Kind, Principal, Via
from .reader import (
    HEADER,
    MAJOR,
    TYPE,
    Fetch,
    Headers,
    IdentityUnavailable,
    PrincipalReader,
    PrincipalRefused,
    Request,
    Response,
    urllib_fetch,
)

__all__ = [
    "HEADER",
    "MAJOR",
    "STEP_UP_PATH",
    "TYPE",
    "Actor",
    "Fetch",
    "Headers",
    "IdentityUnavailable",
    "Kind",
    "Principal",
    "PrincipalReader",
    "PrincipalRefused",
    "Request",
    "Response",
    "Via",
    "principal_middleware",
    "principal_of",
    "refuse_tools",
    "require_machine",
    "require_recent_two_factor",
    "require_role",
    "require_user",
    "urllib_fetch",
]
