# python-commons

Shared Python packages for estate services, released together as the
`jorisjonkers-commons` distribution.

| package | what it does |
|---|---|
| `jorisjonkers_commons.identity` | reads who is calling from identity's Principal contract: the Gate's signed header, access tokens and introspected opaque tokens, plus the policy helpers that guard routes |

## Using it

Pin an exact release tag; nothing resolves from `main` (see [VERSIONING.md](VERSIONING.md)):

```toml
dependencies = [
  "jorisjonkers-commons @ git+https://github.com/JorisJonkers-dev/python-commons@v0.1.0",
]
```

## identity

`PrincipalReader.read` is the one entry point: it takes a request's headers by name and returns the
`Principal`, or raises `PrincipalRefused` with the contract's reason. It reads the Gate's signed
`X-Identity-Principal` header and never the plain `X-Auth-Request-*` ones; without it, it verifies a
JWT access token against the Issuer's keys or introspects an opaque token, keeping each answer for
30 seconds. `IdentityUnavailable` means identity could not be asked, which is not a refusal.

```python
from jorisjonkers_commons.identity import (
    PrincipalReader, principal_middleware, require_recent_two_factor, require_role,
)

reader = PrincipalReader("https://auth.jorisjonkers.dev", "wiki", client_secret=secret)
app = principal_middleware(app, reader)          # 401 when refused, 503 when identity is down
admin = require_role("admin")(admin_app)         # 403 without the role
payments = require_recent_two_factor(5)(pay_app) # 303 to the Gate's step-up, 403 for tokens
```

The middleware and the helpers are plain ASGI, so they wrap a Starlette or FastAPI app or any one
of its routes; Starlette's `request.state.principal` holds what the middleware read.

The Principal type is generated from the contract pinned in `contract/`. To move to a new contract
release, pin it and regenerate:

```bash
scripts/pin-contract.sh contract/principal/v1.1.0
PRINCIPAL_UPDATE=true task test
```

## Working on it

```bash
mise install   # the toolchain: Python, uv, task, actionlint, gitleaks
task check     # everything CI runs
```
