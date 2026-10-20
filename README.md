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

## Working on it

```bash
mise install   # the toolchain: Python, uv, task, actionlint, gitleaks
task check     # everything CI runs
```
