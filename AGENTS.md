# Agents

Guidance for any coding agent working in this repository.

- Repository contract: [CLAUDE.md](CLAUDE.md)
- Estate-wide conventions: https://github.com/JorisJonkers-dev/workspace/blob/main/CLAUDE.md

## Build and test

Commands come from `Taskfile.yml`:

```bash
task sync
task check
task test
task lint
task build
```

`task check` runs everything CI runs on a pull request.
