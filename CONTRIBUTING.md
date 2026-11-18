# Contributing

Thanks for helping improve Void.

## Scope

Void is a **passive, defensive** research tool. Contributions that add any of the following will
not be accepted: logging in or registering on hidden services, purchasing or contacting sellers,
downloading files or images, evading the safety filters, or targeting private individuals.
Changes that weaken a safety control need an explicit justification in the pull request.

## Setup

```bash
make install      # creates .venv and installs dev dependencies
make test         # pytest; no Tor, Ollama or network required
make lint         # ruff check + format check
make fmt          # auto-fix
```

## Guidelines

- Add or update tests with every behaviour change. The pipeline takes injectable collaborators; use the fakes in `tests/conftest.py`.
- Keep the runtime dependency list small (`requirements.txt`) and avoid CDN assets in the UI; the CSP forbids them.
- Never commit `.env`, collected data, audit logs, or real seed lists.
- Do not add coded slang or indicator lists for illegal content to the repository; operators supply those through `config/blocklist.txt`.
- Use clear commit messages (imperative mood, one logical change per commit).

## Pull requests

Fill in the PR template, make sure CI is green, and describe how you tested the change.
