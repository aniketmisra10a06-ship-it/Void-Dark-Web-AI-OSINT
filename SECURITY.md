# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability
reporting (Security tab, "Report a vulnerability"). Include steps to reproduce and the affected version.
We aim to acknowledge reports within 7 days.

Of particular interest: bypasses of the safety filters, prompt-injection paths that reach the
model with elevated trust, SSRF or URL-allowlist bypasses, XSS in the chat UI, and authentication bypass.

## Threat model

Void fetches untrusted content from hostile networks and feeds it to an LLM.

| Asset | Protected by |
| --- | --- |
| The host and internal network | URL allow-list (v3 `.onion` only by default), manual redirect validation, text-only fetching, dropped capabilities |
| Your anonymity | Search and page requests go via Void's own embedded Tor with remote DNS (`socks5h`), enforced in code. The container itself has direct internet access (used only for an optional AI provider), so keep untrusted code out of it |
| The model's behaviour | Untrusted-data wrapping, tag neutralisation, no tools, no client-supplied `system` turns |
| Your AI API key (optional feature) | Stored server-side only (`llm.json` in the data volume, mode `0600`), never returned by the API, scrubbed from errors, dropped when the provider or base URL changes, `https://` required for remote providers, redirects not followed |
| Local installs | Host-header allow-list when no token is set (DNS rebinding), same-origin check on state-changing requests |
| Operators and users | Safety filters, PII redaction, defanged URLs, strict CSP |
| Accountability | JSONL audit log of queries and URLs |

Data sent to an AI provider (only if you configure one; the default built-in analyst sends nothing anywhere): with a cloud provider, your questions and the redacted page text
leave your machine and fall under that provider's data policy. Use a local model if that is a problem.
Anyone who can read the Docker data volume or the host can read the saved API key: use a key with a
spend limit, and rotate it if the volume is shared or backed up.

Out of scope: guaranteeing that every harmful page is detected, and the security of Tor itself.

## Safe use

- Run it on a machine or VM that holds nothing sensitive.
- Create the API key just for Void, with a spending limit.
- Keep the UI on `127.0.0.1`. If you expose it, put it behind TLS and set `ACCESS_TOKEN`.
- Never open `.onion` URLs from results in a regular browser; use Tor Browser, and only if you must.
- Treat model output as a lead to verify, not a finding.
- Do not redistribute leaked personal data you encounter.
- If you encounter child sexual abuse material, stop, do not download or share it, and report it to the
  [NCMEC CyberTipline](https://report.cybertip.org), the [IWF](https://report.iwf.org.uk) or your local
  [INHOPE](https://www.inhope.org) hotline.

## Supported versions

Only the latest release receives security fixes.
