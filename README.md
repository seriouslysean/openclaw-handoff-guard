# openclaw-pii-guard

An [OpenClaw](https://docs.openclaw.ai) plugin (id `pii-guard`) that stops an agent from handing known personal-data formats to another agent.

An agent that can't reach the web can still ask one that can: the text it sends with `sessions_send` or `sessions_spawn` can become a search query or a fetched URL. This plugin checks that text and blocks the call when it holds an email address, a phone or card number, a bank account number (IBAN), a US Social Security number, a Matrix id, or a credential. Everything else passes, so research about people, places and topics works as before.

**Status:** experimental. Built and tested against OpenClaw 2026.10.5. Not published on ClawHub or npm; install it from source. What has and hasn't been checked on a live gateway is in [docs/verification.md](docs/verification.md).

## What it blocks

The block reason the agent sees (the host's wrapper line is illustrative until it is checked on a live gateway, see [docs/verification.md](docs/verification.md)):

```text
Tool "openclaw:core:sessions_send" was blocked before execution: Blocked: this text for <agent> contains an email address. Rephrase without it, or ask the owner.
```

| Kind | Detected by |
| --- | --- |
| `email`, `phone-number`, `credit-card-number` | [@arcjet/redact](https://github.com/arcjet/arcjet-js/tree/main/redact) (local, WebAssembly) |
| `us-ssn` | a pattern excluding numbers never issued; nine digits in a row only with a keyword such as "SSN" near them |
| `us-itin`, `us-bank-account`, `us-passport`, `us-driver-license` | [Presidio](https://github.com/microsoft/presidio)'s US patterns, each needing one of [Amazon Macie](https://docs.aws.amazon.com/macie/latest/user/managed-data-identifiers.html)'s keywords within 30 characters (a separated ITIN needs none) |
| `credential` | [secretlint](https://github.com/secretlint/secretlint)'s recommended preset (provider tokens, private keys, basic-auth and database connection URLs), plus JSON Web Tokens and bearer headers |
| `iban` | candidates checked by [ibantools](https://github.com/Simplify/ibantools) (country format and checksum) |
| `matrix-id` | a pattern for user, room and alias ids |
| `ip-address` | @arcjet/redact; off by default, since public addresses are routine in research |

Every text field of the call is checked: the message or task, a spawn's label, attachments (base64 ones decoded) and output schema, and any field it doesn't know. Zero-width characters are removed and full-width digits folded first. The matched value is never repeated in the block reason, which reaches the transcript and the logs. Text it can't read is blocked. Details and known gaps are in [docs/how-it-works.md](docs/how-it-works.md).

## Install

From a checkout, with runtime dependencies only:

```sh
npm ci --omit=dev --ignore-scripts
openclaw plugins install --link --force --accept-capabilities /path/to/openclaw-pii-guard
openclaw plugins enable pii-guard
openclaw plugins inspect pii-guard --runtime --json
```

- `--force` confirms a source that isn't on ClawHub; a local source always asks for capability consent (`cli/plugins/install.md:79-83`). The plugin requests no capabilities.
- `--omit=dev` keeps OpenClaw's own SDK out of `node_modules`: the gateway maps `openclaw/plugin-sdk/*` to its own install, so a second copy can drift from the host.
- With no config, text to every agent is checked for every kind except `ip-address`. To exempt agents that can't reach the web or a channel: `openclaw config set plugins.entries.pii-guard.config '{"allowTargets":["<agent id>"]}' --strict-json`. To choose kinds: `"kinds": ["email", "credential"]`. Config edits apply without a restart.
- `inspect` should show the plugin as loaded, with `before_tool_call` in `typedHooks`.

To turn it off, run `openclaw plugins disable pii-guard`.

## Bounds

- **Scoped:** only `sessions_send` and `sessions_spawn`, and only the text they hand over. Every other tool call passes untouched.
- **Some false positives:** some ten-digit numbers, such as an ISBN-10, read as a phone number. The block reason says which kind, so the agent can rephrase.
- **Fixed formats only:** names, addresses and private facts in free text aren't formats, so they pass. Catching them needs a classifier or a model, which is a different plugin.
- **Fails closed:** agent text it can't read is blocked, and OpenClaw blocks the call if the handler throws or exceeds its timeout.
- **Agents only:** text sent from the CLI or the Control UI doesn't go through an agent's tools, so the hook never sees it.

## Develop

Requires Node 24.16 or later.

```sh
npm ci --ignore-scripts
npm run lint && npm run typecheck && npm test
```

Run the checks in a separate clone from the one you've installed with `--link`, or reinstall with `--omit=dev` afterwards.

## License

[MIT](LICENSE)
