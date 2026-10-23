# openclaw-leak-guard

An [OpenClaw](https://docs.openclaw.ai) plugin (id `leak-guard`) that stops an agent from handing known personal-data formats to another agent.

An agent that can't reach the web can still ask one that can: the text it sends with `sessions_send` or `sessions_spawn` can become a search query or a fetched URL. This plugin checks that text and, by default, blocks the call when it holds an email address, a phone or card number, a bank account number (IBAN), a US Social Security number, a Matrix id, a Matrix token, or a credential, and logs a warning for a US street address or a date of birth. Everything else passes, so research about people, places and topics works as before.

**Status:** experimental. Built and tested against OpenClaw 2026.10.5. Not published on ClawHub or npm; install it from source. What has and hasn't been checked on a live gateway is in [docs/verification.md](docs/verification.md).

## Groups and modes

| Group | Kinds | Default mode |
| --- | --- | --- |
| `secrets` | `matrix-token`, `credential` | `block` |
| `structured-pii` | `email`, `phone-number`, `credit-card-number`, `iban`, `matrix-id`, `us-ssn`, `us-itin`, `us-bank-account`, `us-passport`, `us-driver-license`; `ip-address` on request | `block` |
| `contextual-pii` | `us-street`, `date-of-birth` | `warn` |

| Mode | What happens to a call whose text matches |
| --- | --- |
| `block` | Refused before execution, with a reason naming the group and kind. |
| `approve` | Held for the owner through OpenClaw's plugin approvals: allow once or deny, never allow always. A timeout denies. |
| `warn` | Goes ahead; the group and kind are logged through `api.logger.warn`, never the value. |
| `off` | The group is not run. |

A detector that fails follows its group's mode. Text the plugin can't read always blocks.

The block reason the agent sees (the host's wrapper line is illustrative until it is checked on a live gateway, see [docs/verification.md](docs/verification.md)):

```text
Tool "openclaw:core:sessions_send" was blocked before execution: Blocked: this text for <agent> contains an email address. Rephrase without it, or ask the owner.
```

| Kind | Detected by |
| --- | --- |
| `email`, `phone-number`, `credit-card-number` | [@arcjet/redact](https://github.com/arcjet/arcjet-js/tree/main/redact) (local, WebAssembly) |
| `us-ssn` | a pattern excluding numbers never issued; nine digits in a row only with a keyword such as "SSN" near them |
| `us-itin`, `us-bank-account`, `us-passport`, `us-driver-license` | [Presidio](https://github.com/microsoft/presidio)'s US patterns, each needing one of [Amazon Macie](https://docs.aws.amazon.com/macie/latest/user/managed-data-identifiers.html)'s keywords within 30 characters (a separated ITIN needs none) |
| `matrix-token` (`secrets`) | Matrix access, refresh and login tokens from Synapse and the Matrix Authentication Service, recognised by their CRC-32 checksum; a wrong checksum passes |
| `credential` (`secrets`) | [secretlint](https://github.com/secretlint/secretlint)'s recommended preset (provider tokens, private keys, basic-auth and database connection URLs), plus JSON Web Tokens and bearer headers; and, when you supply a binary, [gitleaks](https://github.com/gitleaks/gitleaks)' built-in rules without `generic-api-key` (see [gitleaks](#gitleaks-optional)) |
| `iban` | candidates checked by [ibantools](https://github.com/Simplify/ibantools) (country format and checksum) |
| `matrix-id` | a pattern for user, room and alias ids |
| `ip-address` | @arcjet/redact; off by default, since public addresses are routine in research |
| `us-street` (`contextual-pii`) | a house number, one to three capitalised words and a USPS Publication 28 (appendix C1) street suffix; a heuristic, no standard |
| `date-of-birth` (`contextual-pii`) | [Presidio](https://github.com/microsoft/presidio)'s date formats with one of Macie's date-of-birth keywords, or `born`, within 30 characters |

Kinds are listed below. Every text field of the call is checked: the message or task, a spawn's label, attachments (base64 ones decoded) and output schema, and any field it doesn't know. Zero-width characters are removed and full-width digits folded first. The matched value is never repeated in the block reason, which reaches the transcript and the logs. Text it can't read is blocked. Details and known gaps are in [docs/how-it-works.md](docs/how-it-works.md).

## Install

From a checkout, with runtime dependencies only:

```sh
npm ci --omit=dev --ignore-scripts
openclaw plugins install --link --force --accept-capabilities /path/to/openclaw-leak-guard
openclaw plugins enable leak-guard
openclaw plugins inspect leak-guard --runtime --json
```

- `--force` confirms a source that isn't on ClawHub; a local source always asks for capability consent (`cli/plugins/install.md:79-83`). The plugin requests no capabilities.
- `--omit=dev` keeps OpenClaw's own SDK out of `node_modules`: the gateway maps `openclaw/plugin-sdk/*` to its own install, so a second copy can drift from the host.
- With no config, text to every agent is checked: `secrets` and `structured-pii` block, and `contextual-pii` logs a warning. Config edits apply without a restart.
- Choose a mode per group: `openclaw config set plugins.entries.leak-guard.config '{"groups":{"structured-pii":{"mode":"approve"}}}' --strict-json`. A group's `kinds` narrows what it checks, such as `"kinds": ["email", "ip-address"]`. An unknown group, mode or kind falls back to the group's default, so a typo never turns checking off.
- Override a mode for one receiving agent, such as one that can't reach the web or a channel: `{"targets":{"<agent id>":{"structured-pii":"off"}}}`. The other groups stay on for it.
- Deprecated, still accepted for one release: `allowTargets` (read as every group `off` for those ids; a `targets` entry for the same id wins) and a top-level `kinds` (split into the groups; a group with none of the listed kinds checks nothing, as before).
- `inspect` should show the plugin as loaded, with `before_tool_call` in `typedHooks`.

To turn it off, run `openclaw plugins disable leak-guard`.

## gitleaks (optional)

A second `credential` detector: the gitleaks release binary, run as a separate process on the text over stdin. The plugin downloads nothing; you supply the binary.

1. Get the gitleaks 8.30.1 release archive for your platform from <https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1>.
2. Check its SHA-256 against `gitleaks_8.30.1_checksums.txt` from the same release, and unpack it.
3. Point the plugin at the executable, by absolute path: `openclaw config set plugins.entries.leak-guard.config '{"groups":{"secrets":{"gitleaks":{"binary":"/path/to/gitleaks"}}}}' --strict-json`.

| Release asset (8.30.1) | SHA-256 |
| --- | --- |
| `gitleaks_8.30.1_darwin_arm64.tar.gz` | `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5` |
| `gitleaks_8.30.1_darwin_x64.tar.gz` | `dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709` |
| `gitleaks_8.30.1_linux_arm64.tar.gz` | `e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080` |
| `gitleaks_8.30.1_linux_x64.tar.gz` | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |

- With no binary set, or one that isn't an executable file, gitleaks is skipped, one warning is logged at startup and secretlint still runs. The plugin does not check the binary's hash; that is yours to verify at install.
- It runs with `config/gitleaks.toml`: gitleaks' built-in rules (`useDefault`), minus `generic-api-key`, which flags any high-entropy string beside a key-like word and is not a fixed format. A match is the `credential` kind; the block reason names the group and kind, never the rule or the text.
- A run that exits with an error, returns an unreadable report or takes longer than 5 s is a detector failure and follows the `secrets` mode.
- Tested with 8.30.1 only. Another version may differ in flags, exit codes or rules.

## Bounds

- **Scoped:** only `sessions_send` and `sessions_spawn`, and only the text they hand over. Every other tool call passes untouched.
- **Some false positives:** some ten-digit numbers, such as an ISBN-10, read as a phone number. The block reason says which kind, so the agent can rephrase.
- **Fixed formats only:** names, addresses and private facts in free text aren't formats, so they pass. Catching them needs a classifier or a model, which is a different plugin.
- **Unreadable text blocks:** agent text it can't read is blocked whatever the modes are. A detector that throws follows its group's mode, and OpenClaw blocks the call if the handler itself exceeds its timeout.
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
