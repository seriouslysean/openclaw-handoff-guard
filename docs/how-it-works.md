# How it works

Checked against OpenClaw 2026.10.5.

## The hook

The plugin registers one asynchronous `before_tool_call` handler at priority 90 (`plugins/hooks/tool-policy.md`). For a call it blocks, it returns `{ block: true, blockReason }`, which is terminal. OpenClaw blocks the call when a `before_tool_call` handler throws or exceeds its timeout, 15 seconds by default (`plugins/hooks/reference.md`, "On thrown error or timeout"), so a detector that fails blocks rather than passes. A check takes milliseconds.

## Which calls carry agent text

| Tool | Text checked | Receiving agent |
| --- | --- | --- |
| `sessions_send` | `message` | `agentId`, or the id in an `agent:<id>:…` session key; a label or another session key is unknown |
| `sessions_spawn` | `label` and `task` | `agentId`, or the requester's own agent when it is absent (`tools/subagents/tool-reference.md`, `agentId`) |

`message` posts to a channel and reaches people, not agents (`concepts/session-tool.md`), so it is out of scope.

## Exemptions

`allowTargets` lists agents whose incoming text isn't checked. Only a known id matches: a call whose target is a label, an unmapped session or a spawn with no requester id is checked, since OpenClaw documents missing context as unproven (`plugins/hooks/tool-policy.md`).

## Kinds

Each kind is a fixed format, so the same text gives the same verdict on every run. The first kind found, in the order of the table in the README, names the block.

- **email, phone-number, credit-card-number, ip-address:** `@arcjet/redact`, which runs locally in WebAssembly. The guard uses only its detection, through the `replace` callback, and never its redacted output.
- **credential:** `secretlint` with `@secretlint/secretlint-rule-preset-recommend`, run on the text as if it were a file. The preset matches provider-specific token formats. A generic high-entropy string is not a credential to it.
- **iban:** an upper-case country code, two digits and 11 to 30 more characters, grouped by four or not, then `ibantools`' country format and checksum. A wrong check digit passes.
- **us-ssn:** `NNN-NN-NNNN` with the hyphens, excluding area 000, 666 and 900–999, group 00 and serial 0000, which are never issued.
- **matrix-id:** `@`, `!` or `#`, a localpart, a colon and a server name with a dot (the Matrix specification's common identifier format).

## What it can't see

- Names, street addresses, dates of birth and private facts in free text. None is a fixed format.
- A value split, spelled out or encoded ("someone at example dot org").
- Text that reaches the web some other way than through another agent.
