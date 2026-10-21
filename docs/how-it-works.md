# How it works

Checked against OpenClaw 2026.10.5.

## The hook

The plugin registers one asynchronous `before_tool_call` handler at priority 90 (`plugins/hooks/tool-policy.md`). For a call it blocks, it returns `{ block: true, blockReason }`, which is terminal. OpenClaw blocks the call when a `before_tool_call` handler throws or exceeds its timeout, 15 seconds by default (`plugins/hooks/reference.md`, "On thrown error or timeout"), so a detector that fails blocks rather than passes. A check takes milliseconds.

## Which calls carry agent text

| Tool | Required text | Receiving agent |
| --- | --- | --- |
| `sessions_send` | `message` | the id in an `agent:<id>:…` `sessionKey`; with no `sessionKey` or `label`, `agentId`. Any other key or a label lookup is unknown |
| `sessions_spawn` | `task` | `agentId`, or the requester's own agent when it is absent (`tools/subagents/tool-reference.md`, `agentId`) |

The target order follows OpenClaw's own: `sessions_send` uses `agentId` only when neither `sessionKey` nor `label` is given (dist `sessions-spawn-tool`, 2026.10.5), so an `agentId` can't borrow an exemption for a call that goes elsewhere.

Every string in the parameters is checked, nested or not, except the fields that choose where or how the call runs (`SELECTORS` in `src/rules.ts`: session keys, agent ids, model, mode and similar). That covers a spawn's `label`, its `attachments` (a base64 `content` is decoded and checked as well), its `outputSchema`, and any field an upgrade adds. Tool names are compared without a namespace, case or padding.

`message` posts to a channel and reaches people, not agents (`concepts/session-tool.md`), so it is out of scope. A spawn with `context: "fork"` copies the requester's transcript to the child, but every native fork must target the requester's own agent (`tool-reference.md`, `context`), so a fork never reaches another agent.

## Exemptions

`allowTargets` lists agents whose incoming text isn't checked. Only a known id matches: a call whose target is a label, an unmapped session or a spawn with no requester id is checked, since OpenClaw documents missing context as unproven (`plugins/hooks/tool-policy.md`).

## Kinds

Each kind is a fixed format, so the same text gives the same verdict on every run. The first kind found, in the order of the table in the README, names the block. Before matching, format characters (`\p{Cf}`, such as zero-width spaces) are removed and the text is folded with NFKC, so full-width digits read as digits; both the original and the folded text are checked.

- **email, phone-number, credit-card-number, ip-address:** `@arcjet/redact`, which runs locally in WebAssembly. The guard uses only its detection, through the `replace` callback, and never its redacted output. ISSNs (`NNNN-NNNC`) are masked for this pass, since the phone detector reads them as numbers. Two of its matches are dropped: an email address whose domain has no top-level domain (`unit@.service`, `name@localhost`, `plugin@marketplace`), which can't reach anyone, and a phone number that is a slash date (`08/29`, `03/14/1990`).
- **us-ssn:** `NNN-NN-NNNN` with hyphens, spaces or dots (the same one twice), excluding area 000, 666 and 900–999, group 00 and serial 0000, which are never issued. Nine digits with no separator pass: too many ordinary numbers look like that. It is checked before phone numbers so the block names it.
- **credential:** `secretlint` with `@secretlint/secretlint-rule-preset-recommend`, run on the text as if it were a file, plus JSON Web Tokens (`eyJ….eyJ….…`) and `Authorization: Bearer` headers. The preset matches provider-specific token formats and whole private keys. A generic high-entropy string, a `password=` assignment or a truncated key is not a credential to it.
- **iban:** a country code, two digits and 11 to 30 more characters in any case, grouped by spaces, dashes or line breaks or not, then `ibantools`' country format and checksum. A wrong check digit passes.
- **matrix-id:** `@`, `!` or `#`, a localpart with at least one letter, a colon and a server name ending in an alphabetic TLD (the Matrix specification's common identifier format), so ratios and times such as `#1:2.5x` aren't ids.

## What it can't see

- Names, street addresses, dates of birth and private facts in free text. None is a fixed format.
- A value split, spelled out or encoded ("someone at example dot org", a percent-encoded Matrix id, a card number grouped with dots).
- Text that reaches the web some other way than through another agent.
