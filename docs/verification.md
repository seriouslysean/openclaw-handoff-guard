# Verification

## Checked

- **Unit tests** (`npm test`) cover:
  - each kind found in a synthetic sample, including separator, case, line-break, zero-width and full-width variants;
  - research text that must pass (versions, ISBN-13s, ISSNs, DOIs, ports, prices, dates and slash dates, dice notation, ratios, bare prefixes, and addresses whose domain has no dot or starts with one);
  - IBANs with a wrong check digit and SSNs that are never issued, both passing;
  - the receiving agent for each call shape in OpenClaw's own order, and exemptions that match only a known id;
  - every text field checked, attachments raw and base64-decoded, selectors skipped, and tool names compared without namespace or case;
  - a detector engine that fails to start is retried, not cached;
  - unreadable agent text, blocked;
  - a block reason that never echoes the value;
  - the leak scan.
- **Adversarial review** (read-only, before the first push): ten findings, among them an `agentId` borrowing an exemption, unchecked spawn attachments, format variants and false positives. Each one is fixed with a test, or listed as a gap in `docs/how-it-works.md`.
- **Typecheck** against the OpenClaw 2026.10.5 plugin SDK.
- **Loads in OpenClaw 2026.10.5:** in an isolated state directory (`OPENCLAW_STATE_DIR`), `plugins install --link --accept-capabilities` followed by `plugins inspect pii-guard --runtime --json` reports `status: loaded`, `capabilityCount: 0` and `typedHooks: [{ before_tool_call, priority 90 }]`.
- **Runtime dependencies alone** (`npm ci --omit=dev`): a check runs in about 10 ms on the first call and about 2 ms on 1,750 characters after that, on Apple silicon.

## Not yet checked on a live gateway

- A `sessions_send` with an email address blocked before execution, and a clean one accepted.
- A `sessions_spawn` under another agent with a credential in `task`.
- Tool Search and Code Mode calls: from the docs, not run.

## Checking it on your gateway

1. Run `openclaw plugins inspect pii-guard --runtime --json`. The plugin should be loaded, with `before_tool_call` in `typedHooks`.
2. Ask an agent to send another agent a message containing an address on the reserved `example.org` domain. Expect the block message, naming an email address and not the address itself.
3. Ask it to send the same agent a message with none of the kinds. Expect it to arrive.
