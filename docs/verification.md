# Verification

## Checked

- **Unit tests** (`npm test`) cover:
  - each kind found in a synthetic sample, including separator, case, line-break, zero-width and full-width variants;
  - research text that must pass (versions, ISBN-13s, ISSNs, DOIs, ports, prices, dates and slash dates, dice notation, ratios, bare prefixes, and addresses whose domain has no dot or starts with one);
  - IBANs with a wrong check digit, Matrix token shapes with a wrong checksum and SSNs that are never issued, all passing;
  - a Matrix token blocked by default through `secrets` and passing with `secrets` off;
  - keyword-named US identifiers found with a keyword before or after, in a JSON key, with `_` or `-` for a space, with a plural or a dropped dot in the keyword, after a URL-escaped or JSON-escaped separator and as an ITIN labelled SSN, and passing with a word that only contains a keyword (`itinerary`), a keyword over 30 characters away (also across the original and folded text), `AWS account` and license class codes;
  - the receiving agent for each call shape in OpenClaw's own order, and per-target overrides that match only a known id;
  - each mode's result (block, approve with `allow-once` and `deny` only, warn logging the kind and not the value, off), the strictest result winning, a detector failure following its group's mode, unreadable text blocking with every group off, and the fallbacks for an unknown group, mode or kind;
  - the deprecated `allowTargets` and top-level `kinds`;
  - every text field checked, attachments raw and base64-decoded, selectors skipped, and tool names compared without namespace or case;
  - a detector engine that fails to start is retried, not cached;
  - unreadable agent text, blocked;
  - a block reason that never echoes the value;
  - gitleaks through a fake executable (finding, no finding, exit 1, unreadable report, timeout, stdin-only text, the flags and the pinned config), its failure following each group mode, and the skipped-with-one-warning startup;
  - `us-street` and `date-of-birth` found, warning by default and blocking when the group is set to `block`, and passing on prose numbers, suffix-less addresses, dates with no birth keyword and a year alone after `born`;
  - the leak scan.
- **gitleaks 8.30.1 against the real binary** (`test/gitleaks.test.ts`, runs only when `gitleaks` on `PATH`, or `GITLEAKS_BIN`, reports 8.30.1): a provider token is found, also with a `gitleaks:allow` comment; plain text and a generic `api_key = "…"` pass.
- **Technical text:** 0 of 4,147 paragraphs from four repositories' Markdown and source (tests and fixtures left out) match `us-street` or `date-of-birth`. The same patterns, measured before this change on 40 synthetic addresses and 20 synthetic dates of birth, matched all of them; those samples are no longer kept, so recall is not rechecked here.
- **Adversarial review** (read-only, before the first push): ten findings, among them an `agentId` borrowing an exemption, unchecked spawn attachments, format variants and false positives. Each one is fixed with a test, or listed as a gap in `docs/how-it-works.md`.
- **Typecheck** against the OpenClaw 2026.10.5 plugin SDK.
- **Loads in OpenClaw 2026.10.5:** in an isolated state directory (`OPENCLAW_STATE_DIR`), `plugins install --link --accept-capabilities` followed by `plugins inspect leak-guard --runtime --json` reports `status: loaded`, `capabilityCount: 0` and `typedHooks: [{ before_tool_call, priority 90 }]`.
- **Runtime dependencies alone** (`npm ci --omit=dev`): a check runs in about 10 ms on the first call and about 2 ms on 1,750 characters after that, on Apple silicon.

## Not yet checked on a live gateway

- gitleaks inside a running gateway: the binary's path being executable by the gateway user, and the spawn working under the gateway's sandbox, if any.
- gitleaks versions other than 8.30.1.
- An `approve` result: the pause, the approval prompt and the deny on timeout are from `plugins/plugin-permission-requests.md` and `plugins/hooks/tool-policy.md` (2026.10.5), not run.
- Where `api.logger.warn` lines go and whether the host redacts or rate-limits them: the logger's methods are documented (`plugins/sdk-runtime.md`), its sink and format are not.
- Whether the host rejects a config with an unknown mode or kind at validation (the manifest schema lists the values) or passes it to the plugin, which then falls back to the default.
- That the nested `groups` and `targets` objects in `configSchema` are accepted as written.

- A `sessions_send` with an email address blocked before execution, and a clean one accepted.
- A `sessions_spawn` under another agent with a credential in `task`.
- Tool Search and Code Mode calls: from the docs, not run.

## Checking it on your gateway

1. Run `openclaw plugins inspect leak-guard --runtime --json`. The plugin should be loaded, with `before_tool_call` in `typedHooks`.
2. Ask an agent to send another agent a message containing an address on the reserved `example.org` domain. Expect the block message, naming an email address and not the address itself.
3. Ask it to send the same agent a message with none of the kinds. Expect it to arrive.
