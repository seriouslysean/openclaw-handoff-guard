# Changelog

## Unreleased

- Renamed from `pii-guard` to `leak-guard`: plugin id `leak-guard`, config at `plugins.entries.leak-guard.config`. Re-enable under the new id.
- Three groups, `secrets`, `structured-pii` and `contextual-pii`, each with a mode: `block`, `approve`, `warn` or `off`. Defaults: `secrets` and `structured-pii` block, `contextual-pii` warns. No new detector.
- `targets` sets a mode per group for one receiving agent. `allowTargets` and a top-level `kinds` still work and are deprecated; they go in the next release.
- New kind `matrix-token` in `secrets`: Matrix access, refresh and login tokens from Synapse and the Matrix Authentication Service, matched by their checksum. It is in the default kinds of `secrets`.
- Optional gitleaks 8.30.1 detector for the `credential` kind, run as a separate process from a binary you supply at `groups.secrets.gitleaks.binary`, without `generic-api-key`. Skipped with one startup warning when unset.
- A detector that fails follows its group's mode; unreadable text always blocks.
- First `contextual-pii` kinds, logged as warnings by default: `us-street` (house number, capitalised words, USPS suffix) and `date-of-birth` (a Presidio date format with a Macie birth keyword or `born` within 30 characters).

First version, built and tested against OpenClaw 2026.10.5.

- Blocks `sessions_send` and `sessions_spawn` text holding an email address, a phone or card number, an IBAN, a US Social Security number, a Matrix id or a credential. IP addresses are an opt-in kind.
- Checks every text field of the call, attachments included, after removing format characters and folding with NFKC.
- Blocks agent text it can't read.
- Passes email-shaped text whose domain has no dot or starts with one, such as `unit@.service`, plugin ids and `localhost`, and slash dates that read as phone numbers.
- Checks text to every agent; `allowTargets` exempts listed ones, and `kinds` chooses what is blocked.
- Blocks US ITINs, bank account, passport and driver's license numbers, and unseparated Social Security numbers, when one of Amazon Macie's keywords for them is within 30 characters. A separated ITIN blocks without one.
