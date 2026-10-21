# Changelog

## Unreleased

First version, built and tested against OpenClaw 2026.10.5.

- Blocks `sessions_send` and `sessions_spawn` text holding an email address, a phone or card number, an IBAN, a US Social Security number, a Matrix id or a credential. IP addresses are an opt-in kind.
- Checks every text field of the call, attachments included, after removing format characters and folding with NFKC.
- Blocks agent text it can't read.
- Passes email-shaped text on a domain with no top-level domain, such as unit templates, plugin ids and `localhost`, and slash dates that read as phone numbers.
- Checks text to every agent; `allowTargets` exempts listed ones, and `kinds` chooses what is blocked.
