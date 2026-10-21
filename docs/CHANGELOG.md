# Changelog

## Unreleased

First version, built and tested against OpenClaw 2026.10.5.

- Blocks `sessions_send` and `sessions_spawn` text holding an email address, a phone or card number, an IBAN, a US Social Security number, a Matrix id or a credential. IP addresses are an opt-in kind.
- Blocks agent text it can't read.
- Checks text to every agent; `allowTargets` exempts listed ones, and `kinds` chooses what is blocked.
