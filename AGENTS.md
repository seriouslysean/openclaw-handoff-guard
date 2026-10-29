# AGENTS.md

Rules for working in this repo.

1. Check agent text for secrets and personal data by group, with each group's mode. Never block other tools, never rewrite a call's parameters, and never echo a matched value.
2. `secrets` and `structured-pii` recognise fixed formats only: a match must be decidable from the text alone, the same on every run. `contextual-pii` uses deterministic context patterns only. A model verdict needs its own decision and never blocks alone.
3. Fail by the group's mode: a detector that throws is handled as the group's `block`, `approve` or `warn` says, and `off` does not run it. Unreadable text always blocks.
4. Keep one concern per plugin: what agents hand each other, split into groups. A guard on another surface is a different plugin.
5. Hard-code no agent id; per-agent exemptions come only from `targets`.
6. Keep everything setup-agnostic: no agent names, hostnames, paths, chat ids or job names from any real setup, in code, tests, docs, commits, issues or pull requests.
7. Build fixtures from synthetic values: reserved domains (RFC 2606), fictional or published test numbers, and token shapes assembled at run time.
8. Ship a fix with a test you have watched fail without it.
9. Before writing or changing a test, read https://github.com/splitleafhq/.github/blob/main/docs/testing.md.
10. Cite the OpenClaw version, and a docs page or source file, for any claim about OpenClaw behaviour, and label anything not yet checked on a live gateway as unverified in `docs/verification.md`.
11. Pin every tool, action and dependency to an exact version or commit.
12. Prefer a maintained detector package to a hand-written pattern. Runtime dependencies are the detectors in `package.json` and one pinned detector binary run as a separate process: gitleaks, a release artifact pinned by version and SHA-256. A new one needs its maintenance and licence in the pull request.
13. A comment states a constraint the code can't show, never what the next line does.
14. Write terse, factual prose.
15. Commit and open pull requests on the user's behalf; pushing, merging, tagging and releasing each need their own approval.
16. Keep agent-session links and session trailers out of commit messages, issues and pull request bodies.
