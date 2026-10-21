# AGENTS.md

Rules for working in this repo.

1. Block only what the plugin is for: known personal-data formats in text one agent hands to another, or agent text it can't read. Never block other tools, never rewrite a call's parameters, and never echo a matched value.
2. Recognise fixed formats only: a match must be decidable from the text alone, the same on every run. Names, places and free-text facts belong to a different plugin.
3. Fail closed on agent text: unreadable parameters block, and a detector that throws blocks through the host's failure policy.
4. Keep one rule per plugin. A different guard is a different plugin.
5. Hard-code no agent id; exemptions come only from `allowTargets`.
6. Keep everything setup-agnostic: no agent names, hostnames, paths, chat ids or job names from any real setup, in code, tests, docs, commits, issues or pull requests.
7. Build fixtures from synthetic values: reserved domains (RFC 2606), fictional or published test numbers, and token shapes assembled at run time.
8. Ship a fix with a test you have watched fail without it.
9. Name a test for the failure it prevents.
10. Cite the OpenClaw version, and a docs page or source file, for any claim about OpenClaw behaviour, and label anything not yet checked on a live gateway as unverified in `docs/verification.md`.
11. Pin every tool, action and dependency to an exact version or commit.
12. Prefer a maintained detector package to a hand-written pattern. Runtime dependencies are the detectors in `package.json` and nothing else; a new one needs its maintenance and licence in the pull request.
13. A comment states a constraint the code can't show, never what the next line does.
14. Write terse, factual prose.
15. Commit and open pull requests on the user's behalf; pushing, merging, tagging and releasing each need their own approval.
16. Keep agent-session links and session trailers out of commit messages, issues and pull request bodies.
