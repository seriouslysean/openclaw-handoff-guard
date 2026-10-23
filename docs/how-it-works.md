# How it works

Checked against OpenClaw 2026.10.5.

## The hook

The plugin registers one asynchronous `before_tool_call` handler at priority 90 (`plugins/hooks/tool-policy.md`). The result depends on the mode of the group that matched:

| Mode | Hook result |
| --- | --- |
| `block` | `{ block: true, blockReason }`, which is terminal |
| `approve` | `requireApproval` with `allowedDecisions: ["allow-once", "deny"]` and a 120 s timeout; the run pauses, and a timeout, a cancellation or no approval route blocks the call (`plugins/plugin-permission-requests.md`, "Decision behavior") |
| `warn` | no result; the group and kind go to `api.logger.warn` (`plugins/sdk-runtime.md`) |
| `off` | the group is not run |

The groups run in the order `secrets`, `structured-pii`, `contextual-pii`, and the strictest result wins: block, then approve. Unreadable parameters block before any group runs, whatever the modes are. A detector that throws is a finding in its group's mode: `block` blocks, `approve` asks, `warn` logs, `off` never ran it. OpenClaw blocks the call when the handler itself throws or exceeds its timeout, 15 seconds by default (`plugins/hooks/reference.md`, "On thrown error or timeout"). A check takes milliseconds.

Block reasons, approval texts and log lines name the group and kind and never the matched value.

## Which calls carry agent text

| Tool | Required text | Receiving agent |
| --- | --- | --- |
| `sessions_send` | `message` | the id in an `agent:<id>:…` `sessionKey`; with no `sessionKey` or `label`, `agentId`. Any other key or a label lookup is unknown |
| `sessions_spawn` | `task` | `agentId`, or the requester's own agent when it is absent (`tools/subagents/tool-reference.md`, `agentId`) |

The target order follows OpenClaw's own: `sessions_send` uses `agentId` only when neither `sessionKey` nor `label` is given (dist `sessions-spawn-tool`, 2026.10.5), so an `agentId` can't borrow an exemption for a call that goes elsewhere.

Every string in the parameters is checked, nested or not, except the fields that choose where or how the call runs (`SELECTORS` in `src/rules.ts`: session keys, agent ids, model, mode and similar). That covers a spawn's `label`, its `attachments` (a base64 `content` is decoded and checked as well), its `outputSchema`, and any field an upgrade adds. Tool names are compared without a namespace, case or padding.

`message` posts to a channel and reaches people, not agents (`concepts/session-tool.md`), so it is out of scope. A spawn with `context: "fork"` copies the requester's transcript to the child, but every native fork must target the requester's own agent (`tool-reference.md`, `context`), so a fork never reaches another agent.

## Per-target overrides

`targets` sets a mode per group for one receiving agent, replacing the group's own mode, so an agent can be exempt from `structured-pii` while `secrets` stays on. The deprecated `allowTargets` is read as every group `off` for the listed ids, and a `targets` entry for the same id wins. Only a known id matches: a call whose target is a label, an unmapped session or a spawn with no requester id is checked, since OpenClaw documents missing context as unproven (`plugins/hooks/tool-policy.md`).

## Groups and kinds

`secrets` holds `matrix-token` and `credential`. `structured-pii` holds every other kind; `ip-address` is in the group but not in its default kinds. `contextual-pii` holds `us-street` and `date-of-birth`: shapes that are personal data only with the words around them, so the group warns by default.

Each kind is a fixed format, so the same text gives the same verdict on every run. Within a group, the first kind found, in the order of the table in the README, names the match. Before matching, format characters (`\p{Cf}`, such as zero-width spaces) are removed and the text is folded with NFKC, so full-width digits read as digits; both the original and the folded text are checked.

- **email, phone-number, credit-card-number, ip-address:** `@arcjet/redact`, which runs locally in WebAssembly. The guard uses only its detection, through the `replace` callback, and never its redacted output. ISSNs (`NNNN-NNNC`) are masked for this pass, since the phone detector reads them as numbers. Two of its matches are dropped: an email address whose domain has no dot or starts with one (`unit@.service`, `name@localhost`, `plugin@marketplace`), since SMTP takes only fully qualified domains, and a phone number that is a slash date (`08/29`, `03/14/1990`). An address with a dot in its domain still blocks, including `unit@name.test`.
- **us-ssn:** `NNN-NN-NNNN` with hyphens, spaces or dots (the same one twice), excluding area 000, 666 and 900–999, group 00 and serial 0000, which are never issued. Nine digits with no separator count only with a keyword near them (below), since too many ordinary numbers look like that. It is checked before phone numbers so the block names it.
- **Keyword-named US identifiers:** a value that is only a run of digits or letters counts when one of Amazon Macie's keywords for it is within 30 characters before or after, in any case, with a space in the keyword also matching none, `_` or `-` (Macie, "Keyword requirements for managed data identifiers"; managed data identifiers for PII and financial data). Beyond Macie, a plural (`SSNs`), several spaces and a dropped dot (`i.t.i.n`) count too. A keyword must stand as a word, so `itinerary` is not `itin`. The text is also checked with a URL's `%XX` and a JSON string's `\n`, `\r` and `\t` read back, so `ssn=%20123456789` counts; the original and folded text are checked apart, so a keyword in one can't name a number in the other. Patterns are Presidio's US recognizers at 4f0e236.
  - **us-ssn**, nine digits with the same never-issued exclusions: `social security`, `ss#`, `ssn`.
  - **us-itin:** 9, two digits, a group from 50–65, 70–88, 90–92 or 94–99, and four digits (Presidio's UsItinRecognizer; python-stdnum's `us.itin`). Separated like an SSN it needs no keyword; unseparated it needs `itin`, `i.t.i.n.` or `individual taxpayer identification number`, or an SSN keyword, since an ITIN often goes in a field labelled SSN.
  - **us-bank-account:** 9 to 17 digits (Macie) with `bank account`, `checking account`, `savings account`, `deposit account`, `chequing account` or their `acct` forms. `account` alone is not a keyword, so `AWS account 123456789012` passes. Card numbers are checked first, so a card number beside `checking account` is named a card.
  - **us-passport:** nine digits, or a letter and eight digits, with `passport` or `travel document`.
  - **us-driver-license:** Presidio's US formats (its missing `[` restored), which include any 6 to 14 or 16 digits and match in any case, as Presidio does, with Macie's US keywords (`driver's license`, `driving licence`, `dl#`, `dl:` and the like). A match needs five characters, so class codes such as `A1` pass. A date or timestamp after `DL:` (`DL: 20261021`) blocks.
  - Left out: ABA routing numbers, which banks publish, so research on a bank would block; and card security codes and expiry dates, which identify nothing without the card number, already a kind.
- **matrix-token:** no rule set has Matrix tokens. Synapse's `syt_`, `syr_` and `syl_` and the Matrix Authentication Service's `mat_`, `mar_`, `mct_`, `mcr_` and `mpt_` end in a six-character base62 CRC-32 of the rest, and a token matches only when it verifies, so placeholders and typos pass, as a wrong IBAN check digit does. A localpart's `+` and `/` are also recognised written as `%2B` and `%2F` or as `\/`. Formats: Synapse `synapse/handlers/auth.py` at 7c85c80, the Matrix Authentication Service `crates/data-model/src/tokens.rs` at 93b6bb2. Synapse's older macaroon tokens are not recognised. It is checked before `credential`, so the block names it.
- **us-street:** a house number of one to six digits, an optional compass point (`N`, `N.`), one to three capitalised words and a street suffix from USPS Publication 28, appendix C1, in full or abbreviated (`Lane`, `Ln`, `St`, `Ave`). No standard defines a street address in free text; this is a heuristic, and it is case-sensitive, so prose such as `3 more ways` passes. An address without a suffix (`12 Larchmont, Fenmouth`) and a non-US format pass.
- **date-of-birth:** Presidio's date formats (DateRecognizer at 4f0e236: ISO, numeric day-month or month-day with a two- or four-digit year, and a month name with a day and year), with one of Macie's DATE_OF_BIRTH keywords (`bday`, `b-day`, `birth date`, `birthday`, `date of birth`, `dob`) or `born` within 30 characters, matched as the US identifiers are. Macie's list has no verb form, and `born` is how a birth date is usually written in prose. A year alone (`born in 2006`) passes.
- **credential:** `secretlint` with `@secretlint/secretlint-rule-preset-recommend`, run on the text as if it were a file, plus JSON Web Tokens (`eyJ….eyJ….…`) and `Authorization: Bearer` headers. The preset matches provider-specific token formats and whole private keys. A generic high-entropy string, a `password=` assignment or a truncated key is not a credential to it.
  - **gitleaks** (optional, `groups.secrets.gitleaks.binary`): runs after secretlint finds nothing. `gitleaks stdin --config config/gitleaks.toml --redact --exit-code 2 --ignore-gitleaks-allow --report-format json --report-path -`, text on stdin, as gitleaks 8.30.1 documents (README, "Usage", "Configuration", "Exit Codes"). Exit 0 is a pass; exit 2 with a report holding at least one `RuleID` is a finding; any other exit, an unreadable report or 5 s without an answer throws, which is a failure in the `secrets` mode. Only the presence of a `RuleID` is read: `--redact` blanks the match and secret in the report, and stderr is discarded. `--exit-code 2` is needed because gitleaks exits 1 for both a leak and an error by default. `--ignore-gitleaks-allow` stops a `gitleaks:allow` comment in the text from hiding a finding, and `GITLEAKS_*` variables are not passed on, so the environment can't swap the config. `config/gitleaks.toml` is `[extend] useDefault = true` with `disabledRules = ["generic-api-key"]`. No extra rules are added: the design names none.
- **iban:** a country code, two digits and 11 to 30 more characters in any case, grouped by spaces, dashes or line breaks or not, then `ibantools`' country format and checksum. A wrong check digit passes.
- **matrix-id:** `@`, `!` or `#`, a localpart with at least one letter, a colon and a server name ending in an alphabetic TLD (the Matrix specification's common identifier format), so ratios and times such as `#1:2.5x` aren't ids.

## What it can't see

- Names and private facts in free text, and street addresses and dates of birth outside the shapes above. None is a fixed format.
- A US identifier with no keyword near it, a keyword Macie doesn't list (`license number` alone), or one glued to its keyword or to a trailing letter (`ssn123456789`, `123456789x`).
- A value split, spelled out or encoded ("someone at example dot org", a percent-encoded Matrix id, a card number grouped with dots).
- Text that reaches the web some other way than through another agent.
