import { redact } from '@arcjet/redact';
import { createEngine } from '@secretlint/node';
import { electronicFormatIBAN, isValidIBAN } from 'ibantools';
import { crc32 } from 'node:zlib';

/** Every kind the guard can recognise. Each is a fixed format, so a match is the same on every run. */
export const KINDS = [
  'email',
  'us-ssn',
  'us-itin',
  'credit-card-number',
  'us-bank-account',
  'us-passport',
  'us-driver-license',
  'phone-number',
  'ip-address',
  'iban',
  'matrix-id',
  'matrix-token',
  'credential',
] as const;
export type Kind = (typeof KINDS)[number];

/** The groups a kind belongs to: they set the mode a match is handled with (see `guard.ts`). */
export const GROUPS = ['secrets', 'structured-pii', 'contextual-pii'] as const;
export type Group = (typeof GROUPS)[number];

/** `contextual-pii` has no kinds yet: deterministic context patterns are added to it later. */
export const GROUP_KINDS: Record<Group, readonly Kind[]> = {
  secrets: ['matrix-token', 'credential'],
  'structured-pii': KINDS.filter((kind) => kind !== 'matrix-token' && kind !== 'credential'),
  'contextual-pii': [],
};

export const DEFAULT_GROUP_KINDS: Record<Group, readonly Kind[]> = {
  ...GROUP_KINDS,
  'structured-pii': GROUP_KINDS['structured-pii'].filter((kind) => kind !== 'ip-address'),
};

/** Public IP addresses are routine in research about networks and services, so they pass unless configured. */
export const DEFAULT_KINDS: readonly Kind[] = KINDS.filter((kind) => kind !== 'ip-address');

export const KIND_NAMES: Record<Kind, string> = {
  email: 'an email address',
  'phone-number': 'a phone number',
  'credit-card-number': 'a card number',
  'ip-address': 'an IP address',
  iban: 'a bank account number (IBAN)',
  'us-ssn': 'a US Social Security number',
  'us-itin': 'a US Individual Taxpayer Identification Number',
  'us-bank-account': 'a US bank account number',
  'us-passport': 'a US passport number',
  'us-driver-license': "a US driver's license number",
  'matrix-id': 'a Matrix user, room or alias id',
  'matrix-token': 'a Matrix access, refresh or login token',
  credential: 'a credential or token',
};

type ArcjetKind = 'email' | 'phone-number' | 'credit-card-number' | 'ip-address';
const ARCJET_KINDS: ReadonlySet<Kind> = new Set<ArcjetKind>(['email', 'phone-number', 'credit-card-number', 'ip-address']);

function isArcjetKind(kind: Kind): kind is ArcjetKind {
  return ARCJET_KINDS.has(kind);
}

/** Area 000, 666 and 9xx, group 00 and serial 0000 are never issued (US Social Security Administration, "Social Security Number Randomization"). */
const US_SSN = /\b(?!000|666|9\d\d)\d{3}([-. ])(?!00)\d{2}\1(?!0000)\d{4}\b/;

/**
 * Area 9xx with a group from 50–65, 70–88, 90–92 or 94–99 (Presidio's UsItinRecognizer; python-stdnum's us.itin).
 * Separated like an SSN, it needs no keyword; nine digits in a row need one (below).
 */
const ITIN_GROUP = String.raw`(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])`;
const US_ITIN = new RegExp(String.raw`\b9\d{2}([-. ])${ITIN_GROUP}\1\d{4}\b`);

/**
 * How near a keyword must be: within 30 characters before or after, in any case, a space in it also matching none, "_"
 * or "-" (Amazon Macie, "Keyword requirements for managed data identifiers"). A plural, a doubled space and a dropped
 * dot count too.
 */
const NEAR = 30;

/** A test for a value that is only a run of digits or letters, so it counts only with one of Macie's keywords near it. */
function named(pattern: string, keywords: readonly string[], minLength = 0): (text: string) => boolean {
  const keyword = keywords
    .map((word) =>
      word
        .replaceAll('.', String.raw`\.?`)
        .replaceAll('#', String.raw`\#`)
        .replaceAll("'", "['’]?")
        .replaceAll(' ', String.raw`[\s_-]*`),
    )
    .join('|');
  const word = String.raw`(?<![a-z0-9])(?:${keyword})s?(?![a-z])`;
  const before = new RegExp(String.raw`${word}[\s\S]{0,${NEAR}}$`, 'i');
  const after = new RegExp(String.raw`^[\s\S]{0,${NEAR}}${word}`, 'i');
  const candidate = new RegExp(String.raw`(?<![0-9A-Za-z])(?:${pattern})(?![0-9A-Za-z])`, 'gi');
  return (text) =>
    [...text.matchAll(candidate)].some(({ 0: value, index }) => {
      const end = index + value.length;
      return (
        value.length >= minLength &&
        (before.test(text.slice(Math.max(0, index - 100), index)) || after.test(text.slice(end, end + 100)))
      );
    });
}

/**
 * Keyword lists are Macie's managed data identifiers for the US; patterns are Presidio's US recognizers, the bank
 * account's 9 to 17 digits Macie's. Presidio's driver's license pattern has its missing "[" restored, and a match needs
 * five characters, so class codes such as "A1" pass.
 */
const NAMED: readonly [Kind, (text: string) => boolean][] = [
  ['us-ssn', named(String.raw`(?!000|666|9\d\d)\d{3}(?!00)\d{2}(?!0000)\d{4}`, ['social security', 'ss#', 'ssn'])],
  // An ITIN is issued to someone who can't get an SSN and often goes in a field labelled SSN, so those keywords count.
  [
    'us-itin',
    named(String.raw`9\d{2}${ITIN_GROUP}\d{4}`, [
      'i.t.i.n.',
      'individual taxpayer identification number',
      'itin',
      'social security',
      'ss#',
      'ssn',
    ]),
  ],
  [
    'us-bank-account',
    named(String.raw`\d{9,17}`, [
      'bank account',
      'bank acct',
      'checking account',
      'checking acct',
      'deposit account',
      'deposit acct',
      'savings account',
      'savings acct',
      'chequing account',
      'chequing acct',
    ]),
  ],
  ['us-passport', named(String.raw`\d{9}|[A-Z]\d{8}`, ['passport', 'travel document'])],
  [
    'us-driver-license',
    named(
      String.raw`[A-Z][0-9]{3,6}|[A-Z][0-9]{5,9}|[A-Z][0-9]{6,8}|[A-Z][0-9]{4,8}|[A-Z][0-9]{9,11}|[A-Z]{1,2}[0-9]{5,6}|H[0-9]{8}|V[0-9]{6}|X[0-9]{8}|[A-Z]{2}[0-9]{2,5}|[A-Z]{2}[0-9]{3,7}|[0-9]{2}[A-Z]{3}[0-9]{5,6}|[A-Z][0-9]{13,14}|[A-Z][0-9]{18}|[A-Z][0-9]{6}R|[A-Z][0-9]{9}|[A-Z][0-9]{1,12}|[0-9]{9}[A-Z]|[A-Z]{2}[0-9]{6}[A-Z]|[0-9]{8}[A-Z]{2}|[0-9]{3}[A-Z]{2}[0-9]{4}|[A-Z][0-9][A-Z][0-9][A-Z]|[0-9]{7,8}[A-Z]|[0-9]{6,14}|[0-9]{16}`,
      [
        'dl#',
        'dl:',
        'dlno#',
        'driver licence',
        'driver licences',
        'driver license',
        'driver licenses',
        'driver permit',
        'drivers lic.',
        'drivers licence',
        "driver's licence",
        'drivers licences',
        "driver's licences",
        'drivers license',
        "driver's license",
        'drivers licenses',
        "driver's licenses",
        'drivers permit',
        "driver's permit",
        'drivers permit number',
        'driving licence',
        'driving license',
        'driving permit',
      ],
      5,
    ),
  ],
];

/** A sigil, a localpart and a server name with a dot (Matrix specification, appendix "Common Identifier Format"). */
// The localpart needs a letter and the server an alphabetic TLD, so "#1:2.5x" and "@10:30.5" are not ids.
const MATRIX_ID = /(?<![\w.%+-])[@!#](?=[A-Za-z0-9._=/+-]*[A-Za-z])[A-Za-z0-9._=/+-]+:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/;

/** A country code, two check digits and 11 to 30 more characters, in any case and grouped or not; the checksum decides. */
const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?:[\s-]?[A-Z0-9]){11,30}\b/gi;

/**
 * Matches that can't be what the kind names. SMTP takes only fully qualified domain names (RFC 5321 section 2.3.5), so a
 * domain with no dot, or one starting with a dot, is not a mailbox; anything else blocks, glued text and IP literals
 * included. A slash date such as "08/29" or "03/14/1990" is not a phone number.
 */
const NOT_A_MATCH: Partial<Record<ArcjetKind, RegExp>> = {
  email: /@(?:\.|[^.]*$)/,
  'phone-number': /^\d{1,2}\/\d{1,2}(?:\/(?:\d{2}|\d{4}))?$/,
};

/** ISSNs (NNNN-NNNC) read as phone numbers to the phone detector, so they are masked for that pass only. */
const ISSN = /\b\d{4}-\d{3}[\dX]\b/gi;

/** JSON Web Tokens and bearer headers: fixed shapes the secretlint preset has no rule for. */
const TOKEN_SHAPES = [
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  /\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
];

/**
 * Matrix tokens, which no rule set has: a prefix, a body and a six-character base62 CRC-32 of the rest. Synapse's syt_,
 * syr_ and syl_ carry a base64 localpart and 20 letters and write the checksum most significant digit first
 * (synapse/handlers/auth.py); the Matrix Authentication Service's mat_, mar_, mct_, mcr_ and mpt_ carry 30 letters or
 * digits and write it least significant digit first (crates/data-model/src/tokens.rs).
 */
const MATRIX_TOKEN =
  /(?<![A-Za-z0-9])(?:(sy[tr]_[A-Za-z0-9+/]+_[A-Za-z]{20}|syl_[A-Za-z]{20})|(m(?:at|ar|ct|cr|pt)_[A-Za-z0-9]{30}))_([0-9A-Za-z]{6})(?![A-Za-z0-9])/g;

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function base62(value: number): string[] {
  const digits: string[] = [];
  for (let rest = value; rest > 0; rest = Math.floor(rest / 62)) {
    digits.unshift(BASE62.charAt(rest % 62));
  }
  return digits;
}

// A wrong checksum passes, like an IBAN's: it is a placeholder or a typo, not a working token. The localpart's + and /
// are read back from a URL's %2B and %2F and a JSON encoder's \/.
function hasMatrixToken(text: string): boolean {
  const decoded = text.replaceAll(/%2B/gi, '+').replaceAll(/%2F/gi, '/').replaceAll('\\/', '/');
  return [...decoded.matchAll(MATRIX_TOKEN)].some(([, synapse, mas, checksum]) => {
    const digits = base62(crc32(synapse ?? mas ?? ''));
    return (synapse ? digits : digits.toReversed()).join('').padStart(6, '0') === checksum;
  });
}

/** A URL's %XX and a JSON string's \n, \r and \t, read back so an escaped separator doesn't glue a value to its keyword. */
function unescaped(text: string): string {
  return text
    .replaceAll(/%[0-9A-F]{2}/gi, (escape) => String.fromCodePoint(Number.parseInt(escape.slice(1), 16)))
    .replaceAll(/\\[nrt]/g, ' ');
}

/**
 * Format characters (zero-width and the like) are removed and compatibility forms folded (NFKC), so "４１１１" and a
 * zero-width space inside a number don't hide it. Ideographic full stops become dots, which NFKC leaves alone.
 */
export function normalise(text: string): string {
  return text.normalize('NFKC').replaceAll(/\p{Cf}/gu, '').replaceAll(/[\u3002\uFF61]/g, '.');
}

async function arcjetKinds(text: string, wanted: ReadonlySet<Kind>): Promise<Kind[]> {
  const entities = [...wanted].filter(isArcjetKind);
  if (entities.length === 0) {
    return [];
  }
  const found: Kind[] = [];
  await redact(text.replaceAll(ISSN, (issn) => ' '.repeat(issn.length)), {
    entities,
    replace: (entity, value) => {
      if (!NOT_A_MATCH[entity]?.test(value)) {
        found.push(entity);
      }
      return undefined;
    },
  });
  return found;
}

type Engine = ReturnType<typeof createEngine>;

const startEngine = (): Engine =>
  createEngine({ formatter: 'json', configFileJSON: { rules: [{ id: '@secretlint/secretlint-rule-preset-recommend' }] } });

let start = startEngine;
let secretlintEngine: Engine | undefined;

function engine(): Engine {
  // A failed start is not cached: the next check retries instead of blocking every call until a restart.
  secretlintEngine ??= start().catch((error: unknown) => {
    secretlintEngine = undefined;
    throw error;
  });
  return secretlintEngine;
}

/** secretlint's recommended preset: provider token formats, private keys, basic-auth and database connection URLs. */
async function hasCredential(text: string): Promise<boolean> {
  if (TOKEN_SHAPES.some((shape) => shape.test(text))) {
    return true;
  }
  const result = await (await engine()).executeOnContent({ content: text, filePath: 'message.txt' });
  return !result.ok;
}

/** For tests: forget the engine, and start the next one with factory. */
export function resetEngine(factory: () => Engine = startEngine): void {
  start = factory;
  secretlintEngine = undefined;
}

function hasIban(text: string): boolean {
  // A candidate can run into the next word ("... 32 by"), so every length from the longest down is tried.
  return [...text.matchAll(IBAN_CANDIDATE)].some((match) => {
    const compact = electronicFormatIBAN(match[0].replaceAll(/\s/g, '')) ?? '';
    for (let end = compact.length; end >= 15; end -= 1) {
      if (isValidIBAN(compact.slice(0, end))) {
        return true;
      }
    }
    return false;
  });
}

/** The first kind of personal data found in the text, in KINDS order, or undefined. */
export async function findPersonalData(raw: string, kinds: readonly Kind[] = DEFAULT_KINDS): Promise<Kind | undefined> {
  const wanted = new Set(kinds);
  const folded = normalise(raw);
  const text = folded === raw ? raw : `${raw}\n${folded}`;
  const found = new Set<Kind>(await arcjetKinds(text, wanted));
  if (wanted.has('iban') && hasIban(text)) {
    found.add('iban');
  }
  if (wanted.has('us-ssn') && US_SSN.test(text)) {
    found.add('us-ssn');
  }
  if (wanted.has('us-itin') && US_ITIN.test(text)) {
    found.add('us-itin');
  }
  // Each form is checked apart, so a keyword at the end of one can't name a number at the start of the next.
  const forms = [...new Set([raw, folded, unescaped(folded)])];
  for (const [kind, has] of NAMED) {
    if (wanted.has(kind) && forms.some(has)) {
      found.add(kind);
    }
  }
  if (wanted.has('matrix-id') && MATRIX_ID.test(text)) {
    found.add('matrix-id');
  }
  if (wanted.has('matrix-token') && hasMatrixToken(text)) {
    found.add('matrix-token');
  }
  if (wanted.has('credential') && (await hasCredential(text))) {
    found.add('credential');
  }
  return KINDS.find((kind) => found.has(kind));
}
