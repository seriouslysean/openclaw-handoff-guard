import { redact } from '@arcjet/redact';
import { createEngine } from '@secretlint/node';
import { electronicFormatIBAN, isValidIBAN } from 'ibantools';

/** Every kind the guard can recognise. Each is a fixed format, so a match is the same on every run. */
export const KINDS = [
  'email',
  'us-ssn',
  'phone-number',
  'credit-card-number',
  'ip-address',
  'iban',
  'matrix-id',
  'credential',
] as const;
export type Kind = (typeof KINDS)[number];

/** Public IP addresses are routine in research about networks and services, so they pass unless configured. */
export const DEFAULT_KINDS: readonly Kind[] = KINDS.filter((kind) => kind !== 'ip-address');

export const KIND_NAMES: Record<Kind, string> = {
  email: 'an email address',
  'phone-number': 'a phone number',
  'credit-card-number': 'a card number',
  'ip-address': 'an IP address',
  iban: 'a bank account number (IBAN)',
  'us-ssn': 'a US Social Security number',
  'matrix-id': 'a Matrix user, room or alias id',
  credential: 'a credential or token',
};

type ArcjetKind = 'email' | 'phone-number' | 'credit-card-number' | 'ip-address';
const ARCJET_KINDS: ReadonlySet<Kind> = new Set<ArcjetKind>(['email', 'phone-number', 'credit-card-number', 'ip-address']);

function isArcjetKind(kind: Kind): kind is ArcjetKind {
  return ARCJET_KINDS.has(kind);
}

/** Area 000, 666 and 9xx, group 00 and serial 0000 are never issued (US Social Security Administration, "Social Security Number Randomization"). */
const US_SSN = /\b(?!000|666|9\d\d)\d{3}([-. ])(?!00)\d{2}\1(?!0000)\d{4}\b/;

/** A sigil, a localpart and a server name with a dot (Matrix specification, appendix "Common Identifier Format"). */
// The localpart needs a letter and the server an alphabetic TLD, so "#1:2.5x" and "@10:30.5" are not ids.
const MATRIX_ID = /(?<![\w.%+-])[@!#](?=[A-Za-z0-9._=/+-]*[A-Za-z])[A-Za-z0-9._=/+-]+:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/;

/** A country code, two check digits and 11 to 30 more characters, in any case and grouped or not; the checksum decides. */
const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?:[\s-]?[A-Z0-9]){11,30}\b/gi;

/** ISSNs (NNNN-NNNC) read as phone numbers to the phone detector, so they are masked for that pass only. */
const ISSN = /\b\d{4}-\d{3}[\dX]\b/gi;

/** JSON Web Tokens and bearer headers: fixed shapes the secretlint preset has no rule for. */
const TOKEN_SHAPES = [
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  /\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
];

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
    replace: (entity) => {
      found.push(entity);
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
  if (wanted.has('matrix-id') && MATRIX_ID.test(text)) {
    found.add('matrix-id');
  }
  if (wanted.has('credential') && (await hasCredential(text))) {
    found.add('credential');
  }
  return KINDS.find((kind) => found.has(kind));
}
