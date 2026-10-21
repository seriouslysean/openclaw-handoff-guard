import { redact } from '@arcjet/redact';
import { createEngine } from '@secretlint/node';
import { electronicFormatIBAN, isValidIBAN } from 'ibantools';

/** Every kind the guard can recognise. Each is a fixed format, so a match is the same on every run. */
export const KINDS = [
  'email',
  'phone-number',
  'credit-card-number',
  'ip-address',
  'iban',
  'us-ssn',
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
const US_SSN = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/;

/** A sigil, a localpart and a server name with a dot (Matrix specification, appendix "Common Identifier Format"). */
const MATRIX_ID = /(?<![\w.%+-])[@!#][A-Za-z0-9._=/+-]+:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/;

/** A country code, two check digits and 11 to 30 more characters, grouped by four or not; the checksum decides. */
const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/g;

async function arcjetKinds(text: string, wanted: ReadonlySet<Kind>): Promise<Kind[]> {
  const entities = [...wanted].filter(isArcjetKind);
  if (entities.length === 0) {
    return [];
  }
  const found: Kind[] = [];
  await redact(text, {
    entities,
    replace: (entity) => {
      found.push(entity);
      return undefined;
    },
  });
  return found;
}

let secretlintEngine: ReturnType<typeof createEngine> | undefined;

/** secretlint's recommended preset: provider token formats, private keys, basic-auth and database connection URLs. */
async function hasCredential(text: string): Promise<boolean> {
  secretlintEngine ??= createEngine({
    formatter: 'json',
    configFileJSON: { rules: [{ id: '@secretlint/secretlint-rule-preset-recommend' }] },
  });
  const result = await (await secretlintEngine).executeOnContent({ content: text, filePath: 'message.txt' });
  return !result.ok;
}

function hasIban(text: string): boolean {
  return [...text.matchAll(IBAN_CANDIDATE)].some((match) => isValidIBAN(electronicFormatIBAN(match[0]) ?? ''));
}

/** The first kind of personal data found in the text, in KINDS order, or undefined. */
export async function findPersonalData(text: string, kinds: readonly Kind[] = DEFAULT_KINDS): Promise<Kind | undefined> {
  const wanted = new Set(kinds);
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
