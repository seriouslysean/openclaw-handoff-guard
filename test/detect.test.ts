import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { DEFAULT_KINDS, KINDS, findPersonalData, normalise } from '../src/detect.ts';

// Synthetic values only: reserved domains, fictional numbers, published test card and IBAN numbers. Token-shaped
// values are assembled at run time so no secret scanner mistakes this file for a leak.
const FOUND: [string, string][] = [
  ['email', 'write to someone@example.org about it'],
  ['phone-number', 'call (555) 010-0199 tonight'],
  ['phone-number', 'the office is on +44 20 7946 0958'],
  ['credit-card-number', 'card 4111 1111 1111 1111, expires 12/29'],
  ['iban', 'pay GB82 WEST 1234 5698 7654 32 by Friday'],
  ['iban', 'account DE89370400440532013000'],
  ['us-ssn', 'their number is 123-45-6789'],
  ['matrix-id', 'ask @someone:example.org in the room'],
  ['matrix-id', 'the room is !abcdefgh:example.org'],
  ['credential', `use ghp_${'A1b2C3d4E5'.repeat(3)}abcdef for it`],
  ['credential', `xoxb-${'1234567890'}-${'1234567890'}-${'abcdefghijklmnopqrstuvwx'}`],
  // Variants found by review: separators, case, grouping and hidden characters must not hide a value.
  ['us-ssn', 'their number is 123 45 6789'],
  ['us-ssn', 'their number is 123.45.6789'],
  ['us-ssn', 'their number is 123-45-\u200B6789'],
  ['iban', 'account gb82west12345698765432'],
  ['iban', 'account GB82-WEST-1234-5698-7654-32'],
  ['iban', 'account GB82 WEST 1234\n5698 7654 32'],
  ['credit-card-number', 'card 4111\u200B1111\u200B1111\u200B1111'],
  ['credit-card-number', 'card ４１１１ １１１１ １１１１ １１１１'],
  ['email', 'write to someone@example\u3002org'],
  ['credential', `token ${['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'].join('.')}`],
  ['credential', `Authorization: Bearer ${'abcDEF123456ghiJKL7890'}`],
];

for (const [kind, text] of FOUND) {
  test(`${kind} is found: ${text.slice(0, 32)}`, async () => {
    assert.equal(await findPersonalData(text, KINDS), kind);
  });
}

// Research text that must pass: versions, identifiers and numbers that look like digits in a row.
const RESEARCH = [
  'what changed between openclaw 2026.10.4 and 2026.10.5',
  'reviews of ISBN 978-0-13-468599-1',
  'papers from 1999-2004 on a 405B model',
  'llama.cpp on port 8080 with 131072 context',
  'arXiv:2310.06825 and doi 10.1145/3442188.3445922',
  'the GPU costs $1,599.99 and draws 575 W',
  'AC 15, HP 45, 1d20+5 against a CR 3 creature',
  'about 1234567890 tokens a day and 5551234 downloads',
  'the #general channel and the @mention syntax',
  'compare GB82 and DE89 rates',
  'a token prefix like ghp_ is a GitHub token',
  'published at 2026-10-21T05:14:08Z, build 123-45-678',
  // False positives found by review: ISSNs, ratios and times are not phone numbers or Matrix ids.
  'ISSN 0378-5955 and 0028-0836',
  'ranked #1:2.5x faster, #3:1.5 odds, seed #12:30.5, @10:30.5',
  'a 123456789 row table',
];

for (const text of RESEARCH) {
  test(`research text passes: ${text.slice(0, 32)}`, async () => {
    assert.equal(await findPersonalData(text), undefined);
  });
}

test('IP addresses pass by default and are found when asked for', async () => {
  assert.ok(!DEFAULT_KINDS.includes('ip-address'));
  assert.equal(await findPersonalData('the server is 203.0.113.7'), undefined);
  assert.equal(await findPersonalData('the server is 203.0.113.7', ['ip-address']), 'ip-address');
});

test('a kind left out is not looked for', async () => {
  assert.equal(await findPersonalData('write to someone@example.org', ['phone-number']), undefined);
  assert.equal(await findPersonalData('write to someone@example.org', []), undefined);
});

test('an IBAN with a wrong check digit passes', async () => {
  assert.equal(await findPersonalData('GB83 WEST 1234 5698 7654 32', ['iban']), undefined);
});

test('an SSN that is never issued passes', async () => {
  for (const text of ['000-12-3456', '666-12-3456', '900-12-3456', '123-00-4567', '123-45-0000']) {
    assert.equal(await findPersonalData(text, ['us-ssn']), undefined, text);
  }
});

test('an SSN shape is named as one, not as a phone number', async () => {
  assert.equal(await findPersonalData('ticket 123-45-6789'), 'us-ssn');
});

test('normalising removes format characters and folds compatibility forms', () => {
  assert.equal(normalise('a\u200Bb\u2060c ４２ x\u3002y'), 'abc 42 x.y');
});

test('the first kind in order is reported when several are present', async () => {
  assert.equal(await findPersonalData('someone@example.org or 123-45-6789'), 'email');
});
