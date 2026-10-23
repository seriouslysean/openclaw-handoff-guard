import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { findPersonalData } from '../src/detect.ts';
import { type HookApi, decide, register, resolveConfig } from '../src/guard.ts';
import { GITLEAKS_CONFIG, GITLEAKS_VERSION, runGitleaks } from '../src/gitleaks.ts';

// The fake binary reads stdin like gitleaks: a marker word in the text picks the exit code and report. Tokens are
// assembled at run time so no secret scanner mistakes this file for a leak.
const FAKE = `#!/bin/sh
printf '%s\\n' "$@" > "$0.args"
text=$(cat)
case "$text" in
  *FAKELEAK*) printf '[{"RuleID":"aws-access-token","Match":"REDACTED","Secret":"REDACTED"}]\\n'; exit 2 ;;
  *EMPTYLEAK*) printf '[]\\n'; exit 2 ;;
  *FAKEFAIL*) printf 'boom\\n' >&2; exit 1 ;;
  *FAKEBADJSON*) printf 'not json\\n'; exit 2 ;;
  *FAKESLOW*) sleep 5; exit 0 ;;
  *FAKEEARLYEXIT*) exit 0 ;;
esac
printf '[]\\n'
exit 0
`;

let dir = '';
let fake = '';
before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'leak-guard-'));
  fake = join(dir, 'gitleaks');
  await writeFile(fake, FAKE);
  await chmod(fake, 0o755);
});
after(async () => {
  await rm(dir, { recursive: true, force: true });
});

const send = (message: string) => ({ toolName: 'sessions_send', params: { agentId: 'helper', message } });

test('a gitleaks report with a rule id is a credential, found through findPersonalData', async () => {
  assert.equal(await findPersonalData('note FAKELEAK here', ['credential'], { gitleaks: fake }), 'credential');
  assert.equal(await findPersonalData('papers on sparse attention', ['credential'], { gitleaks: fake }), undefined);
});

test('gitleaks is not run when no binary is set or credential is not a wanted kind', async () => {
  assert.equal(await findPersonalData('note FAKELEAK here', ['credential']), undefined);
  assert.equal(await findPersonalData('note FAKELEAK here', ['email'], { gitleaks: fake }), undefined);
});

test('the text goes on stdin and never in argv, with the pinned config, redaction and no inline allow', async () => {
  await runGitleaks(fake, 'FAKELEAK secret-text-Cadderly');
  const args = (await readFile(`${fake}.args`, 'utf8')).split('\n').filter(Boolean);
  assert.equal(args[0], 'stdin');
  assert.ok(args.includes('--redact'));
  assert.ok(args.includes('--ignore-gitleaks-allow'));
  assert.equal(args[args.indexOf('--config') + 1], GITLEAKS_CONFIG);
  assert.equal(args[args.indexOf('--exit-code') + 1], '2');
  assert.ok(args.every((arg) => !arg.includes('Cadderly')));
});

test('an exit 1, a report that is not JSON, a leak exit with no rule id and a missing binary fail the check', async () => {
  for (const text of ['FAKEFAIL', 'FAKEBADJSON', 'EMPTYLEAK', 'FAKEEARLYEXIT-nothing']) {
    if (text.startsWith('FAKEEARLY')) {
      assert.equal(await runGitleaks(fake, text), false);
    } else {
      await assert.rejects(runGitleaks(fake, text), /gitleaks/);
    }
  }
  await assert.rejects(runGitleaks(join(dir, 'absent'), 'text'), /gitleaks/);
});

test('a gitleaks run past the timeout fails the check instead of hanging the call', async () => {
  const started = Date.now();
  await assert.rejects(runGitleaks(fake, 'FAKESLOW', 200), /timed out/);
  assert.ok(Date.now() - started < 3000);
});

test('a gitleaks failure follows the group mode and the block reason never holds the text', async () => {
  const config = (mode: string) => resolveConfig({ groups: { secrets: { mode, gitleaks: { binary: fake } } } });
  const failing = send('FAKEFAIL Cadderly');
  const blocked = await decide(failing, {}, config('block'));
  assert.ok(blocked && 'block' in blocked);
  assert.match(blocked.blockReason, /could not be checked by the secrets group/);
  assert.doesNotMatch(blocked.blockReason, /Cadderly|FAKEFAIL/);
  assert.ok((await decide(failing, {}, config('approve')) ?? {}).hasOwnProperty('requireApproval'));
  assert.equal(await decide(failing, {}, config('off')), undefined);
  const logs: string[] = [];
  assert.equal(await decide(failing, {}, config('warn'), (line) => logs.push(line)), undefined);
  assert.deepEqual(logs, ['leak-guard: warn: secrets check failed in text for helper']);
});

test('a gitleaks finding blocks naming the group and kind only', async () => {
  const config = resolveConfig({ groups: { secrets: { gitleaks: { binary: fake } } } });
  const result = await decide(send('FAKELEAK for Danica'), {}, config);
  assert.ok(result && 'block' in result);
  assert.match(result.blockReason, /a credential or token \(secrets\)/);
  assert.doesNotMatch(result.blockReason, /aws-access-token|FAKELEAK|Danica/);
});

test('resolveConfig reads groups.secrets.gitleaks.binary and ignores anything that is not a non-empty string', () => {
  assert.equal(resolveConfig({ groups: { secrets: { gitleaks: { binary: fake } } } }).groups.secrets.gitleaks, fake);
  for (const binary of ['', 5, null, {}]) {
    assert.equal(resolveConfig({ groups: { secrets: { gitleaks: { binary } } } }).groups.secrets.gitleaks, undefined);
  }
  assert.equal(resolveConfig({ groups: { secrets: { gitleaks: 'x' } } }).groups.secrets.gitleaks, undefined);
  assert.equal(resolveConfig(undefined).groups.secrets.gitleaks, undefined);
});

function api(pluginConfig: unknown, warnings: string[]): HookApi {
  return { pluginConfig, logger: { warn: (line) => warnings.push(line) }, on: () => {} };
}

test('register warns once and keeps secretlint when the gitleaks binary is unset or not executable', async () => {
  for (const pluginConfig of [undefined, { groups: { secrets: { gitleaks: { binary: join(dir, 'absent') } } } }]) {
    const warnings: string[] = [];
    register(api(pluginConfig, warnings));
    assert.equal(warnings.length, 1);
    assert.match(warnings[0] ?? '', /gitleaks/);
    assert.doesNotMatch(warnings[0] ?? '', new RegExp(dir));
  }
  const ghp = ['gh', 'p_', 'a'.repeat(36)].join('');
  assert.ok((await decide(send(`token ${ghp}`), {}, resolveConfig(undefined)) ?? {}).hasOwnProperty('block'));
});

test('register does not warn when the binary is set and executable, or the secrets group is off', () => {
  for (const pluginConfig of [
    { groups: { secrets: { gitleaks: { binary: fake } } } },
    { groups: { secrets: { mode: 'off' } } },
  ]) {
    const warnings: string[] = [];
    register(api(pluginConfig, warnings));
    assert.deepEqual(warnings, []);
  }
});

test('the manifest declares groups.secrets.gitleaks.binary', async () => {
  const manifest = JSON.parse(await readFile(new URL('../openclaw.plugin.json', import.meta.url), 'utf8'));
  const binary = manifest.configSchema.properties.groups.properties.secrets.properties.gitleaks.properties.binary;
  assert.equal(binary.type, 'string');
  assert.equal(manifest.configSchema.properties.groups.properties.secrets.properties.gitleaks.additionalProperties, false);
});

test('the pinned config extends the defaults and disables generic-api-key', async () => {
  const text = await readFile(GITLEAKS_CONFIG, 'utf8');
  assert.match(text, /useDefault\s*=\s*true/);
  assert.match(text, /disabledRules\s*=\s*\["generic-api-key"\]/);
  assert.match(GITLEAKS_VERSION, /^\d+\.\d+\.\d+$/);
});

// Runs only against a real binary: GITLEAKS_BIN, or gitleaks on PATH at the pinned version.
function realBinary(): string | undefined {
  const candidate = process.env.GITLEAKS_BIN ?? 'gitleaks';
  const probe = spawnSync(candidate, ['version'], { encoding: 'utf8' });
  return probe.status === 0 && probe.stdout.trim() === GITLEAKS_VERSION ? candidate : undefined;
}
const real = realBinary();

test('real gitleaks: finds a provider token, passes plain and generic text, ignores an inline allow', { skip: !real }, async () => {
  const awsKey = ['AKIA', 'IOSFODNN7', 'ABCDEFG'].join('');
  assert.equal(await runGitleaks(real ?? '', `key ${awsKey}`), true);
  assert.equal(await runGitleaks(real ?? '', `key ${awsKey} # gitleaks:allow`), true);
  assert.equal(await runGitleaks(real ?? '', 'papers on sparse attention, Cadderly 2026'), false);
  assert.equal(await runGitleaks(real ?? '', 'api_key = "a8f3k2j5h6g7d9s0a1q2w3e4r5t6y7u8"'), false);
});
