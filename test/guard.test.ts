import { strict as assert } from 'node:assert';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { DEFAULT_KINDS, GROUPS, findPersonalData, resetEngine } from '../src/detect.ts';
import { type HookApi, MODES, PLUGIN_ID, UNREADABLE_REASON, decide, register, resolveConfig } from '../src/guard.ts';

const email = { toolName: 'sessions_send', params: { agentId: 'helper', message: 'mail someone@example.org' } };

const SECRETS_DEFAULT = ['matrix-token', 'credential'];
const STRUCTURED_DEFAULT = DEFAULT_KINDS.filter((kind) => !SECRETS_DEFAULT.includes(kind));
const credentialText = ['gh', 'p_', 'a'.repeat(36)].join('');
const credential = { toolName: 'sessions_send', params: { agentId: 'helper', message: `token ${credentialText}` } };
const matrixToken = ['syt', 'Y2FkZGVybHk', 'GuenhwyvarIcingdaleS', '066Dhg'].join('_');
const matrix = { toolName: 'sessions_send', params: { agentId: 'helper', message: `access_token: ${matrixToken}` } };
const clean = { toolName: 'sessions_send', params: { agentId: 'helper', message: 'papers on sparse attention' } };
const main = { agentId: 'main' };
const blocks = (result: unknown) => typeof result === 'object' && result !== null && 'block' in result;

test('with no config, secrets and structured-pii block, contextual-pii warns, and no target is exempt', () => {
  const expected = {
    groups: {
      secrets: { mode: 'block', kinds: SECRETS_DEFAULT },
      'structured-pii': { mode: 'block', kinds: STRUCTURED_DEFAULT },
      'contextual-pii': { mode: 'warn', kinds: [] },
    },
    targets: {},
  };
  assert.deepEqual(resolveConfig(undefined), expected);
  assert.deepEqual(resolveConfig({ allowTargets: 'helper', groups: 'all' }), expected);
  assert.equal(STRUCTURED_DEFAULT.some((kind) => kind === 'ip-address'), false);
});

test('an unknown group, mode or kind falls back to that group default, so a typo never turns checking off', () => {
  const config = resolveConfig({
    groups: {
      secrets: { mode: 'allow', kinds: ['email'] },
      'structured-pii': { mode: 'approve', kinds: ['email', 'ip-address', 'email', 'nickname', 'credential'] },
      'contextual-pii': { mode: 'loud' },
      nonsense: { mode: 'off' },
    },
  });
  assert.deepEqual(config.groups.secrets, { mode: 'block', kinds: SECRETS_DEFAULT });
  assert.deepEqual(config.groups['structured-pii'], { mode: 'approve', kinds: ['email', 'ip-address'] });
  assert.equal(config.groups['contextual-pii'].mode, 'warn');
  assert.deepEqual(resolveConfig({ groups: { 'structured-pii': { kinds: [] } } }).groups['structured-pii'].kinds, STRUCTURED_DEFAULT);
});

test('per-target overrides set a mode per group; unknown groups and modes in them are ignored', () => {
  const config = resolveConfig({
    groups: { 'structured-pii': { mode: 'approve' } },
    targets: { helper: { 'structured-pii': 'off', secrets: 'sometimes', nonsense: 'off' }, '': { secrets: 'off' }, bad: 'off' },
  });
  assert.deepEqual(config.targets, { helper: { 'structured-pii': 'off' } });
});

test('deprecated allowTargets turns every group off for the listed targets, and an explicit override wins', () => {
  const config = resolveConfig({ allowTargets: ['helper', '', 3, 'other'], targets: { other: { secrets: 'block' } } });
  assert.deepEqual(config.targets.helper, { secrets: 'off', 'structured-pii': 'off', 'contextual-pii': 'off' });
  assert.deepEqual(config.targets.other, { secrets: 'block' });
});

test('deprecated top-level kinds are split into the groups, and an empty result never means "check nothing"', () => {
  const split = resolveConfig({ kinds: ['email', 'ip-address', 'email', 'nickname'] });
  assert.deepEqual(split.groups['structured-pii'].kinds, ['email', 'ip-address']);
  assert.deepEqual(split.groups.secrets.kinds, []);
  const both = resolveConfig({ kinds: ['email', 'credential'] });
  assert.deepEqual(both.groups.secrets.kinds, ['credential']);
  assert.deepEqual(resolveConfig({ kinds: ['nickname'] }).groups.secrets.kinds, SECRETS_DEFAULT);
  assert.deepEqual(resolveConfig({ kinds: [] }).groups['structured-pii'].kinds, STRUCTURED_DEFAULT);
  const explicit = resolveConfig({ kinds: ['email'], groups: { secrets: { kinds: ['credential'] } } });
  assert.deepEqual(explicit.groups.secrets.kinds, ['credential']);
});

test('personal data to an agent is blocked, and the reason names the group and kind but never the value', async () => {
  const result = await decide(email, main, resolveConfig({}));
  assert.ok(result && 'block' in result);
  assert.match(result.blockReason, /helper contains an email address/);
  assert.match(result.blockReason, /structured-pii/);
  assert.doesNotMatch(result.blockReason, /example\.org/);
});

test('a secret is blocked in its own group and named as such', async () => {
  const result = await decide(credential, main, resolveConfig({}));
  assert.ok(result && 'block' in result);
  assert.match(result.blockReason, /secrets/);
  assert.match(result.blockReason, /credential or token/);
  assert.doesNotMatch(result.blockReason, new RegExp(credentialText));
});

test('a Matrix token is blocked by default through the secrets group, and passes when secrets is off', async () => {
  const result = await decide(matrix, main, resolveConfig({}));
  assert.ok(result && 'block' in result);
  assert.match(result.blockReason, /\(secrets\)/);
  assert.match(result.blockReason, /Matrix access, refresh or login token/);
  assert.doesNotMatch(result.blockReason, new RegExp(matrixToken));
  assert.equal(await decide(matrix, main, resolveConfig({ groups: { secrets: { mode: 'off' } } })), undefined);
  assert.equal(await decide(matrix, main, resolveConfig({ groups: { secrets: { kinds: ['credential'] } } })), undefined);
});

test('only a known target with an override is exempt; a label or an unmapped session is checked', async () => {
  const config = resolveConfig({ targets: { helper: { 'structured-pii': 'off' } } });
  assert.equal(await decide(email, main, config), undefined);
  const byLabel = { toolName: 'sessions_send', params: { label: 'helper', message: 'mail someone@example.org' } };
  const blocked = await decide(byLabel, main, config);
  assert.ok(blocked && 'block' in blocked);
  const unmapped = await decide(byLabel, {}, config);
  assert.ok(unmapped && 'block' in unmapped && /another agent/.test(unmapped.blockReason));
});

test('an override can exempt one group and keep another on', async () => {
  const config = resolveConfig({ targets: { helper: { 'structured-pii': 'off' } } });
  assert.equal(await decide(email, main, config), undefined);
  const result = await decide(credential, main, config);
  assert.ok(result && 'block' in result);
});

test("a spawn under the requester's own agent is exempt only when that agent has an override", async () => {
  const spawn = { toolName: 'sessions_spawn', params: { task: 'call (555) 010-0199' } };
  assert.ok(blocks(await decide(spawn, main, resolveConfig({}))));
  assert.equal(await decide(spawn, main, resolveConfig({ allowTargets: ['main'] })), undefined);
  assert.equal(await decide(spawn, main, resolveConfig({ targets: { main: { 'structured-pii': 'off' } } })), undefined);
  assert.ok(blocks(await decide(spawn, undefined, resolveConfig({ allowTargets: ['main'] }))));
});

test('approve mode asks, with allow-once and deny only, a bounded text, and never the value', async () => {
  const config = resolveConfig({ groups: { 'structured-pii': { mode: 'approve' } } });
  const result = await decide(email, main, config);
  assert.ok(result && 'requireApproval' in result);
  const ask = result.requireApproval;
  assert.deepEqual(ask.allowedDecisions, ['allow-once', 'deny']);
  assert.ok(ask.title.length <= 80 && ask.description.length <= 512);
  assert.match(ask.description, /email address/);
  assert.match(ask.description, /structured-pii/);
  assert.doesNotMatch(`${ask.title} ${ask.description}`, /example\.org/);
  assert.ok(ask.timeoutMs !== undefined && ask.timeoutMs <= 600_000);
});

test('warn mode lets the call through and logs the group and kind, never the value', async () => {
  const lines: string[] = [];
  const config = resolveConfig({ groups: { 'structured-pii': { mode: 'warn' } } });
  assert.equal(await decide(email, main, config, (line) => lines.push(line)), undefined);
  assert.equal(lines.length, 1);
  assert.match(lines[0] ?? '', /structured-pii/);
  assert.match(lines[0] ?? '', /email/);
  assert.doesNotMatch(lines[0] ?? '', /example\.org/);
});

test('off mode does not run the group', async () => {
  const lines: string[] = [];
  const config = resolveConfig({ groups: { 'structured-pii': { mode: 'off' } } });
  assert.equal(await decide(email, main, config, (line) => lines.push(line)), undefined);
  assert.deepEqual(lines, []);
});

test('the strictest result wins: block over approve over warn', async () => {
  const both = { toolName: 'sessions_send', params: { agentId: 'helper', message: `mail someone@example.org ${credentialText}` } };
  const one = async (secrets: string, structured: string) =>
    decide(both, main, resolveConfig({ groups: { secrets: { mode: secrets }, 'structured-pii': { mode: structured } } }), () => {});
  const blocked = await one('approve', 'block');
  assert.ok(blocked && 'block' in blocked);
  const asked = await one('warn', 'approve');
  assert.ok(asked && 'requireApproval' in asked);
  assert.equal(await one('warn', 'warn'), undefined);
});

test('a detector failure follows its group mode', async () => {
  resetEngine(() => Promise.reject(new Error('start failed')));
  try {
    const failing = (mode: string) => decide(clean, main, resolveConfig({ groups: { secrets: { mode } } }), (line) => lines.push(line));
    const lines: string[] = [];
    const blocked = await failing('block');
    assert.ok(blocked && 'block' in blocked && /could not be checked/.test(blocked.blockReason));
    const asked = await failing('approve');
    assert.ok(asked && 'requireApproval' in asked);
    assert.equal(await failing('warn'), undefined);
    assert.match(lines.at(-1) ?? '', /secrets/);
    assert.doesNotMatch(lines.at(-1) ?? '', /start failed/);
    assert.equal(await failing('off'), undefined);
  } finally {
    resetEngine();
  }
});

test('unreadable parameters block whatever the modes and overrides are', async () => {
  const off = resolveConfig({
    groups: { secrets: { mode: 'off' }, 'structured-pii': { mode: 'off' }, 'contextual-pii': { mode: 'off' } },
    allowTargets: ['main'],
  });
  assert.deepEqual(await decide({ toolName: 'sessions_send', params: {} }, main, off), { block: true, blockReason: UNREADABLE_REASON });
});

test('clean text and other tools pass; unreadable agent text is blocked', async () => {
  const config = resolveConfig({});
  assert.equal(await decide(clean, { agentId: 'main' }, config), undefined);
  assert.equal(await decide({ toolName: 'read', params: { path: 'someone@example.org' } }, {}, config), undefined);
  assert.deepEqual(await decide({ toolName: 'sessions_send', params: {} }, {}, config), {
    block: true,
    blockReason: UNREADABLE_REASON,
  });
});

test('register adds one before_tool_call handler that uses the plugin config and logs warnings', async () => {
  const calls: { name: string; handler: Parameters<HookApi['on']>[1]; priority: number }[] = [];
  const warnings: string[] = [];
  const api: HookApi = {
    pluginConfig: { targets: { helper: { 'structured-pii': 'off' } }, groups: { secrets: { mode: 'warn' } } },
    logger: { warn: (line) => warnings.push(line) },
    on: (name, handler, options) => calls.push({ name, handler, priority: options.priority }),
  };
  register(api);
  assert.equal(calls.length, 1);
  const [call] = calls;
  assert.equal(call?.name, 'before_tool_call');
  assert.equal(call?.priority, 90);
  assert.equal(await call?.handler(email, main), undefined);
  const other = { toolName: 'sessions_send', params: { agentId: 'other', message: 'mail someone@example.org' } };
  assert.ok(blocks(await call?.handler(other, main)));
  assert.equal(await call?.handler(credential, main), undefined);
  const logged = warnings.filter((line) => !line.includes('gitleaks skipped'));
  assert.equal(logged.length, 1);
  assert.doesNotMatch(logged[0] ?? '', new RegExp(credentialText));
});

test('register works without a logger', async () => {
  let handler: Parameters<HookApi['on']>[1] | undefined;
  register({ pluginConfig: { groups: { secrets: { mode: 'warn' } } }, on: (_name, fn) => (handler = fn) });
  assert.equal(await handler?.(credential, main), undefined);
});

test('the manifest id, groups, modes and kinds match the code', async () => {
  const manifest: unknown = JSON.parse(await readFile(new URL('../openclaw.plugin.json', import.meta.url), 'utf8'));
  assert.ok(typeof manifest === 'object' && manifest !== null && 'id' in manifest);
  assert.equal(manifest.id, PLUGIN_ID);
  assert.equal(PLUGIN_ID, 'leak-guard');
  const text = JSON.stringify(manifest);
  const { KINDS } = await import('../src/detect.ts');
  assert.match(text, new RegExp(JSON.stringify(KINDS).replaceAll(/[[\]]/g, '\\$&')));
  assert.match(text, new RegExp(JSON.stringify(MODES).replaceAll(/[[\]]/g, '\\$&')));
  for (const group of GROUPS) {
    assert.ok(text.includes(`"${group}"`), group);
  }
  const enums = [...text.matchAll(/"kinds":\{"type":"array","items":\{"type":"string","enum":(\[[^\]]*\])/g)];
  assert.equal(enums.length, 4);
  for (const [, list] of enums) {
    assert.equal(list, JSON.stringify(KINDS));
  }
});

test('an engine that failed to start is not cached, so one failure does not block every later call', async () => {
  let starts = 0;
  const real = (await import('@secretlint/node')).createEngine;
  resetEngine(() => {
    starts += 1;
    return starts === 1
      ? Promise.reject(new Error('start failed'))
      : real({ formatter: 'json', configFileJSON: { rules: [{ id: '@secretlint/secretlint-rule-preset-recommend' }] } });
  });
  try {
    await assert.rejects(findPersonalData('plain text', ['credential']), /start failed/);
    assert.equal(await findPersonalData('plain text', ['credential']), undefined);
    assert.equal(starts, 2);
  } finally {
    resetEngine();
  }
});
