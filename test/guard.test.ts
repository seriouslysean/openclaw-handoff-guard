import { strict as assert } from 'node:assert';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { DEFAULT_KINDS } from '../src/detect.ts';
import { type HookApi, PLUGIN_ID, UNREADABLE_REASON, decide, register, resolveConfig } from '../src/guard.ts';

const email = { toolName: 'sessions_send', params: { agentId: 'helper', message: 'mail someone@example.org' } };

test('with no config, text to every agent is checked for the default kinds', () => {
  assert.deepEqual(resolveConfig(undefined), { allowTargets: [], kinds: [...DEFAULT_KINDS] });
  assert.deepEqual(resolveConfig({ allowTargets: 'helper' }), { allowTargets: [], kinds: [...DEFAULT_KINDS] });
  assert.deepEqual(resolveConfig({ allowTargets: ['helper', '', 3] }).allowTargets, ['helper']);
});

test('kinds replace the default, unknown names are dropped, and an empty result never means "check nothing"', () => {
  assert.deepEqual(resolveConfig({ kinds: ['email', 'ip-address', 'email', 'nickname'] }).kinds, ['email', 'ip-address']);
  assert.deepEqual(resolveConfig({ kinds: ['nickname'] }).kinds, [...DEFAULT_KINDS]);
  assert.deepEqual(resolveConfig({ kinds: [] }).kinds, [...DEFAULT_KINDS]);
});

test('personal data to an agent is blocked, and the reason names the kind but never the value', async () => {
  const result = await decide(email, { agentId: 'main' }, resolveConfig({}));
  assert.equal(result?.block, true);
  assert.match(result?.blockReason ?? '', /helper contains an email address/);
  assert.doesNotMatch(result?.blockReason ?? '', /example\.org/);
});

test('only a known, listed target is exempt; a label or an unmapped session is checked', async () => {
  const config = resolveConfig({ allowTargets: ['helper'] });
  assert.equal(await decide(email, { agentId: 'main' }, config), undefined);
  const byLabel = { toolName: 'sessions_send', params: { label: 'helper', message: 'mail someone@example.org' } };
  assert.equal((await decide(byLabel, { agentId: 'main' }, config))?.block, true);
  assert.match((await decide(byLabel, {}, config))?.blockReason ?? '', /another agent/);
});

test("a spawn under the requester's own agent is exempt only when that agent is listed", async () => {
  const spawn = { toolName: 'sessions_spawn', params: { task: 'call (555) 010-0199' } };
  assert.equal((await decide(spawn, { agentId: 'main' }, resolveConfig({})))?.block, true);
  assert.equal(await decide(spawn, { agentId: 'main' }, resolveConfig({ allowTargets: ['main'] })), undefined);
  assert.equal((await decide(spawn, undefined, resolveConfig({ allowTargets: ['main'] })))?.block, true);
});

test('clean text and other tools pass; unreadable agent text is blocked', async () => {
  const config = resolveConfig({});
  const clean = { toolName: 'sessions_send', params: { agentId: 'helper', message: 'papers on sparse attention' } };
  assert.equal(await decide(clean, { agentId: 'main' }, config), undefined);
  assert.equal(await decide({ toolName: 'read', params: { path: 'someone@example.org' } }, {}, config), undefined);
  assert.deepEqual(await decide({ toolName: 'sessions_send', params: {} }, {}, config), {
    block: true,
    blockReason: UNREADABLE_REASON,
  });
});

test('register adds one before_tool_call handler that uses the plugin config', async () => {
  const calls: { name: string; handler: Parameters<HookApi['on']>[1]; priority: number }[] = [];
  const api: HookApi = {
    pluginConfig: { allowTargets: ['helper'] },
    on: (name, handler, options) => calls.push({ name, handler, priority: options.priority }),
  };
  register(api);
  assert.equal(calls.length, 1);
  const [call] = calls;
  assert.equal(call?.name, 'before_tool_call');
  assert.equal(call?.priority, 90);
  assert.equal(await call?.handler(email, { agentId: 'main' }), undefined);
  const other = { toolName: 'sessions_send', params: { agentId: 'other', message: 'mail someone@example.org' } };
  assert.equal((await call?.handler(other, { agentId: 'main' }))?.block, true);
});

test('the manifest id and kinds match the code', async () => {
  const manifest: unknown = JSON.parse(await readFile(new URL('../openclaw.plugin.json', import.meta.url), 'utf8'));
  assert.ok(typeof manifest === 'object' && manifest !== null && 'id' in manifest);
  assert.equal(manifest.id, PLUGIN_ID);
  const { KINDS } = await import('../src/detect.ts');
  assert.match(JSON.stringify(manifest), new RegExp(JSON.stringify(KINDS).replaceAll(/[[\]]/g, '\\$&')));
});
