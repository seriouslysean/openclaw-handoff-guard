import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { outboundText } from '../src/rules.ts';

test('other tools are not agent text, channel posts included', () => {
  assert.equal(outboundText('read', { path: 'notes.md' }, 'main'), undefined);
  assert.equal(outboundText('message', { action: 'send', message: 'hi' }, 'main'), undefined);
});

test('sessions_send names its target by agentId or by an agent session key, and a label stays unknown', () => {
  assert.deepEqual(outboundText('sessions_send', { agentId: 'helper', message: 'm' }, 'main'), { target: 'helper', text: 'm' });
  assert.deepEqual(outboundText('sessions_send', { sessionKey: ['agent', 'helper', 'main'].join(':'), message: 'm' }, 'main'), {
    target: 'helper',
    text: 'm',
  });
  assert.deepEqual(outboundText('sessions_send', { label: 'helper', message: 'm' }, 'main'), { target: undefined, text: 'm' });
  assert.deepEqual(outboundText('sessions_send', { sessionKey: 'main', message: 'm' }, 'main'), { target: undefined, text: 'm' });
});

test('sessions_spawn runs under the requester unless agentId says otherwise, and its label is checked too', () => {
  assert.deepEqual(outboundText('sessions_spawn', { task: 't' }, 'main'), { target: 'main', text: 't' });
  assert.deepEqual(outboundText('sessions_spawn', { task: 't', agentId: 'helper', label: 'l' }, 'main'), {
    target: 'helper',
    text: 'l\nt',
  });
  assert.deepEqual(outboundText('sessions_spawn', { task: 't', agentId: '' }, 'main'), { target: undefined, text: 't' });
  assert.deepEqual(outboundText('sessions_spawn', { task: 't' }, undefined), { target: undefined, text: 't' });
});

test('unreadable agent text is null, so it can be blocked', () => {
  for (const [tool, params] of [
    ['sessions_send', undefined],
    ['sessions_send', 'text'],
    ['sessions_send', { agentId: 'helper' }],
    ['sessions_send', { message: ['m'] }],
    ['sessions_spawn', {}],
    ['sessions_spawn', { task: 't', label: 3 }],
  ] as const) {
    assert.equal(outboundText(tool, params, 'main'), null, `${tool} ${JSON.stringify(params)}`);
  }
});
