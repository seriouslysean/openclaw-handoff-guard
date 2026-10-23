/**
 * Nothing published here may identify a user's setup: no home paths, addresses, chat ids or session keys. Prose is
 * the usual leak, so every text file in the repository is scanned, committed or not. Fixtures need addresses and ids,
 * so the reserved example domains (RFC 2606: example.org/.com/.net, .invalid, .test) are allowed.
 */
import { strict as assert } from 'node:assert';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { test } from 'node:test';

const ROOT = join(import.meta.dirname, '..');
const SKIP = new Set(['.git', 'node_modules', 'dist']);

const RESERVED = String.raw`(?!(?:[a-z0-9-]+\.)*(?:example\.(?:org|com|net)|[a-z0-9-]+\.(?:invalid|test))\b)`;
const DOMAIN = String.raw`${RESERVED}[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`;

const SHAPES: [string, RegExp][] = [
  ['home path', /(?:\/Users|\/home)\/[A-Za-z0-9._-]+\/|[A-Z]:\\Users\\/],
  ['email address', new RegExp(`[A-Za-z0-9._%+-]+@(?!users\\.noreply\\.github\\.com\\b)${DOMAIN}`)],
  ['Matrix id', new RegExp(`[!@#][A-Za-z0-9._=-]{6,}:${DOMAIN}`)],
  ['OpenClaw session key', /\bagent:[a-z0-9_-]+:(?:main|explicit|thread|group|direct|subagent|cron)\b/],
  ['agent session link', /claude\.ai\/code\/session|chatgpt\.com\/codex\/tasks/],
];

export function findLeaks(text: string): string[] {
  const found: string[] = [];
  for (const [name, shape] of SHAPES) {
    const match = shape.exec(text);
    if (match) {
      found.push(`${name}: ${match[0]}`);
    }
  }
  return found;
}

async function files(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) {
      continue;
    }
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await files(path)));
    } else if (entry.isFile()) {
      out.push(path);
    }
  }
  return out;
}

test('the scan catches each shape it claims to', () => {
  // Built from parts so this file doesn't trip its own scan.
  const samples = [
    ['/Us', 'ers/someone/project'],
    ['someone', '@', 'mail.someco.io'],
    ['!AbCdEf123456', ':', 'matrix.org'],
    ['@someone123', ':', 'example.organic.io'],
    ['agent:', 'helper:', 'main'],
    ['https://claude.ai/code/', 'session/abc'],
  ].map((parts) => parts.join(''));
  for (const sample of samples) {
    assert.equal(findLeaks(sample).length, 1, sample);
  }
  assert.deepEqual(findLeaks(['bot', '@', 'users.noreply.github.com'].join('')), []);
  assert.deepEqual(findLeaks('someone@example.org, @someone:example.org, x@host.invalid, x@mail.example.com'), []);
  assert.deepEqual(findLeaks('https://docs.openclaw.ai/plugins and plugins.entries.leak-guard.config'), []);
});

test('no file in the repository identifies a setup', async () => {
  const problems: string[] = [];
  for (const path of await files(ROOT)) {
    const text = await readFile(path, 'utf8');
    for (const leak of findLeaks(text)) {
      problems.push(`${relative(ROOT, path)}: ${leak}`);
    }
  }
  assert.deepEqual(problems, []);
});
