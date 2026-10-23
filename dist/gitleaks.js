import { spawn } from 'node:child_process';
/** The gitleaks release the config and the tests were checked against (docs/how-it-works.md). */
export const GITLEAKS_VERSION = '8.30.1';
export const GITLEAKS_CONFIG = new URL('../config/gitleaks.toml', import.meta.url).pathname;
/** The handler has 15 s in all (plugins/hooks/reference.md, 2026.10.5), and secretlint runs first. */
const TIMEOUT_MS = 5_000;
/** A leak report is a few hundred bytes per finding; anything past this is not one. */
const MAX_REPORT_BYTES = 1_000_000;
/** A rule id is a short slug; the report's other fields, which hold the redacted match, are never read. */
function hasRuleId(report) {
    const parsed = JSON.parse(report);
    return (Array.isArray(parsed) &&
        parsed.some((item) => typeof item === 'object' && item !== null && 'RuleID' in item && typeof item.RuleID === 'string'));
}
/**
 * Runs `gitleaks stdin` as a separate process (gitleaks 8.30.1, README, "Usage" and "Exit Codes"). The text goes on
 * stdin, never argv or a file. `--exit-code 2` tells a leak (2) from an error (1, which gitleaks also uses for a leak
 * by default); `--redact` keeps the secret out of the report, `--ignore-gitleaks-allow` stops `gitleaks:allow` in the
 * text from suppressing a finding, and `GITLEAKS_*` variables are dropped so the environment can't swap the config.
 * Resolves true on a finding and false on none; any other outcome rejects, with a message that never holds the text.
 */
export function runGitleaks(binary, text, timeoutMs = TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
        const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('GITLEAKS_')));
        const child = spawn(binary, [
            'stdin',
            '--config',
            GITLEAKS_CONFIG,
            '--redact',
            '--exit-code',
            '2',
            '--ignore-gitleaks-allow',
            '--no-banner',
            '--log-level',
            'error',
            '--report-format',
            'json',
            '--report-path',
            '-',
        ], { stdio: ['pipe', 'pipe', 'ignore'], env });
        const chunks = [];
        let size = 0;
        let done = false;
        const finish = (error, found = false) => {
            if (!done) {
                done = true;
                clearTimeout(timer);
                child.kill('SIGKILL');
                if (error) {
                    reject(error);
                }
                else {
                    resolve(found);
                }
            }
        };
        // Not spawn's `timeout`: killing a wrapper script leaves a grandchild holding the pipe, so `close` never comes.
        const timer = setTimeout(() => finish(new Error('gitleaks timed out')), timeoutMs);
        child.stdout.on('data', (chunk) => {
            size += chunk.length;
            if (size <= MAX_REPORT_BYTES) {
                chunks.push(chunk);
            }
        });
        child.stdin.on('error', () => { });
        child.on('error', () => finish(new Error('gitleaks could not run')));
        child.on('close', (code, signal) => {
            if (signal) {
                finish(new Error('gitleaks was stopped'));
            }
            else if (code === 0) {
                finish(undefined, false);
            }
            else if (code === 2 && size <= MAX_REPORT_BYTES) {
                try {
                    finish(hasRuleId(Buffer.concat(chunks).toString('utf8')) ? undefined : new Error('gitleaks gave no rule id'), true);
                }
                catch {
                    finish(new Error('gitleaks gave an unreadable report'));
                }
            }
            else {
                finish(new Error(`gitleaks exited with ${code}`));
            }
        });
        child.stdin.end(text);
    });
}
