/**
 * The tool calls that hand text to another agent (OpenClaw 2026.10.5, docs tools/subagents/tool-reference.md and
 * concepts/session-tool.md): `sessions_send` runs another session with `message`, and `sessions_spawn` starts a child
 * run with `task`, a `label`, attachments and an output schema. Channel posts (`message`) reach people, not agents,
 * and are out of scope.
 */
export const AGENT_TEXT_TOOLS: ReadonlySet<string> = new Set(['sessions_send', 'sessions_spawn']);

/**
 * Parameters that pick where or how a call runs rather than carry text for the receiver. Every other string, nested
 * or not, is checked, so a field added by an upgrade is checked until it is listed here. Session keys and git URLs are
 * here because they can hold a room id or an `@host:` form that isn't personal data.
 */
const SELECTORS: Record<string, ReadonlySet<string>> = {
  sessions_send: new Set(['sessionKey', 'label', 'agentId', 'mode', 'watch', 'timeoutSeconds']),
  sessions_spawn: new Set([
    'agentId',
    'taskName',
    'runtime',
    'resumeSessionId',
    'streamTo',
    'model',
    'thinking',
    'mode',
    'cleanup',
    'completionTarget',
    'context',
    'projectId',
    'projectGitUrl',
    'encoding',
    'mimeType',
  ]),
};

export interface OutboundText {
  /** The receiving agent's id, or undefined when the call names it in a way the guard can't map. */
  target: string | undefined;
  text: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonEmpty(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/** The agent id inside an `agent:<id>:...` session key. */
function agentOfSessionKey(value: unknown): string | undefined {
  const match = typeof value === 'string' ? /^agent:([^:]+):/.exec(value) : null;
  return match?.[1];
}

/** `openclaw:core:sessions_send`, `Sessions_Send ` and `sessions_send` are the same tool. */
export function canonicalTool(toolName: string): string {
  return toolName.trim().toLowerCase().split(':').at(-1) ?? '';
}

/** Every string under value, skipping selector keys; a base64 attachment is checked raw and decoded. */
function collect(value: unknown, skip: ReadonlySet<string>, out: string[]): void {
  if (typeof value === 'string') {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) {
      collect(item, skip, out);
    }
  } else if (isRecord(value)) {
    if (value.encoding === 'base64' && typeof value.content === 'string') {
      out.push(Buffer.from(value.content, 'base64').toString('utf8'));
    }
    for (const [key, item] of Object.entries(value)) {
      if (!skip.has(key)) {
        collect(item, skip, out);
      }
    }
  }
}

/**
 * Who receives a `sessions_send`: OpenClaw uses `agentId` only when neither `sessionKey` nor `label` is given
 * (dist sessions-spawn-tool, sessions_send target resolution, 2026.10.5). A session key that isn't `agent:<id>:...`
 * and any label lookup are unknown, so they are checked.
 */
function sendTarget(params: Record<string, unknown>): string | undefined {
  if (params.sessionKey !== undefined) {
    return agentOfSessionKey(params.sessionKey);
  }
  if (params.label !== undefined) {
    return undefined;
  }
  return nonEmpty(params.agentId);
}

/** A spawn without agentId runs under the requester's own agent (tool-reference.md, `agentId`). */
function spawnTarget(params: Record<string, unknown>, requester: string | undefined): string | undefined {
  return params.agentId == null ? requester : nonEmpty(params.agentId);
}

/**
 * The text a call hands to another agent and who receives it: undefined for any other tool, and null for an agent
 * text call whose text can't be read, which the guard blocks.
 */
export function outboundText(toolName: string, params: unknown, requester: string | undefined): OutboundText | null | undefined {
  const tool = canonicalTool(toolName);
  const skip = SELECTORS[tool];
  if (!AGENT_TEXT_TOOLS.has(tool) || !skip) {
    return undefined;
  }
  if (!isRecord(params)) {
    return null;
  }
  const required = tool === 'sessions_send' ? params.message : params.task;
  if (typeof required !== 'string') {
    return null;
  }
  if (tool === 'sessions_spawn') {
    if (params.label != null && typeof params.label !== 'string') {
      return null;
    }
    if (params.attachments != null && (!Array.isArray(params.attachments) || !params.attachments.every(isRecord))) {
      return null;
    }
  }
  const strings: string[] = [];
  collect(params, skip, strings);
  const target = tool === 'sessions_send' ? sendTarget(params) : spawnTarget(params, requester);
  return { target, text: strings.join('\n') };
}
