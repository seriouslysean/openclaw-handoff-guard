/**
 * The tool calls that hand text to another agent (OpenClaw 2026.10.5, docs tools/subagents/tool-reference.md and
 * concepts/session-tool.md): `sessions_send` runs another session with `message`, and `sessions_spawn` starts a child
 * run with `task` and an optional `label`. Channel posts (`message`) reach people, not agents, and are out of scope.
 */
export const AGENT_TEXT_TOOLS: ReadonlySet<string> = new Set(['sessions_send', 'sessions_spawn']);

export interface OutboundText {
  /** The receiving agent's id, or undefined when the call names it only by a label or session the guard can't map. */
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

/**
 * The text a call hands to another agent and who receives it: undefined for any other tool, and null for an agent
 * text call whose text can't be read, which the guard blocks.
 */
export function outboundText(toolName: string, params: unknown, requester: string | undefined): OutboundText | null | undefined {
  if (!AGENT_TEXT_TOOLS.has(toolName)) {
    return undefined;
  }
  if (!isRecord(params)) {
    return null;
  }
  if (toolName === 'sessions_send') {
    const message = params.message;
    if (typeof message !== 'string') {
      return null;
    }
    return { target: nonEmpty(params.agentId) ?? agentOfSessionKey(params.sessionKey), text: message };
  }
  const task = params.task;
  if (typeof task !== 'string' || (params.label !== undefined && typeof params.label !== 'string')) {
    return null;
  }
  // A spawn without agentId runs under the requester's own agent (tool-reference.md, `agentId`).
  const target = params.agentId === undefined ? requester : nonEmpty(params.agentId);
  return { target, text: typeof params.label === 'string' ? `${params.label}\n${task}` : task };
}
