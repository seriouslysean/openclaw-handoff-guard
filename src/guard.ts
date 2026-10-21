import { DEFAULT_KINDS, KINDS, KIND_NAMES, type Kind, findPersonalData } from './detect.ts';
import { outboundText } from './rules.ts';

export const PLUGIN_ID = 'pii-guard';

export interface GuardConfig {
  allowTargets: string[];
  kinds: Kind[];
}

export interface ToolCallEvent {
  toolName: string;
  params?: unknown;
}

export interface ToolCallContext {
  agentId?: string;
}

export interface BlockResult {
  block: true;
  blockReason: string;
}

export const UNREADABLE_REASON = 'Blocked: the text for another agent could not be read, so it could not be checked.';

function isKind(value: unknown): value is Kind {
  return KINDS.some((kind) => kind === value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((id): id is string => typeof id === 'string' && id !== '') : [];
}

/**
 * Text to every agent is checked unless its id is in `allowTargets`. `kinds` replaces the default kinds; unknown
 * names are dropped, and a list with no known kind falls back to the default rather than checking nothing.
 */
export function resolveConfig(raw: unknown): GuardConfig {
  const value = typeof raw === 'object' && raw !== null ? raw : {};
  const kinds = 'kinds' in value && Array.isArray(value.kinds) ? value.kinds.filter(isKind) : [];
  return {
    allowTargets: strings('allowTargets' in value ? value.allowTargets : undefined),
    kinds: kinds.length > 0 ? [...new Set(kinds)] : [...DEFAULT_KINDS],
  };
}

/**
 * Only a known, listed target is exempt. A target named by a label or an unmapped session is checked: OpenClaw
 * documents missing context as unproven, not as "some other agent" (plugins/hooks/tool-policy.md, 2026.10.5).
 */
export async function decide(event: ToolCallEvent, ctx: ToolCallContext | undefined, config: GuardConfig): Promise<BlockResult | undefined> {
  const outbound = outboundText(event.toolName, event.params, ctx?.agentId);
  if (outbound === undefined) {
    return undefined;
  }
  if (outbound === null) {
    return { block: true, blockReason: UNREADABLE_REASON };
  }
  if (outbound.target && config.allowTargets.includes(outbound.target)) {
    return undefined;
  }
  const kind = await findPersonalData(outbound.text, config.kinds);
  if (!kind) {
    return undefined;
  }
  // The matched value is never echoed: the reason reaches the transcript and the logs.
  return {
    block: true,
    blockReason: `Blocked: this text for ${outbound.target ?? 'another agent'} contains ${KIND_NAMES[kind]}. Rephrase without it, or ask the owner.`,
  };
}

export interface HookApi {
  pluginConfig?: unknown;
  on(
    name: 'before_tool_call',
    handler: (event: ToolCallEvent, ctx?: ToolCallContext) => Promise<BlockResult | undefined>,
    options: { priority: number },
  ): void;
}

/**
 * Registers one `before_tool_call` handler. `{ block: true }` is terminal, and the host blocks the call when a handler
 * throws or exceeds its 15 s default (plugins/hooks/reference.md, "On thrown error or timeout", 2026.10.5), so a
 * detector that fails blocks rather than lets the text through.
 */
export function register(api: HookApi): void {
  const config = resolveConfig(api.pluginConfig);
  api.on('before_tool_call', (event, ctx) => decide(event, ctx, config), { priority: 90 });
}
