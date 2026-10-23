import { DEFAULT_GROUP_KINDS, GROUPS, GROUP_KINDS, KINDS, KIND_NAMES, type Group, type Kind, findPersonalData } from './detect.ts';
import { outboundText } from './rules.ts';

export const PLUGIN_ID = 'leak-guard';

/** What happens to a call whose text matches a group: block it, ask first, let it through and log, or skip the group. */
export const MODES = ['block', 'approve', 'warn', 'off'] as const;
export type Mode = (typeof MODES)[number];

const DEFAULT_MODES: Record<Group, Mode> = { secrets: 'block', 'structured-pii': 'block', 'contextual-pii': 'warn' };

export interface GroupConfig {
  mode: Mode;
  kinds: Kind[];
}

export interface GuardConfig {
  groups: Record<Group, GroupConfig>;
  /** Per receiving agent id: a mode that replaces the group's own. */
  targets: Record<string, Partial<Record<Group, Mode>>>;
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

export interface ApprovalResult {
  requireApproval: {
    title: string;
    description: string;
    severity: 'warning';
    timeoutMs: number;
    allowedDecisions: ['allow-once', 'deny'];
  };
}

export type Decision = BlockResult | ApprovalResult | undefined;

export const UNREADABLE_REASON = 'Blocked: the text for another agent could not be read, so it could not be checked.';

/** 2 minutes, the host's default. A timeout blocks the call (plugins/plugin-permission-requests.md, 2026.10.5). */
const APPROVAL_TIMEOUT_MS = 120_000;

function isKind(value: unknown): value is Kind {
  return KINDS.some((kind) => kind === value);
}

function isMode(value: unknown): value is Mode {
  return MODES.some((mode) => mode === value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((id): id is string => typeof id === 'string' && id !== '') : [];
}

/** The listed kinds that belong to the group, without repeats. */
function kindsOf(group: Group, value: unknown): Kind[] {
  const allowed = GROUP_KINDS[group];
  const listed = Array.isArray(value) ? value.filter(isKind).filter((kind) => allowed.includes(kind)) : [];
  return [...new Set(listed)];
}

/**
 * An unknown group, mode or kind falls back to that group's default, and a kinds list with no known kind falls back to
 * the default kinds rather than checking nothing. The deprecated top-level `kinds` is split into the groups: a group
 * with none of the listed kinds checks nothing, as the flat list did. The deprecated `allowTargets` becomes an override
 * that turns every group off for the listed ids; an explicit `targets` entry for the same id wins.
 */
export function resolveConfig(raw: unknown): GuardConfig {
  const value = isRecord(raw) ? raw : {};
  const groupsRaw = isRecord(value.groups) ? value.groups : {};
  const legacy = Array.isArray(value.kinds) ? value.kinds.filter(isKind) : [];
  const groupConfig = (group: Group): GroupConfig => {
    const entry = isRecord(groupsRaw[group]) ? groupsRaw[group] : {};
    const explicit = kindsOf(group, entry.kinds);
    const flat = legacy.length > 0 ? kindsOf(group, legacy) : undefined;
    return {
      mode: isMode(entry.mode) ? entry.mode : DEFAULT_MODES[group],
      kinds: explicit.length > 0 ? explicit : (flat ?? [...DEFAULT_GROUP_KINDS[group]]),
    };
  };
  const groups: Record<Group, GroupConfig> = {
    secrets: groupConfig('secrets'),
    'structured-pii': groupConfig('structured-pii'),
    'contextual-pii': groupConfig('contextual-pii'),
  };
  const targets: GuardConfig['targets'] = {};
  for (const id of strings(value.allowTargets)) {
    targets[id] = { secrets: 'off', 'structured-pii': 'off', 'contextual-pii': 'off' };
  }
  if (isRecord(value.targets)) {
    for (const [id, overrides] of Object.entries(value.targets)) {
      if (id === '' || !isRecord(overrides)) {
        continue;
      }
      const valid: Partial<Record<Group, Mode>> = {};
      for (const group of GROUPS) {
        const mode = overrides[group];
        if (isMode(mode)) {
          valid[group] = mode;
        }
      }
      targets[id] = valid;
    }
  }
  return { groups, targets };
}

interface Finding {
  mode: Exclude<Mode, 'off'>;
  group: Group;
  /** Undefined when the group's detector failed. */
  kind: Kind | undefined;
}

function describe(finding: Finding, target: string): string {
  return finding.kind
    ? `this text for ${target} contains ${KIND_NAMES[finding.kind]} (${finding.group})`
    : `this text for ${target} could not be checked by the ${finding.group} group`;
}

/**
 * Only a known target with an override gets a different mode. A target named by a label or an unmapped session is
 * checked with the group's own mode: OpenClaw documents missing context as unproven, not as "some other agent"
 * (plugins/hooks/tool-policy.md, 2026.10.5). A detector that throws is a finding in its group's mode; text that can't
 * be read is blocked whatever the modes are, since no group can check it. The strictest finding decides: block, then
 * approve; a warn only logs, and the log never holds the matched value.
 */
export async function decide(
  event: ToolCallEvent,
  ctx: ToolCallContext | undefined,
  config: GuardConfig,
  log: (line: string) => void = () => {},
): Promise<Decision> {
  const outbound = outboundText(event.toolName, event.params, ctx?.agentId);
  if (outbound === undefined) {
    return undefined;
  }
  if (outbound === null) {
    return { block: true, blockReason: UNREADABLE_REASON };
  }
  const target = outbound.target ?? 'another agent';
  const overrides = outbound.target ? config.targets[outbound.target] : undefined;
  const checked = await Promise.all(
    GROUPS.map(async (group): Promise<Finding | undefined> => {
      const mode = overrides?.[group] ?? config.groups[group].mode;
      const { kinds } = config.groups[group];
      if (mode === 'off' || kinds.length === 0) {
        return undefined;
      }
      try {
        const kind = await findPersonalData(outbound.text, kinds);
        return kind ? { mode, group, kind } : undefined;
      } catch {
        return { mode, group, kind: undefined };
      }
    }),
  );
  const findings = checked.filter((item) => item !== undefined);
  for (const finding of findings.filter((item) => item.mode === 'warn')) {
    log(`${PLUGIN_ID}: warn: ${finding.kind ? `${finding.group} ${finding.kind}` : `${finding.group} check failed`} in text for ${target}`);
  }
  const blocking = findings.find((item) => item.mode === 'block');
  if (blocking) {
    // The matched value is never echoed: the reason reaches the transcript and the logs.
    const reason = blocking.kind ? 'Rephrase without it, or ask the owner.' : 'Try again, or ask the owner.';
    return { block: true, blockReason: `Blocked: ${describe(blocking, target)}. ${reason}` };
  }
  const asking = findings.find((item) => item.mode === 'approve');
  if (asking) {
    return {
      requireApproval: {
        title: 'Text for another agent needs a check',
        description: `Held: ${describe(asking, target)}. Allow this call once?`,
        severity: 'warning',
        timeoutMs: APPROVAL_TIMEOUT_MS,
        allowedDecisions: ['allow-once', 'deny'],
      },
    };
  }
  return undefined;
}

export interface HookApi {
  pluginConfig?: unknown;
  logger?: { warn(line: string): void };
  on(
    name: 'before_tool_call',
    handler: (event: ToolCallEvent, ctx?: ToolCallContext) => Promise<Decision>,
    options: { priority: number },
  ): void;
}

/**
 * Registers one `before_tool_call` handler. `{ block: true }` is terminal, `requireApproval` pauses the run and a
 * timeout blocks the call (plugins/hooks/tool-policy.md, plugins/plugin-permission-requests.md, 2026.10.5). Warnings
 * go to `api.logger.warn` (plugins/sdk-runtime.md, 2026.10.5); where the host writes them is unverified.
 */
export function register(api: HookApi): void {
  const config = resolveConfig(api.pluginConfig);
  const log = (line: string) => api.logger?.warn(line);
  api.on('before_tool_call', (event, ctx) => decide(event, ctx, config, log), { priority: 90 });
}
