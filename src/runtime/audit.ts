/**
 * Runtime audit factory (face four: audit channel).
 *
 * `createRuntimeAudit(ctx)` resolves the trust-broker store, loads the anchor
 * journal, and registers structural Host listeners that append one stable JSONL
 * record per observable action:
 *
 * | Host event                  | audit event(s)                                   |
 * | --------------------------- | ------------------------------------------------ |
 * | `tools/pre-execute`         | `tool_call` (+ `scope_exceeded`)                 |
 * | `tools/post-execute`        | `tool_result` (+ `context_write` on rewrite)     |
 * | `system-prompt/assemble`    | `context_write` when the assembly changed        |
 * | `agent/inbox/inserted`      | `context_write` (`inbox_insert`)                 |
 * | `session/event`             | `context_write` (`history_compress`)             |
 *
 * Safety rules that are part of the contract:
 * - No `@deepseek-ai/*` imports: the factory takes the structural slice
 *   `RuntimeHostContext` from `src/types.ts`, so it is testable in isolation and
 *   can be mounted by the bundle entry without a DSH build-time dependency.
 * - Audit/classification failures are logged through `ctx.logger?.warn` and
 *   swallowed; tool dispatch must never fail because of the audit channel.
 * - Every waterfall listener calls `next()` exactly once and returns its value
 *   unchanged. v1 records, it does not intercept.
 */

import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { isTrustAnchor } from '../core/anchor-store.ts';
import { DEFAULT_REDACT_KEYS, digestJson, redactDeep } from '../core/fs-utils.ts';
import { readJsonlFile } from '../core/jsonl.ts';
import { parseDeclaredCapabilities } from '../core/manifest.ts';
import { TRUST_BROKER_VERSION } from '../version.ts';
import { AuditLog } from './audit-log.ts';
import type { AuditAttribution, AuditDraft } from './audit-log.ts';
import { checkToolScope, classifyToolCall } from './scope.ts';
import type { ClassifiedToolCall, ToolScopeVerdict } from './scope.ts';
import type {
  AuditEvent,
  RuntimeAuditConfig,
  RuntimeAuditHandle,
  RuntimeAuditService,
  RuntimeHostContext,
  TrustAnchor,
} from '../types.ts';

/** Default audit journal file name inside the store directory. */
const DEFAULT_AUDIT_FILE = 'audit.jsonl';
/** Default trust-anchor journal file name inside the store directory. */
const DEFAULT_ANCHORS_FILE = 'anchors.jsonl';
/** Default decision journal file name inside the store directory (reserved). */
const DEFAULT_DECISIONS_FILE = 'decisions.jsonl';
/** Digest used when an argument/result value cannot be canonicalized. */
const DIGEST_UNAVAILABLE = digestJson('[digest-unavailable]');
const AUDIT_ENVELOPE_FIELDS = [
  'schema_version', 'event', 'seq', 'id', 'ts', 'plugin_id', 'plugin_version', 'session_id', 'agent_id',
];
const AUDIT_EVENT_FIELDS = new Map<string, readonly string[]>([
  ['tool_call', ['tool', 'call_id', 'arguments_digest', 'argument_keys', 'categories', 'scope', 'owner_plugin_id']],
  ['tool_result', ['tool', 'call_id', 'ok', 'result_digest', 'settled_digest', 'rewritten']],
  ['scope_exceeded', ['tool', 'call_id', 'owner_plugin_id', 'exceeded', 'declared', 'evidence']],
  ['context_write', ['channel', 'before_digest', 'after_digest', 'chars_before', 'chars_after', 'detail']],
  ['anchor_created', ['anchor']],
  ['decision_recorded', ['decision_digest', 'action']],
  ['audit_error', ['operation', 'message']],
]);
const ANCHOR_AUDIT_FIELDS = [
  'schema_version', 'plugin_id', 'version', 'content_hash',
  'capability_keys', 'declaration_status', 'decision_digest', 'confirmed_by', 'confirmed_at',
];

/** Anchors of the store: flat load order plus the per-plugin index. */
interface AnchorIndex {
  all: TrustAnchor[];
  byPlugin: Map<string, TrustAnchor[]>;
}

/** Runtime audit service with the resolved decisions-journal path exposed. */
type RuntimeAuditServiceWithPaths = RuntimeAuditService & { readonly decisions_log_path: string };

/**
 * Create the runtime audit channel for a Host plugin.
 *
 * Anchors are read synchronously during creation so scope decisions made by the
 * very first tool call are already anchor-aware; {@link RuntimeAuditHandle.reloadAnchors}
 * re-reads the journal after an external confirmation.
 */
export function createRuntimeAudit(
  ctx: RuntimeHostContext,
  config: RuntimeAuditConfig = {},
): RuntimeAuditHandle {
  const storeDir = resolveStoreDir(config);
  const auditFile = resolveStorePath(storeDir, config.audit_file, DEFAULT_AUDIT_FILE);
  const anchorsFile = resolveStorePath(storeDir, config.anchors_file, DEFAULT_ANCHORS_FILE);
  const decisionsFile = resolveStorePath(storeDir, config.decisions_file, DEFAULT_DECISIONS_FILE);

  const warn = (message: string): void => {
    try {
      ctx.logger?.warn(message);
    } catch {
      // A broken logger must not break tool dispatch either.
    }
  };

  const auditLog = new AuditLog({ file: auditFile });
  const redactKeys = [...DEFAULT_REDACT_KEYS, ...(config.redact_argument_keys ?? [])];
  let disposed = false;
  const toolOwners = new Map<string, string>(Object.entries(config.tool_owners ?? {}));
  let anchorIndex = loadAnchorIndex(anchorsFile, warn);

  /**
   * Record one draft event. Failures are logged once per record call and never
   * propagate: the audit channel is not allowed to break dispatch.
   */
  const recordDraft = (draft: AuditDraft, attribution?: AuditAttribution): void => {
    if (disposed) return;
    try {
      const event = auditLog.record(draft, attribution);
      if (event !== null) return;
      warn('trust-broker: runtime audit write failed');
    } catch {
      warn('trust-broker: runtime audit record failed');
    }
  };

  /** Digest that never throws; used on untrusted result/assembly payloads. */
  const safeDigest = (value: unknown): string => {
    try {
      return digestJson(value);
    } catch {
      warn('trust-broker: runtime audit digest failed');
      return DIGEST_UNAVAILABLE;
    }
  };

  const toolOwnerSnapshot = (): Record<string, string> => Object.fromEntries(toolOwners);

  /** Build and append the `tool_call` record (plus `scope_exceeded` when needed). */
  const recordPreExecute = (exec: unknown): void => {
    const call = asRecord(exec) ?? {};
    const tool = toolNameOf(call);
    const args = call.arguments;
    const callId = optionalString(call.callId);
    const argumentKeys = topLevelKeys(args);
    const argumentsDigest = safeDigest(redactDeep(args, redactKeys));

    let classified: ClassifiedToolCall;
    try {
      classified = classifyToolCall(tool, args, config.tool_capabilities);
    } catch {
      warn('trust-broker: tool classification failed');
      classified = { categories: [], sources: [] };
    }

    const ownerPluginId = toolOwners.get(tool);
    let verdict: ToolScopeVerdict;
    try {
      verdict = checkToolScope({
        tool,
        categories: classified.categories,
        owner_plugin_id: ownerPluginId,
        anchors: anchorIndex.all,
        tool_owners: toolOwnerSnapshot(),
      });
    } catch {
      warn('trust-broker: scope check failed');
      verdict = { scope: 'unattributed', exceeded: [], declared: [], owner_plugin_id: ownerPluginId };
    }

    const attribution: AuditAttribution = {};
    const agentId = idOf(call.agent);
    if (agentId !== undefined) attribution.agent_id = agentId;

    recordDraft(
      {
        event: 'tool_call',
        tool,
        ...(callId !== undefined ? { call_id: callId } : {}),
        arguments_digest: argumentsDigest,
        argument_keys: argumentKeys,
        categories: classified.categories,
        scope: verdict.scope,
        ...(verdict.owner_plugin_id !== undefined
          ? { owner_plugin_id: verdict.owner_plugin_id }
          : {}),
      },
      attribution,
    );

    if (verdict.scope !== 'undeclared_scope') return;
    recordDraft(
      {
        event: 'scope_exceeded',
        tool,
        ...(callId !== undefined ? { call_id: callId } : {}),
        owner_plugin_id: verdict.owner_plugin_id ?? ownerPluginId ?? '',
        exceeded: verdict.exceeded,
        declared: verdict.declared,
        evidence: 'tool-call-outside-anchored-surface',
      },
      attribution,
    );
  };

  /** Record `tool_result` and, when a plugin rewrote the output, `context_write`. */
  const recordPostExecute = async (
    exec: unknown,
    result: unknown,
    next: () => unknown,
  ): Promise<unknown> => {
    if (disposed) return next();
    const before = safeDigest(result);
    // Dispatch errors thrown by next() must propagate untouched.
    const decision = await next();
    if (disposed) return decision;
    try {
      const call = asRecord(exec) ?? {};
      const tool = toolNameOf(call);
      const callId = optionalString(call.callId);
      const attribution: AuditAttribution = {};
      const agentId = idOf(call.agent);
      if (agentId !== undefined) attribution.agent_id = agentId;
      const after = safeDigest(projectPostExecute(result, decision));
      const rewritten = before !== after;
      recordDraft({
        event: 'tool_result',
        tool,
        ...(callId !== undefined ? { call_id: callId } : {}),
        ok: asRecord(result)?.isError === false,
        result_digest: before,
        settled_digest: after,
        rewritten,
      }, attribution);
      if (rewritten) {
        recordDraft({
          event: 'context_write',
          channel: 'tool_output_rewrite',
          before_digest: before,
          after_digest: after,
        }, attribution);
      }
    } catch {
      warn('trust-broker: post-execute audit failed');
    }
    return decision;
  };

  /** Record a prompt-assembly rewrite when the waterfall changed the assembly. */
  const recordPromptAssembly = async (
    assembly: unknown,
    next: () => unknown,
  ): Promise<unknown> => {
    if (disposed) return next();
    const before = safeDigest(assembly);
    const nextAssembly = await next();
    if (disposed) return nextAssembly;
    try {
      const after = safeDigest(nextAssembly);
      if (before !== after) {
        recordDraft({
          event: 'context_write',
          channel: 'prompt_assembly',
          before_digest: before,
          after_digest: after,
        });
      }
    } catch {
      warn('trust-broker: prompt-assembly audit failed');
    }
    return nextAssembly;
  };

  /** Record an agent-inbox insertion as a context write. */
  const recordInboxInsert = (payload: unknown): void => {
    if (config.context_audit === false) return;
    const record = asRecord(payload);
    if (record === undefined) return;
    const agent = record.agent;
    const message = record.message;
    if (!agent || !message) return;
    const messageRecord = asRecord(message);
    const digestSource = messageRecord?.content ?? message;
    const detail = inboxSourceKind(record, messageRecord);
    const attribution: AuditAttribution = {};
    const agentId = idOf(agent);
    if (agentId !== undefined) attribution.agent_id = agentId;
    recordDraft(
      {
        event: 'context_write',
        channel: 'inbox_insert',
        after_digest: safeDigest(digestSource),
        ...(detail !== undefined ? { detail } : {}),
      },
      attribution,
    );
  };

  /** Record a session-history compaction as a context write. */
  const recordSessionEvent = (session: unknown, event: unknown): void => {
    if (config.context_audit === false) return;
    const eventRecord = asRecord(event);
    const type = eventRecord?.type;
    if (typeof type !== 'string' || !type.startsWith('compaction/')) return;
    const attribution: AuditAttribution = {};
    const sessionId = optionalString(asRecord(session)?.id);
    if (sessionId !== undefined) attribution.session_id = sessionId;
    recordDraft(
      {
        event: 'context_write',
        channel: 'history_compress',
        detail: type,
        before_digest: safeDigest(eventRecord?.data),
      },
      attribution,
    );
  };

  /* ----------------------------------------------------------------------- */
  /* Listener registration. Waterfall listeners call next() exactly once.     */
  /* ----------------------------------------------------------------------- */

  ctx.on('tools/pre-execute', (exec: unknown, next: () => unknown) => {
    if (disposed) return next();
    try {
      recordPreExecute(exec);
    } catch {
      warn('trust-broker: pre-execute audit failed');
    }
    return next();
  });

  ctx.on(
    'tools/post-execute',
    (exec: unknown, result: unknown, next: () => unknown) =>
      recordPostExecute(exec, result, next),
  );

  ctx.on('system-prompt/assemble', (assembly: unknown, _context: unknown, next: () => unknown) =>
    recordPromptAssembly(assembly, next),
  );

  ctx.on('agent/inbox/inserted', (payload: unknown) => {
    if (disposed) return;
    try {
      recordInboxInsert(payload);
    } catch {
      warn('trust-broker: inbox-insert audit failed');
    }
  });

  ctx.on('session/event', (session: unknown, event: unknown) => {
    if (disposed) return;
    try {
      recordSessionEvent(session, event);
    } catch {
      warn('trust-broker: session-event audit failed');
    }
  });

  /* ----------------------------------------------------------------------- */
  /* Service / handle.                                                        */
  /* ----------------------------------------------------------------------- */

  /** Re-read the anchor journal synchronously; the returned promise is for API symmetry. */
  const reloadAnchors = (): Promise<void> => {
    if (disposed) return Promise.resolve();
    try {
      anchorIndex = loadAnchorIndex(anchorsFile, warn);
    } catch {
      warn('trust-broker: failed to reload anchors');
    }
    return Promise.resolve();
  };

  const setToolOwner = (tool: string, pluginId: string): void => {
    if (disposed) return;
    if (typeof tool !== 'string' || tool === '') return;
    if (typeof pluginId !== 'string' || pluginId === '') return;
    toolOwners.set(tool, pluginId);
  };

  const listAnchors = (pluginId?: string): Promise<TrustAnchor[]> => {
    if (disposed) return Promise.resolve([]);
    try {
      const anchors =
        pluginId === undefined
          ? anchorIndex.all
          : (anchorIndex.byPlugin.get(pluginId) ?? []);
      return Promise.resolve(structuredClone(anchors));
    } catch {
      warn('trust-broker: listAnchors failed');
      return Promise.resolve([]);
    }
  };

  const recordEvent: RuntimeAuditService['record'] = (event): void => {
    if (disposed) return;
    try {
      const candidate = projectServiceEvent(event, safeDigest);
      if (candidate === undefined) return;
      if (isCompleteEnvelope(candidate)) {
        auditLog.append(candidate as unknown as AuditEvent);
        if (auditLog.lastError !== undefined) warn('trust-broker: runtime audit write failed');
      } else {
        recordDraft(candidate as AuditDraft);
      }
    } catch {
      warn('trust-broker: service audit record failed');
    }
  };

  const service: RuntimeAuditServiceWithPaths = {
    store_dir: storeDir,
    audit_log_path: auditFile,
    anchors_log_path: anchorsFile,
    decisions_log_path: decisionsFile,
    version: TRUST_BROKER_VERSION,
    listAnchors,
    record: recordEvent,
    reloadAnchors,
    setToolOwner,
  };

  return {
    service,
    audit_log_path: auditFile,
    anchors_log_path: anchorsFile,
    reloadAnchors,
    setToolOwner,
    dispose: () => {
      disposed = true;
      auditLog.close();
    },
  };
}

/* ------------------------------------------------------------------------- */
/* Store resolution and anchor loading.                                      */
/* ------------------------------------------------------------------------- */

/** Resolve the store directory from config, environment, or the user home. */
function resolveStoreDir(config: RuntimeAuditConfig): string {
  const configured =
    config.store_dir ??
    process.env.DSH_TRUST_BROKER_STORE ??
    (process.env.DSH_HOME
      ? join(process.env.DSH_HOME, 'trust-broker')
      : join(homedir(), '.dsh', 'trust-broker'));
  return resolve(configured);
}

/** Resolve one journal file; relative names live under the store directory. */
function resolveStorePath(storeDir: string, configured: string | undefined, fallback: string): string {
  const file = configured ?? fallback;
  return isAbsolute(file) ? resolve(file) : resolve(join(storeDir, file));
}

/**
 * Read the anchor journal synchronously and index it per plugin.
 *
 * Malformed lines are reported to `warn` and skipped; valid anchors are kept.
 * This is a tolerant reader: a corrupt journal must never prevent the audit
 * channel from starting.
 */
function loadAnchorIndex(anchorsFile: string, warn: (message: string) => void): AnchorIndex {
  const index: AnchorIndex = { all: [], byPlugin: new Map() };
  const { records, errors } = readJsonlFile(anchorsFile);
  for (const error of errors) {
    warn(`trust-broker: failed to read anchor journal at line ${error.line}`);
  }
  for (const record of records) {
    if (!isTrustAnchor(record)) {
      warn('trust-broker: skipping malformed anchor record');
      continue;
    }
    index.all.push(record);
    const existing = index.byPlugin.get(record.plugin_id);
    if (existing === undefined) {
      index.byPlugin.set(record.plugin_id, [record]);
    } else {
      existing.push(record);
    }
  }
  return index;
}

/* ------------------------------------------------------------------------- */
/* Payload helpers.                                                          */
/* ------------------------------------------------------------------------- */

/** Narrow an unknown value to a plain record (arrays are excluded). */
function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

/**
 * DSH post-execute returns a decision. Compare its effect with the original
 * result instead of hashing the decision envelope as if it were a tool result.
 */
function projectPostExecute(result: unknown, decision: unknown): unknown {
  const verdict = asRecord(decision);
  const original = asRecord(result);
  if (verdict === undefined || original === undefined) return decision;
  if (verdict.kind === 'block') {
    return {
      isError: true,
      content: verdict.feedback,
      ...(verdict.additionalContexts !== undefined
        ? { additionalContexts: verdict.additionalContexts }
        : {}),
    };
  }
  if (verdict.kind !== 'accept') return decision;

  const addedContexts = Array.isArray(verdict.additionalContexts) ? verdict.additionalContexts : [];
  const originalContexts = Array.isArray(original.additionalContexts) ? original.additionalContexts : [];
  return {
    ...original,
    ...(verdict.content !== undefined ? { content: verdict.content } : {}),
    ...(Object.hasOwn(verdict, 'value') ? { value: verdict.value } : {}),
    ...(addedContexts.length > 0
      ? { additionalContexts: [...originalContexts, ...addedContexts] }
      : {}),
  };
}

/** Copy only journal fields and omit payloads that can carry private content. */
function projectServiceEvent(
  event: unknown,
  digest: (value: unknown) => string,
): Record<string, unknown> | undefined {
  const input = asRecord(event);
  if (input === undefined || !Object.hasOwn(input, 'event') || typeof input.event !== 'string') {
    return undefined;
  }
  const fields = AUDIT_EVENT_FIELDS.get(input.event);
  if (fields === undefined) return undefined;
  const envelopeFields = isCompleteEnvelope(input) ? AUDIT_ENVELOPE_FIELDS : ['event'];
  const projected = projectAuditMetadata(input, [...envelopeFields, ...fields]);
  if (input.event === 'anchor_created') {
    const anchor = input.anchor;
    if (!isTrustAnchor(anchor)) return undefined;
    projected.anchor = {
      ...projectAuditMetadata(anchor as unknown as Record<string, unknown>, ANCHOR_AUDIT_FIELDS),
      declared_capabilities: parseDeclaredCapabilities(anchor.declared_capabilities).declared,
      scanner: projectAuditMetadata(anchor.scanner, ['name', 'version', 'heuristic']),
    };
  }
  for (const field of ['message', 'detail'] as const) {
    if (typeof projected[field] === 'string') projected[field] = digest(projected[field]);
  }
  return projected;
}

function projectAuditMetadata(
  source: Record<string, unknown>,
  fields: readonly string[],
): Record<string, unknown> {
  const entries: Array<[string, unknown]> = [];
  for (const field of fields) {
    if (!Object.hasOwn(source, field)) continue;
    const value = source[field];
    if (typeof value === 'string' || typeof value === 'boolean' || Number.isFinite(value)) {
      entries.push([field, value]);
    } else if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
      entries.push([field, [...value]]);
    }
  }
  return Object.fromEntries(entries);
}

/** Tool name from a pre/post-execute payload. */
function toolNameOf(record: Record<string, unknown>): string {
  return typeof record.name === 'string' ? record.name : String(record.name ?? '');
}

/** Stringify an optional scalar (tool call ids may be strings or numbers). */
function optionalString(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'bigint') return String(value);
  return undefined;
}

/** Agent/session identity from either a bare id or an `{ id }` record. */
function idOf(value: unknown): string | undefined {
  return optionalString(value) ?? optionalString(asRecord(value)?.id);
}

/** Top-level argument keys (never values, so secrets are not copied here). */
function topLevelKeys(value: unknown): string[] {
  const record = asRecord(value);
  if (record === undefined) return [];
  return Object.keys(record);
}

/** Best-effort string "kind" describing where an inbox insert came from. */
function inboxSourceKind(
  payload: Record<string, unknown>,
  message: Record<string, unknown> | undefined,
): string | undefined {
  const candidates: unknown[] = [
    message?.source,
    payload.source,
    message?.kind,
    payload.kind,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === 'string') return candidate;
    if (candidate === null || candidate === undefined || typeof candidate !== 'object') continue;
    const kind = (candidate as Record<string, unknown>).kind;
    if (typeof kind === 'string') return kind;
  }
  return undefined;
}

/** True when a value already carries a complete audit envelope. */
function isCompleteEnvelope(value: unknown): boolean {
  const record = asRecord(value);
  if (record === undefined) return false;
  return (
    record.schema_version === 1 &&
    typeof record.event === 'string' &&
    typeof record.seq === 'number' &&
    Number.isInteger(record.seq) &&
    typeof record.id === 'string' &&
    typeof record.ts === 'string'
  );
}
