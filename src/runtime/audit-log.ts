/**
 * Append-only runtime audit log (face four).
 *
 * The runtime audit channel is a stable, machine-readable JSONL stream that
 * records what a Host plugin actually did at the layers a filesystem sandbox
 * cannot observe: tool dispatch intent, scope exceeding a plugin's anchored
 * surface, tool-output rewriting and context writes. Version 1 only *records*;
 * it never intercepts or rewrites a tool decision.
 *
 * # Design constraints
 *
 * - The writer keeps the file descriptor open (`JsonlWriter`) for the hot path.
 * - `record` fills the envelope (`schema_version`, `event`, `seq`, `id`, `ts`,
 *   plus optional attribution) and never throws: a broken audit disk must not
 *   be able to break tool dispatch. Failures surface through {@link lastError}.
 * - Field order inside one JSONL line is stable for downstream consumers:
 *   envelope first, then attribution, then event-specific fields.
 */

import { randomUUID } from 'node:crypto';
import { errorMessage } from '../core/fs-utils.ts';
import { JsonlWriter } from '../core/jsonl.ts';
import { AUDIT_SCHEMA_VERSION } from '../types.ts';
import type {
  AuditEvent,
  AuditEventBase,
  ContextWriteAuditEvent,
  DecisionAction,
  ScopeExceededAuditEvent,
  ToolCallAuditEvent,
  ToolResultAuditEvent,
  TrustAnchor,
} from '../types.ts';

/** The envelope fields the writer fills in; a draft omits exactly these. */
export type AuditEnvelopeField =
  | 'schema_version'
  | 'seq'
  | 'id'
  | 'ts'
  | 'plugin_id'
  | 'plugin_version'
  | 'session_id'
  | 'agent_id';

/**
 * Draft accepted by {@link AuditLog.record}.
 *
 * Local corrected counterpart of the shared `AuditEventDraft`: the shared union
 * is built with `Omit<..., keyof AuditEventBase>`, which also removes the
 * `event` discriminant. Keeping `event` here is required for a typed draft API;
 * `audit.ts` reports this as a gap in the shared contract instead of editing
 * `src/types.ts` (read-only for the runtime face).
 */
export type AuditDraft =
  | Omit<ToolCallAuditEvent, AuditEnvelopeField>
  | Omit<ToolResultAuditEvent, AuditEnvelopeField>
  | Omit<ScopeExceededAuditEvent, AuditEnvelopeField>
  | Omit<ContextWriteAuditEvent, AuditEnvelopeField>
  | { event: 'anchor_created'; anchor: TrustAnchor }
  | { event: 'decision_recorded'; decision_digest: string; action: DecisionAction }
  | { event: 'audit_error'; operation: string; message: string };

/** Optional attribution stamped into the envelope of one audit event. */
export interface AuditAttribution {
  plugin_id?: string;
  plugin_version?: string;
  session_id?: string;
  agent_id?: string;
}

/** Constructor options for {@link AuditLog}. */
export interface AuditLogOptions {
  /** Append-only JSONL file. Parent directories are created lazily on first write. */
  file: string;
  /** Flush every record to disk. Default false; audit lines are not fsync'd on the hot path. */
  fsync?: boolean;
  /** Injectable clock for deterministic `ts`. Default `() => new Date()`. */
  now?: () => Date;
  /** Injectable id factory. Default `crypto.randomUUID()` with a counter fallback. */
  idFactory?: () => string;
}

/**
 * Long-lived, tolerant JSONL writer for runtime audit events.
 *
 * One instance owns one file and one monotonically increasing `seq` counter.
 * `record` / `append` never throw; call {@link close} on plugin disposal.
 */
export class AuditLog {
  /** Absolute path of the JSONL file this log appends to. */
  readonly file: string;

  readonly #writer: JsonlWriter;
  readonly #now: () => Date;
  readonly #idFactory: () => string;
  #seq = 0;
  #fallbackId = 0;
  #lastError: string | undefined;

  constructor(options: AuditLogOptions) {
    this.file = options.file;
    this.#writer = new JsonlWriter({ file: options.file, fsync: options.fsync });
    this.#now = options.now ?? (() => new Date());
    this.#idFactory = options.idFactory ?? (() => randomUUID());
  }

  /** Last write/validation failure; cleared by the next successful append. */
  get lastError(): string | undefined {
    return this.#lastError;
  }

  /**
   * Fill the envelope and append one JSONL line.
   *
   * @returns the written event, or `null` when the write failed (the failure is
   *   recorded in {@link lastError}; nothing is thrown and nothing reaches stdout).
   */
  record(draft: AuditDraft, attribution?: AuditAttribution): AuditEvent | null {
    try {
      const seq = this.#seq + 1;
      const id = this.#nextId();
      const ts = this.#now().toISOString();
      const event = buildAuditEvent(draft, seq, id, ts, attribution);
      if (!this.#writer.tryAppend(event)) {
        this.#lastError = this.#writer.lastError;
        return null;
      }
      this.#seq = seq;
      this.#lastError = undefined;
      return event;
    } catch (error) {
      this.#lastError = errorMessage(error);
      return null;
    }
  }

  /**
   * Append an already-enveloped event without touching it.
   *
   * Low-level escape hatch used by the runtime service for events built
   * elsewhere; writer failures are recorded in {@link lastError} and swallowed.
   */
  append(event: AuditEvent): void {
    try {
      if (!this.#writer.tryAppend(event)) {
        this.#lastError = this.#writer.lastError;
        return;
      }
      const appendedSeq = (event as Partial<AuditEventBase>).seq;
      if (typeof appendedSeq === 'number' && appendedSeq > this.#seq) this.#seq = appendedSeq;
      this.#lastError = undefined;
    } catch (error) {
      this.#lastError = errorMessage(error);
    }
  }

  /** Flush and close the underlying file descriptor. Idempotent. */
  close(): void {
    this.#writer.close();
  }

  #nextId(): string {
    try {
      const id = this.#idFactory();
      if (typeof id === 'string' && id !== '') return id;
    } catch {
      // Fall through to the counter id; a broken id factory must not lose the event.
    }
    this.#fallbackId += 1;
    return `audit-${process.pid}-${this.#fallbackId}`;
  }
}

/** Build one event with a deterministic envelope field order. */
function buildAuditEvent(
  draft: AuditDraft,
  seq: number,
  id: string,
  ts: string,
  attribution?: AuditAttribution,
): AuditEvent {
  const envelope: AuditEventBase = {
    schema_version: AUDIT_SCHEMA_VERSION,
    event: draft.event,
    seq,
    id,
    ts,
  };
  const attributed: Partial<AuditEventBase> = {};
  if (attribution !== undefined) {
    if (attribution.plugin_id !== undefined) attributed.plugin_id = attribution.plugin_id;
    if (attribution.plugin_version !== undefined) attributed.plugin_version = attribution.plugin_version;
    if (attribution.session_id !== undefined) attributed.session_id = attribution.session_id;
    if (attribution.agent_id !== undefined) attributed.agent_id = attribution.agent_id;
  }
  // Spread draft last: it repeats `event` (same value) but appends its own fields.
  return { ...envelope, ...attributed, ...draft } as unknown as AuditEvent;
}
