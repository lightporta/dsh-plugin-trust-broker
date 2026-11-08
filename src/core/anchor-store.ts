/**
 * Persistent append-only trust-anchor store.
 *
 * A trust anchor records "this plugin version, with this content hash and this
 * capability set, was confirmed by the user/policy at this time". Anchors are the
 * memory of the trust broker: the drift comparison and the admission gate read
 * them, and the CLI appends one only after an explicit confirmation.
 *
 * Storage contract (security properties):
 * - Append-only JSONL: `record()` appends exactly one JSON line; the file is
 *   never rewritten or truncated, so a forged/edited journal leaves history
 *   behind instead of erasing it, and concurrent appends cannot interleave
 *   partial lines (`O_APPEND` in `jsonl.ts`).
 * - Durable by default: `record()` fsyncs unless `fsync: false` is passed.
 * - Fail-visible parsing: every line is validated with {@link isTrustAnchor};
 *   malformed lines are reported by {@link AnchorStore.snapshot} and skipped by
 *   the lookup helpers, so one torn/corrupt line never hides the other anchors.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type {
  CapabilityKey,
  ConfirmedBy,
  DeclaredCapabilities,
  DeclarationStatus,
  TrustAnchor,
} from '../types.ts';
import { TRUST_SCHEMA_VERSION } from '../types.ts';
import { appendJsonLine, readJsonlFile } from './jsonl.ts';

/** Fixed file name of the anchor journal inside a store directory. */
export const ANCHOR_STORE_FILENAME = 'anchors.jsonl';

/** Values accepted by `TrustAnchor.confirmed_by`. */
const CONFIRMED_BY_VALUES: ReadonlySet<string> = new Set<ConfirmedBy>(['user', 'policy']);

/** Values accepted by `TrustAnchor.declaration_status`. */
const DECLARATION_STATUS_VALUES: ReadonlySet<string> = new Set<DeclarationStatus>([
  'declared',
  'unstated',
  'incomplete',
  'malformed',
]);

type PlainObject = Record<string, unknown>;

/** Resolve the anchor journal path for a store directory. */
export function anchorStorePath(storeDir: string): string {
  return join(storeDir, ANCHOR_STORE_FILENAME);
}

/** Constructor options for {@link AnchorStore}. */
export interface AnchorStoreOptions {
  /** Absolute path of the JSONL journal (normally `anchorStorePath(storeDir)`). */
  file: string;
  /** Flush each append to disk. Default `true`; anchors must survive a crash. */
  fsync?: boolean;
}

/** Input accepted by {@link buildTrustAnchor}. */
export interface BuildAnchorInput {
  plugin_id: string;
  version: string;
  /** Canonical content hash (`sha256:<hex>`); anchors are refused when null. */
  content_hash: string;
  declared_capabilities: DeclaredCapabilities;
  /** Effective capability set confirmed by the user/policy. */
  capability_keys: CapabilityKey[];
  declaration_status: DeclarationStatus;
  scanner: { name: string; version?: string; heuristic: boolean };
  /** sha-256 digest over the canonical decision facts (anchor binding). */
  decision_digest: string;
  confirmed_by: ConfirmedBy;
  /** ISO confirmation time; defaults to the current time. */
  confirmed_at?: string;
  notes?: string;
}

/**
 * Build a complete {@link TrustAnchor} record from decision facts.
 *
 * Pure: does not write anything and does not read the clock unless
 * `confirmed_at` is omitted. Inputs are copied (the anchor never aliases caller
 * arrays/objects). Invalid runtime input (for example a null/foreign content
 * hash) throws a `TypeError` so a bad anchor can never enter the journal.
 *
 * @param input Decision facts captured at confirmation time.
 * @returns A schema-v1 anchor ready for {@link AnchorStore.record}.
 */
export function buildTrustAnchor(input: BuildAnchorInput): TrustAnchor {
  const scanner: TrustAnchor['scanner'] =
    input.scanner.version === undefined
      ? { name: input.scanner.name, heuristic: input.scanner.heuristic }
      : {
          name: input.scanner.name,
          version: input.scanner.version,
          heuristic: input.scanner.heuristic,
        };
  const anchor: TrustAnchor = {
    plugin_id: input.plugin_id,
    version: input.version,
    content_hash: input.content_hash,
    declared_capabilities: structuredClone(input.declared_capabilities),
    confirmed_at: input.confirmed_at ?? new Date().toISOString(),
    confirmed_by: input.confirmed_by,
    schema_version: TRUST_SCHEMA_VERSION,
    capability_keys: [...input.capability_keys],
    declaration_status: input.declaration_status,
    scanner,
    decision_digest: input.decision_digest,
    ...(input.notes === undefined ? {} : { notes: input.notes }),
  };
  const problems = anchorProblems(anchor);
  if (problems.length > 0) {
    throw new TypeError(`buildTrustAnchor: invalid trust anchor: ${problems.join('; ')}`);
  }
  return anchor;
}

/**
 * Type guard for a persisted anchor line.
 *
 * Required fields must be present and well-typed: `plugin_id`, `version`,
 * `content_hash` starting with `sha256:`, `declared_capabilities` object,
 * `capability_keys` string array, `declaration_status` enum, `scanner` object,
 * `decision_digest`, `confirmed_by` enum, parseable `confirmed_at`, and
 * `schema_version: 1`. Unknown extra fields are allowed for forward
 * compatibility, and capability keys are not required to exist in the current
 * catalog (a newer broker may have written them).
 */
export function isTrustAnchor(value: unknown): value is TrustAnchor {
  return anchorProblems(value).length === 0;
}

/** List every problem with a would-be anchor; empty when valid. */
function anchorProblems(value: unknown): string[] {
  if (!isPlainObject(value)) return ['anchor is not a JSON object'];
  const problems: string[] = [];
  if (!isNonEmptyString(value.plugin_id)) problems.push('plugin_id must be a non-empty string');
  if (!isNonEmptyString(value.version)) problems.push('version must be a non-empty string');
  if (typeof value.content_hash !== 'string' || !value.content_hash.startsWith('sha256:')) {
    problems.push("content_hash must be a string starting with 'sha256:'");
  }
  if (!isPlainObject(value.declared_capabilities)) {
    problems.push('declared_capabilities must be an object');
  }
  if (
    !Array.isArray(value.capability_keys) ||
    !value.capability_keys.every((key) => isNonEmptyString(key))
  ) {
    problems.push('capability_keys must be an array of non-empty strings');
  }
  if (
    typeof value.declaration_status !== 'string' ||
    !DECLARATION_STATUS_VALUES.has(value.declaration_status)
  ) {
    problems.push("declaration_status must be one of 'declared', 'unstated', 'incomplete', 'malformed'");
  }
  if (!isPlainObject(value.scanner)) {
    problems.push('scanner must be an object');
  } else {
    if (!isNonEmptyString(value.scanner.name)) problems.push('scanner.name must be a non-empty string');
    if (typeof value.scanner.heuristic !== 'boolean') problems.push('scanner.heuristic must be a boolean');
    if (value.scanner.version !== undefined && typeof value.scanner.version !== 'string') {
      problems.push('scanner.version must be a string when present');
    }
  }
  if (!isNonEmptyString(value.decision_digest)) {
    problems.push('decision_digest must be a non-empty string');
  }
  if (
    typeof value.confirmed_by !== 'string' ||
    !CONFIRMED_BY_VALUES.has(value.confirmed_by)
  ) {
    problems.push("confirmed_by must be 'user' or 'policy'");
  }
  if (
    !isNonEmptyString(value.confirmed_at) ||
    Number.isNaN(Date.parse(value.confirmed_at))
  ) {
    problems.push('confirmed_at must be an ISO-8601 timestamp string');
  }
  if (value.schema_version !== TRUST_SCHEMA_VERSION) {
    problems.push(`schema_version must be ${TRUST_SCHEMA_VERSION}`);
  }
  if (value.notes !== undefined && typeof value.notes !== 'string') {
    problems.push('notes must be a string when present');
  }
  return problems;
}

/** Append-only reader/writer for the trust-anchor journal. */
export class AnchorStore {
  /** Absolute or relative path of the JSONL journal. */
  readonly file: string;
  readonly #fsync: boolean;

  constructor(options: AnchorStoreOptions) {
    if (!isPlainObject(options)) {
      throw new TypeError('AnchorStore requires an options object');
    }
    if (!isNonEmptyString(options.file)) {
      throw new TypeError('AnchorStore: options.file must be a non-empty string');
    }
    this.file = options.file;
    this.#fsync = options.fsync !== false;
  }

  /**
   * Append one anchor as a single JSONL line (append-only, fsync by default).
   *
   * @throws TypeError when the anchor is invalid; the journal is not touched.
   * @throws When the append itself fails (callers must not treat anchors as durable on error).
   */
  async record(anchor: TrustAnchor): Promise<void> {
    const problems = anchorProblems(anchor);
    if (problems.length > 0) {
      throw new TypeError(`AnchorStore.record: refusing to record invalid trust anchor: ${problems.join('; ')}`);
    }
    appendJsonLine(this.file, anchor, { fsync: this.#fsync });
  }

  /** All valid anchors in file order, optionally filtered by plugin id. */
  async list(pluginId?: string): Promise<TrustAnchor[]> {
    const { records } = readJsonlFile(this.file);
    const anchors: TrustAnchor[] = [];
    for (const record of records) {
      if (!isTrustAnchor(record)) continue;
      if (pluginId !== undefined && record.plugin_id !== pluginId) continue;
      anchors.push(record);
    }
    return anchors;
  }

  /**
   * Latest valid anchor for a plugin: greatest `confirmed_at`; on a tie the
   * later JSONL line wins. Malformed lines are skipped (see {@link snapshot}).
   */
  async latest(pluginId: string): Promise<TrustAnchor | undefined> {
    return pickLatest(await this.list(pluginId));
  }

  /**
   * Latest valid anchor for a plugin whose content hash matches.
   *
   * Used to skip re-confirmation when identical bytes were already confirmed.
   */
  async findMatch(pluginId: string, contentHash: string): Promise<TrustAnchor | undefined> {
    const matches = (await this.list(pluginId)).filter(
      (anchor) => anchor.content_hash === contentHash,
    );
    return pickLatest(matches);
  }

  /**
   * Full inspection of the journal: valid anchors plus every parse/validation
   * problem with its 1-based line number. A missing file is an empty store.
   */
  async snapshot(): Promise<{
    anchors: TrustAnchor[];
    errors: Array<{ line: number; message: string }>;
    file: string;
  }> {
    const { records, errors: parseErrors } = readJsonlFile(this.file);
    const lineNumbers = recordLineNumbers(this.file, records, parseErrors);
    const anchors: TrustAnchor[] = [];
    const errors: Array<{ line: number; message: string }> = [...parseErrors];
    records.forEach((record, index) => {
      const problems = anchorProblems(record);
      if (problems.length === 0) {
        anchors.push(record as TrustAnchor);
        return;
      }
      errors.push({
        line: lineNumbers[index] ?? index + 1,
        message: `invalid anchor record: ${problems.join('; ')}`,
      });
    });
    errors.sort((left, right) => {
      const byLine = left.line - right.line;
      if (byLine !== 0) return byLine;
      return left.message < right.message ? -1 : left.message > right.message ? 1 : 0;
    });
    return { anchors, errors, file: this.file };
  }
}

/** Anchor with the greatest confirmed_at; ties resolved by later input order. */
function pickLatest(anchors: readonly TrustAnchor[]): TrustAnchor | undefined {
  let best: TrustAnchor | undefined;
  let bestTime = Number.NEGATIVE_INFINITY;
  let bestIndex = -1;
  anchors.forEach((anchor, index) => {
    const time = Date.parse(anchor.confirmed_at);
    if (time > bestTime || (time === bestTime && index > bestIndex)) {
      best = anchor;
      bestTime = time;
      bestIndex = index;
    }
  });
  return best;
}

/**
 * Map each parsed record back to its file line number.
 *
 * `readJsonlFile` returns parsed records and parse errors but not line
 * provenance, so the raw lines are re-read only for line accounting: blank lines
 * and lines already reported as parse errors are skipped, and the remaining
 * lines pair 1:1 with the parsed records. Falls back to ordinal numbers when the
 * mapping cannot be reconstructed (e.g. the file became unreadable).
 */
function recordLineNumbers(
  file: string,
  records: readonly unknown[],
  parseErrors: ReadonlyArray<{ line: number; message: string }>,
): number[] {
  const fallback = (): number[] => records.map((_, index) => index + 1);
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    return fallback();
  }
  const malformedLines = new Set(
    parseErrors.map((error) => error.line).filter((line) => line > 0),
  );
  const numbers: number[] = [];
  const lines = text.split('\n');
  for (let index = 0; index < lines.length && numbers.length < records.length; index += 1) {
    const raw = lines[index] ?? '';
    if (raw.trim() === '') continue;
    const lineNumber = index + 1;
    if (malformedLines.has(lineNumber)) continue;
    numbers.push(lineNumber);
  }
  return numbers.length === records.length ? numbers : fallback();
}

function isPlainObject(value: unknown): value is PlainObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}
