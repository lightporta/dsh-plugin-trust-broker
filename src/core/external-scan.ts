/**
 * Adapter for schema 2 reports. An operator can supply a report or select a
 * trusted executable by absolute path. No ambient module or PATH discovery is
 * performed. A failed explicit scan never becomes an absent scan.
 */

import { spawn } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type {
  CapabilityFact,
  CapabilityPath,
  DetectionError,
  DetectionSource,
  EvidenceRef,
} from '../types.ts';
import { capabilityPathsForScannerId, isDeclarable } from './catalog.ts';
import { redactUrlCredentials } from './fs-utils.ts';
import { FileReadLimitError, readTreeFile } from './tree-files.ts';

/** Display name of the reference scanner. */
export const SCANNER_BIN = 'dsh-trust-check';

/** Report schema version this adapter understands. */
export const SCANNER_SCHEMA_VERSION = 2 as const;

/** Identifier of the only injection target whose location the broker knows. */
const CORDIS_PATCH_FIELD = 'cordis.patch.yml';

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_SNIPPET_LENGTH = 200;
const MAX_REPORT_BYTES = 8 * 1024 * 1024;

/** Input bag for {@link loadExternalScan}. */
export interface ExternalScanInput {
  /** Plugin root passed to the scanner. May be a private snapshot. */
  root: string;
  /** Original plugin root, if the scanner receives a snapshot. */
  candidateRoot?: string;
  /** Already-parsed `dsh-trust-check --json` payload. Takes priority. */
  report?: unknown;
  /** Path to a `dsh-trust-check --json` payload. Used when `report` is absent. */
  reportPath?: string;
  /** Absolute path to an operator-selected, trusted scanner executable. */
  bin?: string;
  /** Spawn timeout in milliseconds, capped at 30 s. */
  timeoutMs?: number;
  /** Set to `false` to consume reports only. */
  allowSpawn?: boolean;
  signal?: AbortSignal;
}

/** Identity of the scanner that produced a successful report. */
export interface ExternalScannerDescriptor {
  name: string;
  version?: string;
  schema_version: 2;
}

/** A schema 2 report was parsed and mapped into verifiable facts. */
export interface ExternalScanSuccess {
  ok: true;
  scanner: ExternalScannerDescriptor;
  /** Facts with `heuristic: false` and `source.kind: 'dsh-trust-check'`. */
  facts: CapabilityFact[];
  /** Scanner high-confidence lines, passed through verbatim. */
  red_lines: string[];
  notes: string[];
}

/** The scanner was found but its output cannot be trusted or used. */
export interface ExternalScanFailure {
  ok: false;
  errors: DetectionError[];
  notes: string[];
}

/**
 * Result of an external scan attempt: a success, a failure, or `null` when no
 * external input is configured (a note for the decision layer, not an error).
 */
export type ExternalScanOutcome = ExternalScanSuccess | ExternalScanFailure | null;

/** Plain-object guard (scanner payloads are untrusted JSON). */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Build a single-error failure result. */
function failure(code: string, message: string, notes: string[] = []): ExternalScanFailure {
  return { ok: false, errors: [{ code, message }], notes };
}

/** Trim a scanner snippet and cap it at the evidence contract's 200 chars. */
function trimSnippet(value: string): string {
  return redactUrlCredentials(value).trim().slice(0, MAX_SNIPPET_LENGTH);
}

/** Structural evidence row shared by `evidence[]` and `facts[].evidence[]`. */
function toEvidence(row: Record<string, unknown>): EvidenceRef | undefined {
  const file = typeof row.file === 'string' && row.file.trim() !== '' ? row.file : undefined;
  const line =
    typeof row.line === 'number' && Number.isInteger(row.line) && row.line > 0 ? row.line : undefined;
  const snippet = typeof row.snippet === 'string' ? trimSnippet(row.snippet) : undefined;
  const field = typeof row.field === 'string' && row.field !== '' ? row.field : undefined;
  if (file === undefined && line === undefined && snippet === undefined && field === undefined) {
    return undefined;
  }
  const evidence: EvidenceRef = {};
  if (file !== undefined) evidence.file = file;
  if (line !== undefined) evidence.line = line;
  if (snippet !== undefined && snippet !== '') evidence.snippet = snippet;
  if (field !== undefined) evidence.field = field;
  return evidence;
}

/** Stable evidence identity used for de-duplication. */
function evidenceKey(evidence: EvidenceRef): string {
  return [
    evidence.file ?? '',
    evidence.line === undefined ? '' : String(evidence.line),
    evidence.snippet ?? '',
    evidence.field ?? '',
  ].join('\u0000');
}

/** Best-effort host extraction for `destination:<host>` details. */
function destinationHost(value: string): string {
  try {
    const parsed = new URL(value);
    if (parsed.host !== '') return parsed.host;
  } catch {
    // Not an absolute URL; fall back to the raw value scanner reported.
  }
  return redactUrlCredentials(value);
}

/** Accumulator for one scanner capability id mapped to one broker path. */
interface FactBuilder {
  capability: CapabilityPath;
  /** Metadata pointer used when the scanner gave no file:line evidence rows. */
  fallbackField: string;
  evidence: EvidenceRef[];
  evidenceKeys: Set<string>;
  details: string[];
}

/** Load an explicit schema 2 report or run an explicitly selected scanner. */
export async function loadExternalScan(input: ExternalScanInput): Promise<ExternalScanOutcome> {
  if (input.signal?.aborted === true) return abortedScan();
  if (input.report !== undefined) return interpretReport(input.report, '传入的');
  if (input.reportPath !== undefined) return loadReportFile(input.reportPath, input.signal);
  if (input.allowSpawn === false || input.bin === undefined) return null;
  if (!isAbsolute(input.bin)) {
    return failure('external_scanner_failed', '外部扫描器必须使用可信的绝对可执行文件路径。');
  }

  const timeoutMs =
    typeof input.timeoutMs === 'number' && Number.isFinite(input.timeoutMs) && input.timeoutMs > 0
      ? Math.min(input.timeoutMs, DEFAULT_TIMEOUT_MS)
      : DEFAULT_TIMEOUT_MS;
  let command: string;
  let root: string;
  let candidate: string;
  try {
    [command, root, candidate] = await Promise.all([
      realpath(input.bin),
      realpath(input.root),
      realpath(input.candidateRoot ?? input.root),
    ]);
  } catch {
    return failure('external_scanner_failed', '无法解析指定的外部扫描器或扫描目录。');
  }
  if (input.signal?.aborted) return abortedScan();
  if (isWithin(root, command) || isWithin(candidate, command)) {
    return failure('external_scanner_failed', '扫描器不可位于待审插件目录中。');
  }
  return spawnScanner(command, root, timeoutMs, input.signal);
}

function isWithin(root: string, file: string): boolean {
  const rel = relative(root, file);
  return !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`);
}

function abortedScan(): ExternalScanFailure {
  return failure('external_scanner_aborted', '外部扫描已取消。');
}

function oversizedReport(): ExternalScanFailure {
  return failure('external_scanner_report_too_large', '外部扫描器报告超过 8 MiB 上限。');
}

/** Read only the operator-selected regular file, bounded even if it grows. */
async function loadReportFile(reportPath: string, signal?: AbortSignal): Promise<ExternalScanOutcome> {
  const absolutePath = resolve(reportPath);
  let data: Buffer;
  try {
    const directory = await realpath(dirname(absolutePath));
    data = await readTreeFile(join(directory, basename(absolutePath)), MAX_REPORT_BYTES, { rejectHardLinks: true, signal });
  } catch (error) {
    if (signal?.aborted === true) return abortedScan();
    if (error instanceof FileReadLimitError) return oversizedReport();
    return failure('external_scanner_report_unreadable', '无法读取指定的外部扫描器报告。');
  }
  if (signal?.aborted === true) return abortedScan();
  return parseReport(data.toString('utf8'), '报告文件中的');
}

/** Parse an untrusted payload without leaking its contents through parser errors. */
function parseReport(source: string, origin: string): ExternalScanSuccess | ExternalScanFailure {
  let payload: unknown;
  try {
    payload = JSON.parse(source) as unknown;
  } catch {
    return failure('external_scanner_report_invalid', `${origin}外部扫描器报告不是合法 JSON。`);
  }
  return interpretReport(payload, origin);
}

/** Run the selected scanner without a shell, inherited credentials or stderr. */
function spawnScanner(
  command: string,
  root: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<ExternalScanOutcome> {
  return new Promise((resolveOutcome) => {
    const group = process.platform !== 'win32';
    let child;
    try {
      child = spawn(command, ['--dir', root, '--json'], {
        cwd: dirname(command),
        detached: group,
        env: { PATH: dirname(process.execPath) },
        shell: false,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch {
      resolveOutcome(failure('external_scanner_failed', '无法启动指定的外部扫描器。'));
      return;
    }

    let settled = false;
    const chunks: Buffer[] = [];
    let bytes = 0;
    const finish = (outcome: ExternalScanOutcome, terminate = false): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (terminate) {
        try {
          if (group && child.pid !== undefined) process.kill(-child.pid, 'SIGKILL');
          else child.kill('SIGKILL');
        } catch {
          child.kill('SIGKILL');
        }
        child.stdout.destroy();
      }
      resolveOutcome(outcome);
    };
    const abort = (): void => finish(abortedScan(), true);
    const timer = setTimeout(
      () => finish(failure('external_scanner_timeout', `外部扫描在 ${timeoutMs}ms 内未完成。`), true),
      timeoutMs,
    );
    child.stdout.on('data', (chunk: Buffer) => {
      if (settled) return;
      bytes += chunk.length;
      if (bytes > MAX_REPORT_BYTES) finish(oversizedReport(), true);
      else chunks.push(chunk);
    });
    child.once('error', () =>
      finish(failure('external_scanner_failed', '无法运行指定的外部扫描器。'), true),
    );
    child.once('close', (code) => {
      if (settled) return;
      if (code !== 0) {
        finish(failure('external_scanner_failed', '指定的外部扫描器未成功退出。'));
        return;
      }
      finish(parseReport(Buffer.concat(chunks, bytes).toString('utf8'), '可执行文件输出的'));
    });
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted === true) abort();
  });
}

/**
 * Validate a schema 2 payload and map it into broker facts.
 *
 * Mapping rules (contract of face two):
 * - `plugins[0].capabilities[]` -> one fact per capability id via
 *   `capabilityPathsForScannerId`; the fact's `capability`/`path` is the mapped
 *   broker path and the scanner id becomes part of `detail`.
 * - `plugins[0].evidence[]` rows -> evidence for the matching scanner capability.
 * - `plugins[0].facts[].id` prefix before the first `.` -> supplementary
 *   evidence for an already-detected scanner capability.
 * - `plugins[0].destinations[]` -> evidence + `destination:<host>` detail on
 *   `network.fetch`.
 * - `plugins[0].injections[]` -> `context.prompt_inject` (system-prompt/skill)
 *   or `composition.override` (override/disable), located at `cordis.patch.yml`.
 * - `plugins[0].redLines[]` -> `red_lines` with URL credentials removed.
 */
function interpretReport(payload: unknown, origin: string): ExternalScanSuccess | ExternalScanFailure {
  const notes: string[] = [];

  if (!isPlainObject(payload)) {
    return failure('external_scanner_report_invalid', `${origin} 的扫描器报告顶层必须是对象`);
  }

  const schemaVersion = payload.schemaVersion;
  if (schemaVersion !== SCANNER_SCHEMA_VERSION) {
    return failure(
      'external_scanner_schema_unsupported',
      `${origin}扫描器报告使用了不受支持的版本，仅支持 schema 2。`,
    );
  }

  if (payload.errors !== undefined && !Array.isArray(payload.errors)) {
    return failure('external_scanner_report_invalid', '扫描器报告的 errors 必须是数组。');
  }
  const payloadErrors = payload.errors ?? [];
  if (payloadErrors.length > 0) {
    return failure('external_scanner_failed', `外部扫描器报告了 ${payloadErrors.length} 项错误。`);
  }

  const plugins = payload.plugins;
  if (!Array.isArray(plugins) || plugins.length !== 1) {
    return failure('external_scanner_report_invalid', `${origin}扫描器报告必须只包含一个插件。`);
  }
  const plugin = plugins[0];
  if (!isPlainObject(plugin)) {
    return failure('external_scanner_report_invalid', `${origin}扫描器报告 plugins[0] 不是对象。`);
  }
  if (!Array.isArray(plugin.capabilities)) {
    return failure('external_scanner_report_invalid', '扫描器报告的 capabilities 必须是数组。');
  }
  for (const field of ['evidence', 'destinations', 'facts', 'injections', 'redLines'] as const) {
    if (plugin[field] !== undefined && !Array.isArray(plugin[field])) {
      return failure('external_scanner_report_invalid', `扫描器报告的 ${field} 必须是数组。`);
    }
  }

  const scanner = readScannerDescriptor(payload);
  const source: DetectionSource = {
    kind: 'dsh-trust-check',
    name: scanner.name,
    ...(scanner.version !== undefined ? { version: scanner.version } : {}),
    schema_version: SCANNER_SCHEMA_VERSION,
    heuristic: false,
  };

  const builders = new Map<CapabilityPath, FactBuilder>();
  const unknownCapabilityIds = new Set<string>();

  const ensureBuilder = (path: CapabilityPath, fallbackField: string): FactBuilder => {
    const existing = builders.get(path);
    if (existing !== undefined) return existing;
    const created: FactBuilder = {
      capability: path,
      fallbackField,
      evidence: [],
      evidenceKeys: new Set<string>(),
      details: [],
    };
    builders.set(path, created);
    return created;
  };

  const addEvidence = (path: CapabilityPath, fallbackField: string, evidence: EvidenceRef): void => {
    const builder = ensureBuilder(path, fallbackField);
    const key = evidenceKey(evidence);
    if (builder.evidenceKeys.has(key)) return;
    builder.evidenceKeys.add(key);
    builder.evidence.push(evidence);
  };

  const addDetail = (path: CapabilityPath, fallbackField: string, detail: string): void => {
    if (detail === '') return;
    // Scanner-provided details are untrusted display text: strip URL
    // credentials, collapse control whitespace and cap the length.
    const safeDetail = redactUrlCredentials(detail)
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, MAX_SNIPPET_LENGTH);
    if (safeDetail === '') return;
    const builder = ensureBuilder(path, fallbackField);
    if (!builder.details.includes(safeDetail)) builder.details.push(safeDetail);
  };

  // 1) Scanner capability ids -> broker capability paths.
  const rawCapabilities = plugin.capabilities;
  if (Array.isArray(rawCapabilities)) {
    for (const capabilityId of rawCapabilities) {
      if (typeof capabilityId !== 'string' || capabilityId === '') continue;
      const paths = capabilityPathsForScannerId(capabilityId);
      if (paths.length === 0) {
        if (!unknownCapabilityIds.has(capabilityId)) {
          unknownCapabilityIds.add(capabilityId);
          notes.push(`扫描器能力 "${capabilityId}" 不在本地能力目录中，已忽略。`);
        }
        continue;
      }
      for (const path of paths) {
        addDetail(path, 'dsh-trust-check#plugins[0].capabilities', capabilityId);
      }
    }
  }

  // 2) Evidence rows for scanner capabilities (also creates facts if the
  //    scanner omitted the id from capabilities but gave concrete evidence).
  const rawEvidence = plugin.evidence;
  if (Array.isArray(rawEvidence)) {
    for (const row of rawEvidence) {
      if (!isPlainObject(row)) continue;
      const capabilityId = typeof row.capability === 'string' ? row.capability : '';
      if (capabilityId === '') continue;
      const paths = capabilityPathsForScannerId(capabilityId);
      if (paths.length === 0) continue;
      const evidence = toEvidence(row);
      if (evidence === undefined) continue;
      for (const path of paths) {
        addEvidence(path, 'dsh-trust-check#plugins[0].evidence', evidence);
      }
    }
  }

  // 3) destinations[] are evidence for network.fetch (e.g. egress allowlists).
  const rawDestinations = plugin.destinations;
  if (Array.isArray(rawDestinations)) {
    for (const row of rawDestinations) {
      if (!isPlainObject(row)) continue;
      const value = typeof row.value === 'string' ? row.value.trim() : '';
      if (value === '') continue;
      addDetail('network.fetch', 'dsh-trust-check#plugins[0].destinations', `destination:${destinationHost(value)}`);
      const evidence = toEvidence(row);
      if (evidence !== undefined) {
        addEvidence('network.fetch', 'dsh-trust-check#plugins[0].destinations', evidence);
      }
    }
  }

  // 4) facts[] may carry additional evidence; the id prefix names a scanner id.
  const rawFacts = plugin.facts;
  if (Array.isArray(rawFacts)) {
    for (const row of rawFacts) {
      if (!isPlainObject(row)) continue;
      const id = typeof row.id === 'string' ? row.id : '';
      const prefix = id.split('.')[0] ?? '';
      if (prefix === '') continue;
      const paths = capabilityPathsForScannerId(prefix);
      if (paths.length === 0) continue;
      const factEvidence = Array.isArray(row.evidence) ? row.evidence : [];
      for (const evidenceRow of factEvidence) {
        if (!isPlainObject(evidenceRow)) continue;
        const evidence = toEvidence(evidenceRow);
        if (evidence === undefined) continue;
        for (const path of paths) {
          // Supplement only already-detected capabilities; never invent a fact.
          if (!builders.has(path)) continue;
          addEvidence(path, 'dsh-trust-check#plugins[0].facts', evidence);
        }
      }
      for (const path of paths) {
        if (builders.has(path)) addDetail(path, 'dsh-trust-check#plugins[0].facts', `fact:${id}`);
      }
    }
  }

  // 5) injections[]: prompt/context writes and composition overrides.
  const rawInjections = plugin.injections;
  if (Array.isArray(rawInjections)) {
    for (const row of rawInjections) {
      if (!isPlainObject(row)) continue;
      const kind = typeof row.kind === 'string' ? row.kind : '';
      const detail = typeof row.detail === 'string' ? row.detail.trim() : '';
      const annotatedDetail = detail === '' ? `injection:${kind}` : `injection:${kind}:${detail}`;
      if (kind === 'system-prompt' || kind === 'skill') {
        addDetail('context.prompt_inject', CORDIS_PATCH_FIELD, annotatedDetail);
        addEvidence('context.prompt_inject', CORDIS_PATCH_FIELD, { field: CORDIS_PATCH_FIELD });
      } else if (kind === 'override' || kind === 'disable') {
        addDetail('composition.override', CORDIS_PATCH_FIELD, annotatedDetail);
        addEvidence('composition.override', CORDIS_PATCH_FIELD, { field: CORDIS_PATCH_FIELD });
      } else {
        notes.push(`未知的扫描器注入类型 "${kind}"，已忽略。`);
      }
    }
  }

  // Preserve the scanner's red-line wording apart from URL credentials.
  const rawRedLines = plugin.redLines;
  const redLines: string[] = [];
  if (Array.isArray(rawRedLines)) {
    for (const line of rawRedLines) {
      if (typeof line === 'string') redLines.push(redactUrlCredentials(line));
    }
  }

  // Report-wide coverage/notes are forwarded so the decision stays reviewable.
  for (const [key, value] of [
    ['notes', payload.notes],
    ['coverageNotes', payload.coverageNotes],
  ] as const) {
    if (value === undefined) continue;
    if (!Array.isArray(value)) continue;
    for (const entry of value) {
      if (typeof entry === 'string' && entry !== '') notes.push(redactUrlCredentials(entry));
      else notes.push(`扫描器报告的 ${key} 含非字符串条目，已忽略。`);
    }
  }

  // 7) Finalise: every fact needs some evidence pointer.
  const facts: CapabilityFact[] = [];
  for (const builder of builders.values()) {
    if (builder.evidence.length === 0) {
      builder.evidence.push({ field: builder.fallbackField });
      notes.push(`扫描器能力 ${builder.capability} 没有 file:line 证据行，已改用报告字段指针。`);
    }
    const detail = builder.details.join('; ');
    const fact: CapabilityFact = {
      capability: builder.capability,
      ...(isDeclarable(builder.capability) ? { path: builder.capability } : {}),
      evidence: builder.evidence,
      source,
      heuristic: false,
      ...(detail !== '' ? { detail } : {}),
    };
    facts.push(fact);
  }

  return {
    ok: true,
    scanner,
    facts,
    red_lines: redLines,
    notes,
  };
}

/** Best-effort scanner identity; the payload contract does not require it. */
function readScannerDescriptor(payload: Record<string, unknown>): ExternalScannerDescriptor {
  const rawScanner = isPlainObject(payload.scanner) ? payload.scanner : undefined;
  const rawName = rawScanner?.name;
  const name = typeof rawName === 'string' && rawName.trim() !== '' ? rawName.trim() : SCANNER_BIN;
  const rawVersion =
    typeof payload.scannerVersion === 'string'
      ? payload.scannerVersion
      : typeof rawScanner?.version === 'string'
        ? rawScanner.version
        : undefined;
  const version = rawVersion !== undefined && rawVersion.trim() !== '' ? rawVersion.trim() : undefined;
  return { name, ...(version !== undefined ? { version } : {}), schema_version: SCANNER_SCHEMA_VERSION };
}
