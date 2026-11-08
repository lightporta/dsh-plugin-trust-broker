/**
 * Append-only JSONL helpers.
 *
 * Anchors, decisions and the runtime audit trail are all append-only files of
 * one JSON object per line. Appending is a single `write(2)` against an fd opened
 * with `O_APPEND`, so concurrent writers cannot interleave partial lines on a
 * local filesystem. Readers tolerate a torn final line (crash during write) by
 * reporting it as a parse error instead of discarding the whole file.
 */

import { closeSync, mkdirSync, openSync, readFileSync, existsSync, writeSync, fsyncSync } from 'node:fs';
import { dirname } from 'node:path';
import { errorMessage } from './fs-utils.ts';

export function ensureParentDirSync(file: string): void {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
}

export interface AppendOptions {
  /** Flush to disk before returning. Default false; enable for anchors. */
  fsync?: boolean;
}

/** Append one JSON line. Throws on failure (anchor writes must not be silent). */
export function appendJsonLine(file: string, record: unknown, options: AppendOptions = {}): void {
  ensureParentDirSync(file);
  const line = `${JSON.stringify(record)}\n`;
  const fd = openSync(file, 'a', 0o600);
  try {
    writeSync(fd, line);
    if (options.fsync === true) fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export interface JsonlReadResult {
  records: unknown[];
  errors: Array<{ line: number; message: string }>;
}

/** Read a JSONL file; missing file is an empty result, malformed lines are reported. */
export function readJsonlFile(file: string): JsonlReadResult {
  if (!existsSync(file)) return { records: [], errors: [] };
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    return { records: [], errors: [{ line: 0, message: errorMessage(error) }] };
  }
  const records: unknown[] = [];
  const errors: Array<{ line: number; message: string }> = [];
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index] ?? '';
    if (raw.trim() === '') continue;
    try {
      records.push(JSON.parse(raw) as unknown);
    } catch {
      errors.push({ line: index + 1, message: 'Invalid JSONL record' });
    }
  }
  return { records, errors };
}

/**
 * Long-lived append-only writer for hot paths (runtime audit). Unlike
 * `appendJsonLine` it keeps the fd open; `tryAppend` never throws so a broken
 * audit disk cannot break tool dispatch. Callers must `close()` on disposal.
 */
export class JsonlWriter {
  readonly file: string;
  readonly #fsync: boolean;
  #fd: number | null = null;
  #closed = false;
  #lastError: string | undefined;

  constructor(options: { file: string; fsync?: boolean }) {
    this.file = options.file;
    this.#fsync = options.fsync === true;
  }

  get lastError(): string | undefined {
    return this.#lastError;
  }

  /** Append one record; throws when the write fails. */
  append(record: unknown): void {
    if (this.#closed) throw new Error('JSONL writer is closed');
    const line = `${JSON.stringify(record)}\n`;
    if (this.#closed) throw new Error('JSONL writer is closed');
    if (this.#fd === null) {
      ensureParentDirSync(this.file);
      this.#fd = openSync(this.file, 'a', 0o600);
    }
    writeSync(this.#fd, line);
    if (this.#fsync) fsyncSync(this.#fd);
  }

  /** Append one record, swallowing and recording the error. Returns success. */
  tryAppend(record: unknown): boolean {
    try {
      this.append(record);
      this.#lastError = undefined;
      return true;
    } catch (error) {
      this.#lastError = errorMessage(error);
      return false;
    }
  }

  close(): void {
    this.#closed = true;
    if (this.#fd === null) return;
    try {
      closeSync(this.#fd);
    } catch {
      // Closing a broken fd must not surface during plugin disposal.
    }
    this.#fd = null;
  }
}

/** Map of `line-number -> record` for files where the last write wins per key. */
export function foldJsonlBy<T>(
  file: string,
  pick: (record: unknown) => { key: string; value: T } | undefined,
): { byKey: Map<string, T>; errors: Array<{ line: number; message: string }> } {
  const { records, errors } = readJsonlFile(file);
  const byKey = new Map<string, T>();
  for (const record of records) {
    const picked = pick(record);
    if (picked !== undefined) byKey.set(picked.key, picked.value);
  }
  return { byKey, errors };
}
