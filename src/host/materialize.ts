/**
 * Candidate acquisition for the pre-install review Host service.
 *
 * This module turns a parsed candidate spec into a directory the trust broker
 * can inspect, without ever trusting the acquired bytes:
 *
 * - npm: resolve the exact version from registry metadata, download the tarball
 *   with a timeout and a hard size cap, verify the registry integrity digest,
 *   then unpack it with a local tar reader (node:zlib only, no shell binaries).
 * - git: shallow-clone with argument-vector `spawn` (never a shell), then remove
 *   `.git` so the reviewed tree is the working tree only.
 * - tarball: download or read a local archive, verify size caps, unpack safely.
 * - local: review the directory in place; nothing is copied and nothing is
 *   deleted.
 *
 * The tar reader is deliberately strict and fail-closed: absolute paths, `..`
 * traversal, NUL/control characters, duplicate entries, symlinks, hardlinks,
 * devices and FIFOs are all rejected. Only regular files and directories are
 * ever written, always inside the private candidate directory.
 *
 * Every acquired tree lives under `<storeDir>/candidates/review-*` (mode 0700)
 * and is removed on failure, eviction or service disposal.
 */

import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, rm, rmdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { gunzipSync } from 'node:zlib';

import { errorMessage, redactUrlCredentials, sha256Hex } from '../core/fs-utils.ts';
import { MAX_PACKAGE_JSON_BYTES } from '../core/manifest.ts';
import type { HostErrorCode, ParsedCandidateSpec } from './spec.ts';
import { HostError, isHostError } from './spec.ts';

/** Registry used when the caller does not override it. */
export const DEFAULT_REGISTRY = 'https://registry.npmjs.org';

/** Hard cap for one downloaded/read tarball: 64 MiB. */
export const MAX_TARBALL_BYTES = 64 * 1024 * 1024;

/** Hard cap for a decompressed archive tree: 256 MiB. */
export const MAX_EXTRACTED_BYTES = 256 * 1024 * 1024;

/** Maximum number of archive entries processed in one extraction. */
export const MAX_ARCHIVE_ENTRIES = 10_000;

/** Maximum byte length of one archived relative path. */
export const MAX_ARCHIVE_PATH_BYTES = 1024;

/** Network timeout for registry and tarball requests: 60 s. */
export const REQUEST_TIMEOUT_MS = 60_000;

/** Timeout for one `git clone`: 120 s. */
export const GIT_CLONE_TIMEOUT_MS = 120_000;

/** Hard cap for one registry metadata document: 16 MiB. */
export const REGISTRY_METADATA_MAX_BYTES = 16 * 1024 * 1024;

const EMPTY_ARCHIVE_ENTRY = new Uint8Array(0);
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

/* ------------------------------------------------------------------------- */
/* Candidate workspace (private temp dirs under the store)                    */
/* ------------------------------------------------------------------------- */

/** Per-service owner of candidate directories; `dispose()` removes all of them. */
export interface CandidateWorkspace {
  /** Absolute directory holding candidate temp dirs (`<storeDir>/candidates`). */
  readonly root: string;
  createCandidateDir(): Promise<string>;
  releaseDir(directory: string): Promise<void>;
  dispose(): Promise<void>;
}

/** Create a candidate workspace under `<storeDir>/candidates`. */
export function createCandidateWorkspace(storeDir: string, candidatesDir?: string): CandidateWorkspace {
  const root = resolve(candidatesDir ?? join(storeDir, 'candidates'));
  const rootWithSep = `${root}${sep}`;
  const tracked = new Set<string>();
  let disposed = false;

  async function ensureRoot(): Promise<void> {
    await mkdir(root, { recursive: true, mode: 0o700 });
  }

  return {
    root,
    async createCandidateDir(): Promise<string> {
      if (disposed) throw new HostError('internal_error', '审查工作区已清理（服务已卸载）。');
      await ensureRoot();
      const directory = await mkdtemp(join(root, 'review-'));
      tracked.add(directory);
      return directory;
    },
    async releaseDir(directory: string): Promise<void> {
      const target = resolve(directory);
      // Defense in depth: only remove directories this workspace created.
      if (!tracked.has(target) || !target.startsWith(rootWithSep)) return;
      tracked.delete(target);
      await rm(target, { recursive: true, force: true });
    },
    async dispose(): Promise<void> {
      disposed = true;
      const directories = [...tracked];
      tracked.clear();
      await Promise.allSettled(directories.map((directory) => rm(directory, { recursive: true, force: true })));
      try {
        await rmdir(root);
      } catch {
        // Non-empty or already gone: leave it alone.
      }
    },
  };
}

/* ------------------------------------------------------------------------- */
/* Semver resolution (small, dependency-free, common npm ranges only)         */
/* ------------------------------------------------------------------------- */

/** Parsed semver version with an optional prerelease identifier list. */
export interface SemverVersion {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly prerelease: readonly string[];
}

/** Comparison operators the range resolver understands. */
export type ComparatorOperator = '>=' | '>' | '<=' | '<' | '=';

/** One range comparator, e.g. `>=1.2.0`. */
export interface SemverComparator {
  readonly op: ComparatorOperator;
  readonly version: SemverVersion;
}

/** One AND-group of comparators (`||` unions hold several sets). */
export type ComparatorSet = readonly SemverComparator[];

function makeVersion(major: number, minor: number, patch: number, prerelease: readonly string[] = []): SemverVersion {
  return { major, minor, patch, prerelease };
}

/** Parse a full `x.y.z[-pre][+build]` version; partial versions return `undefined`. */
export function parseSemver(input: string): SemverVersion | undefined {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(input.trim());
  if (match === null) return undefined;
  const major = match[1];
  const minor = match[2];
  const patch = match[3];
  if (major === undefined || minor === undefined || patch === undefined) return undefined;
  const prerelease = match[4] === undefined ? [] : match[4].split('.');
  if (prerelease.some((identifier) => identifier === '' || !/^[0-9A-Za-z-]+$/.test(identifier))) {
    return undefined;
  }
  return makeVersion(Number(major), Number(minor), Number(patch), prerelease);
}

/** Standard semver ordering (build metadata is ignored). */
export function compareSemver(left: SemverVersion, right: SemverVersion): number {
  const byNumber = left.major - right.major || left.minor - right.minor || left.patch - right.patch;
  if (byNumber !== 0) return byNumber;
  const leftPre = left.prerelease;
  const rightPre = right.prerelease;
  if (leftPre.length === 0 && rightPre.length === 0) return 0;
  if (leftPre.length === 0) return 1;
  if (rightPre.length === 0) return -1;
  const length = Math.min(leftPre.length, rightPre.length);
  for (let index = 0; index < length; index += 1) {
    const a = leftPre[index] ?? '';
    const b = rightPre[index] ?? '';
    const aNumeric = /^\d+$/.test(a);
    const bNumeric = /^\d+$/.test(b);
    if (aNumeric && bNumeric) {
      const diff = Number(a) - Number(b);
      if (diff !== 0) return diff;
    } else if (aNumeric) {
      return -1;
    } else if (bNumeric) {
      return 1;
    } else if (a !== b) {
      return a < b ? -1 : 1;
    }
  }
  return leftPre.length - rightPre.length;
}

interface PartialVersion {
  readonly version: SemverVersion;
  /** Number of numeric components supplied: 0 = wildcard, 1 = major, … */
  readonly precision: 0 | 1 | 2 | 3;
  readonly any: boolean;
}

function parsePartialVersion(input: string): PartialVersion | undefined {
  const withoutV = input.trim().replace(/^[v=]/, '');
  const plus = withoutV.indexOf('+');
  const text = plus >= 0 ? withoutV.slice(0, plus) : withoutV;
  const match = /^(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?$/.exec(text);
  if (match === null) return undefined;
  const numbers: number[] = [];
  for (const segment of [match[1], match[2], match[3]]) {
    if (segment === undefined) break;
    if (/^[xX*]$/.test(segment)) break;
    numbers.push(Number(segment));
  }
  if (numbers.length === 0) return { version: makeVersion(0, 0, 0), precision: 0, any: true };
  const prerelease = match[4] === undefined ? [] : match[4].split('.');
  const precision = numbers.length as 1 | 2 | 3;
  return {
    version: makeVersion(numbers[0] ?? 0, numbers[1] ?? 0, numbers[2] ?? 0, prerelease),
    precision,
    any: false,
  };
}

function bumpUpper(version: SemverVersion, precision: 1 | 2): SemverVersion {
  return precision === 1 ? makeVersion(version.major + 1, 0, 0) : makeVersion(version.major, version.minor + 1, 0);
}

function exactComparators(base: SemverVersion, precision: 0 | 1 | 2 | 3): ComparatorSet {
  if (precision >= 3) return [{ op: '=', version: base }];
  const upper = bumpUpper(base, precision === 1 ? 1 : 2);
  return [
    { op: '>=', version: base },
    { op: '<', version: upper },
  ];
}

function caretComparators(base: SemverVersion, precision: 0 | 1 | 2 | 3): ComparatorSet {
  let upper: SemverVersion;
  if (precision === 0 || precision === 1) {
    upper = makeVersion(base.major + 1, 0, 0);
  } else if (base.major > 0) {
    upper = makeVersion(base.major + 1, 0, 0);
  } else if (precision === 2 || base.minor > 0) {
    upper = makeVersion(0, base.minor + 1, 0);
  } else {
    upper = makeVersion(0, 0, base.patch + 1);
  }
  return [
    { op: '>=', version: base },
    { op: '<', version: upper },
  ];
}

function tildeComparators(base: SemverVersion, precision: 0 | 1 | 2 | 3): ComparatorSet {
  const upper = precision <= 1 ? makeVersion(base.major + 1, 0, 0) : makeVersion(base.major, base.minor + 1, 0);
  return [
    { op: '>=', version: base },
    { op: '<', version: upper },
  ];
}

function expandComparatorToken(token: string): ComparatorSet | undefined {
  const match = /^(>=|<=|>|<|=|\^|~)?(.+)$/.exec(token);
  if (match === null) return undefined;
  const operator = match[1] ?? '';
  const partial = parsePartialVersion(match[2] ?? '');
  if (partial === undefined) return undefined;
  if (partial.any) return [{ op: '>=', version: makeVersion(0, 0, 0) }];
  const base = partial.version;
  const precision = partial.precision;
  switch (operator) {
    case '':
    case '=':
      return exactComparators(base, precision);
    case '>=':
      return [{ op: '>=', version: base }];
    case '>':
      if (precision >= 3) return [{ op: '>', version: base }];
      return [{ op: '>=', version: bumpUpper(base, precision === 1 ? 1 : 2) }];
    case '<':
      return [{ op: '<', version: base }];
    case '<=':
      if (precision >= 3) return [{ op: '<=', version: base }];
      return [{ op: '<', version: bumpUpper(base, precision === 1 ? 1 : 2) }];
    case '^':
      return caretComparators(base, precision);
    case '~':
      return tildeComparators(base, precision);
    default:
      return undefined;
  }
}

/**
 * Parse a common npm range (`^ ~ >= > <= < = * x ||` and hyphen ranges).
 * Returns `undefined` for anything unsupported so callers can fall back to
 * dist-tags.latest instead of silently mis-resolving.
 */
export function parseSemverRange(range: string): readonly ComparatorSet[] | undefined {
  const sets: ComparatorSet[] = [];
  for (const part of range.split('||')) {
    const text = part.trim();
    if (text === '') return undefined;
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(text);
    if (hyphen !== null) {
      const lower = parsePartialVersion(hyphen[1] ?? '');
      const upper = parsePartialVersion(hyphen[2] ?? '');
      if (lower === undefined || upper === undefined) return undefined;
      const set: SemverComparator[] = [{ op: '>=', version: lower.version }];
      if (!upper.any) {
        if (upper.precision >= 3) set.push({ op: '<=', version: upper.version });
        else set.push({ op: '<', version: bumpUpper(upper.version, upper.precision === 1 ? 1 : 2) });
      }
      sets.push(set);
      continue;
    }
    const set: SemverComparator[] = [];
    for (const token of text.split(/\s+/).filter((entry) => entry !== '')) {
      const expanded = expandComparatorToken(token);
      if (expanded === undefined) return undefined;
      set.push(...expanded);
    }
    if (set.length === 0) return undefined;
    sets.push(set);
  }
  return sets.length === 0 ? undefined : sets;
}

function testComparator(candidate: SemverVersion, comparator: SemverComparator): boolean {
  const difference = compareSemver(candidate, comparator.version);
  switch (comparator.op) {
    case '>':
      return difference > 0;
    case '>=':
      return difference >= 0;
    case '<':
      return difference < 0;
    case '<=':
      return difference <= 0;
    case '=':
      return difference === 0;
  }
}

/** True when `candidate` satisfies an already-parsed range (semver prerelease rule). */
export function satisfiesSemverRange(candidate: SemverVersion, sets: readonly ComparatorSet[]): boolean {
  for (const set of sets) {
    if (!set.every((comparator) => testComparator(candidate, comparator))) continue;
    if (candidate.prerelease.length > 0) {
      const allowsPrerelease = set.some(
        (comparator) =>
          comparator.version.prerelease.length > 0 &&
          comparator.version.major === candidate.major &&
          comparator.version.minor === candidate.minor &&
          comparator.version.patch === candidate.patch,
      );
      if (!allowsPrerelease) continue;
    }
    return true;
  }
  return false;
}

/* ------------------------------------------------------------------------- */
/* Tar reading and extraction                                                 */
/* ------------------------------------------------------------------------- */

/** Limits applied to one archive extraction. */
export interface ExtractLimits {
  maxEntries?: number;
  maxTotalBytes?: number;
  maxFileBytes?: number;
  maxPathBytes?: number;
}

/** Result of one successful extraction. */
export interface ExtractResult {
  files: number;
  bytes: number;
}

interface TarEntryDraft {
  readonly name: string;
  readonly isDirectory: boolean;
  readonly data: Uint8Array;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** One-line, control-character-free text safe for wire error messages. */
function sanitizeMessage(input: string, maxLength = 300): string {
  const cleaned = input
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return cleaned.length <= maxLength ? cleaned : `${cleaned.slice(0, Math.max(0, maxLength - 1))}…`;
}

function unsafeArchiveEntry(message: string): HostError {
  return new HostError('unsafe_archive_entry', message);
}

function safeName(name: string): string {
  return sanitizeMessage(name, 120);
}

function decodeUtf8(bytes: Uint8Array, what: string): string {
  try {
    return UTF8_DECODER.decode(bytes);
  } catch {
    throw unsafeArchiveEntry(`归档${what}不是合法 UTF-8。`);
  }
}

function isZeroBlock(buffer: Uint8Array, offset: number): boolean {
  if (offset + 512 > buffer.length) return false;
  for (let index = offset; index < offset + 512; index += 1) {
    if (buffer[index] !== 0) return false;
  }
  return true;
}

function tarString(header: Uint8Array, offset: number, length: number): string {
  const slice = header.subarray(offset, offset + length);
  const nul = slice.indexOf(0);
  const end = nul === -1 ? slice.length : nul;
  return decodeUtf8(slice.subarray(0, end), ' 头部字符串');
}

function parseTarOctal(header: Uint8Array, offset: number, length: number): number | undefined {
  const slice = header.subarray(offset, offset + length);
  let text = '';
  for (const byte of slice) {
    if (byte === 0 || byte === 0x20) {
      if (text === '') continue;
      break;
    }
    text += String.fromCharCode(byte);
  }
  if (text === '') return 0;
  if (!/^[0-7]+$/.test(text)) return undefined;
  return Number.parseInt(text, 8);
}

function tarHeaderChecksum(header: Uint8Array): number {
  let sum = 0;
  for (let index = 0; index < 512; index += 1) {
    sum += index >= 148 && index < 156 ? 0x20 : (header[index] ?? 0);
  }
  return sum;
}

function trailingNulTrimmed(data: Uint8Array): Uint8Array {
  let end = data.length;
  while (end > 0 && data[end - 1] === 0) end -= 1;
  return data.subarray(0, end);
}

function stripTrailingSlashes(name: string): string {
  let end = name.length;
  while (end > 0 && name[end - 1] === '/') end -= 1;
  return name.slice(0, end);
}

/** Parse PAX extended-header records (`<length> <key>=<value>\n`). */
function parsePaxRecords(data: Uint8Array): Map<string, string> {
  const records = new Map<string, string>();
  let offset = 0;
  while (offset < data.length) {
    if (data[offset] === 0) break;
    const space = data.indexOf(0x20, offset);
    if (space < 0 || space === offset || space - offset > 20) {
      throw unsafeArchiveEntry('归档 PAX 扩展头格式非法。');
    }
    const lengthText = decodeUtf8(data.subarray(offset, space), ' PAX 长度');
    if (!/^\d+$/.test(lengthText)) throw unsafeArchiveEntry('归档 PAX 扩展头长度非法。');
    const length = Number(lengthText);
    if (length <= space - offset + 1 || offset + length > data.length) {
      throw unsafeArchiveEntry('归档 PAX 扩展头越界。');
    }
    const record = decodeUtf8(data.subarray(space + 1, offset + length), ' PAX 记录');
    const body = record.endsWith('\n') ? record.slice(0, -1) : record;
    const equals = body.indexOf('=');
    if (equals <= 0) throw unsafeArchiveEntry('归档 PAX 扩展头记录非法。');
    const key = body.slice(0, equals);
    if (key === 'path' || key === 'linkpath' || key === 'size') {
      records.set(key, body.slice(equals + 1));
    }
    offset += length;
  }
  return records;
}

/** Validate one archive-relative path and return its segments. */
function validateArchivePath(name: string, maxPathBytes: number): string[] {
  if (name === '') throw unsafeArchiveEntry('归档包含空路径条目。');
  if (name.startsWith('/') || /^[A-Za-z]:[\\/]/.test(name)) {
    throw unsafeArchiveEntry(`归档包含绝对路径（不允许）：${safeName(name)}`);
  }
  if (name.includes('\\')) {
    throw unsafeArchiveEntry(`归档路径包含反斜杠（不允许）：${safeName(name)}`);
  }
  if (/[\u0000-\u001f\u007f]/.test(name)) {
    throw unsafeArchiveEntry('归档路径包含 NUL/控制字符（不允许）。');
  }
  if (Buffer.byteLength(name, 'utf8') > maxPathBytes) {
    throw unsafeArchiveEntry('归档路径过长，已拒绝。');
  }
  const segments = name.split('/');
  for (const segment of segments) {
    if (segment === '') throw unsafeArchiveEntry(`归档路径包含空路径段：${safeName(name)}`);
    if (segment === '.') throw unsafeArchiveEntry(`归档路径包含 . 路径段：${safeName(name)}`);
    if (segment === '..') {
      throw unsafeArchiveEntry(`归档包含 .. 路径穿越（不允许）：${safeName(name)}`);
    }
  }
  return segments;
}

interface ParseLimits {
  readonly maxEntries: number;
  readonly maxTotalBytes: number;
  readonly maxFileBytes: number;
  readonly maxPathBytes: number;
}

/** Walk the uncompressed tar stream and reject any unsafe entry. */
function parseTarEntries(buffer: Uint8Array, limits: ParseLimits): TarEntryDraft[] {
  const drafts: TarEntryDraft[] = [];
  let offset = 0;
  let totalBytes = 0;
  let paxOverrides: Map<string, string> | undefined;
  let longName: string | undefined;

  while (offset < buffer.length) {
    if (offset + 512 > buffer.length) {
      throw unsafeArchiveEntry('归档尾部数据不完整。');
    }
    if (isZeroBlock(buffer, offset)) {
      for (let index = offset; index < buffer.length; index += 1) {
        if (buffer[index] !== 0) throw unsafeArchiveEntry('归档结束标记之后仍包含数据。');
      }
      break;
    }
    const header = buffer.subarray(offset, offset + 512);
    const storedChecksum = parseTarOctal(header, 148, 8);
    if (storedChecksum === undefined || tarHeaderChecksum(header) !== storedChecksum) {
      throw unsafeArchiveEntry('归档头部校验和不匹配（归档可能损坏或被篡改）。');
    }
    const typeFlagByte = header[156] ?? 0;
    const typeFlag = typeFlagByte === 0 ? '0' : String.fromCharCode(typeFlagByte);
    const name = tarString(header, 0, 100);
    const prefix = tarString(header, 345, 155);
    const declaredSize = parseTarOctal(header, 124, 12);
    if (declaredSize === undefined) throw unsafeArchiveEntry('归档条目大小字段非法。');
    const dataStart = offset + 512;
    if (dataStart + declaredSize > buffer.length) {
      throw unsafeArchiveEntry('归档条目数据被截断。');
    }
    const advance = (payloadSize: number): void => {
      let next = dataStart + payloadSize;
      const remainder = next % 512;
      if (remainder !== 0) next += 512 - remainder;
      offset = next;
    };

    if (typeFlag === 'x' || typeFlag === 'g') {
      const records = parsePaxRecords(buffer.subarray(dataStart, dataStart + declaredSize));
      if (typeFlag === 'x') paxOverrides = records;
      advance(declaredSize);
      continue;
    }
    if (typeFlag === 'L') {
      longName = decodeUtf8(trailingNulTrimmed(buffer.subarray(dataStart, dataStart + declaredSize)), ' 长文件名');
      advance(declaredSize);
      continue;
    }
    if (typeFlag === 'K' || typeFlag === 'V') {
      // Long link target / volume header: links are rejected below, volume
      // headers carry no tree content.
      advance(declaredSize);
      continue;
    }

    const overridePath = paxOverrides?.get('path');
    const overrideSize = paxOverrides?.get('size');
    const effectiveName = overridePath ?? longName ?? (prefix === '' ? name : `${prefix}/${name}`);
    let effectiveSize = declaredSize;
    if (overrideSize !== undefined) {
      if (!/^\d+$/.test(overrideSize)) throw unsafeArchiveEntry('归档 PAX 大小记录非法。');
      effectiveSize = Number(overrideSize);
      if (dataStart + effectiveSize > buffer.length) throw unsafeArchiveEntry('归档条目数据被截断。');
    }
    paxOverrides = undefined;
    longName = undefined;

    const isDirectory = typeFlag === '5' || effectiveName.endsWith('/');
    if (isDirectory) {
      const directoryName = stripTrailingSlashes(effectiveName);
      if (directoryName === '') {
        if (effectiveName !== '/' && effectiveName !== './' && effectiveName !== '.') {
          throw unsafeArchiveEntry('归档包含非法根目录条目。');
        }
      } else {
        validateArchivePath(directoryName, limits.maxPathBytes);
        if (drafts.length >= limits.maxEntries) throw unsafeArchiveEntry('归档条目数量超过上限。');
        drafts.push({ name: directoryName, isDirectory: true, data: EMPTY_ARCHIVE_ENTRY });
      }
      advance(declaredSize);
      continue;
    }

    switch (typeFlag) {
      case '0':
      case '7': {
        if (effectiveSize > limits.maxFileBytes) {
          throw new HostError(
            'candidate_too_large',
            `归档内单个文件超过 ${formatMiB(limits.maxFileBytes)} 上限。`,
          );
        }
        totalBytes += effectiveSize;
        if (totalBytes > limits.maxTotalBytes) {
          throw new HostError(
            'candidate_too_large',
            `归档解压后总大小超过 ${formatMiB(limits.maxTotalBytes)} 上限。`,
          );
        }
        if (drafts.length >= limits.maxEntries) throw unsafeArchiveEntry('归档条目数量超过上限。');
        drafts.push({
          name: effectiveName,
          isDirectory: false,
          data: buffer.subarray(dataStart, dataStart + effectiveSize),
        });
        advance(effectiveSize);
        continue;
      }
      case '1':
        throw unsafeArchiveEntry(`归档包含硬链接条目（不允许）：${safeName(effectiveName)}`);
      case '2':
        throw unsafeArchiveEntry(`归档包含符号链接条目（不允许）：${safeName(effectiveName)}`);
      case '3':
      case '4':
        throw unsafeArchiveEntry(`归档包含设备文件条目（不允许）：${safeName(effectiveName)}`);
      case '6':
        throw unsafeArchiveEntry(`归档包含 FIFO 条目（不允许）：${safeName(effectiveName)}`);
      default:
        throw unsafeArchiveEntry(
          `归档包含不支持的条目类型（typeflag ${String.fromCharCode(typeFlagByte)}）。`,
        );
    }
  }
  return drafts;
}

function formatMiB(bytes: number): string {
  return `${Math.round(bytes / 1024 / 1024)} MiB`;
}

function isOutputLimitError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === 'ERR_BUFFER_TOO_LARGE';
}

/**
 * Safely extract a gzip-compressed tar archive into an empty directory.
 *
 * Rejects (fail-closed): absolute paths, `..` traversal, NUL/control chars,
 * backslashes, duplicate paths, symlinks, hardlinks, devices, FIFOs, unknown
 * types, truncated/oversized archives, and any path that would resolve outside
 * `destination`. The leading npm `package/` component is stripped when every
 * entry lives under it.
 */
export async function extractTarball(
  bytes: Uint8Array,
  destination: string,
  limits: ExtractLimits = {},
): Promise<ExtractResult> {
  const maxEntries = limits.maxEntries ?? MAX_ARCHIVE_ENTRIES;
  const maxTotalBytes = limits.maxTotalBytes ?? MAX_EXTRACTED_BYTES;
  const maxFileBytes = limits.maxFileBytes ?? MAX_TARBALL_BYTES;
  const maxPathBytes = limits.maxPathBytes ?? MAX_ARCHIVE_PATH_BYTES;

  let decompressed: Buffer;
  try {
    decompressed = gunzipSync(bytes, { maxOutputLength: maxTotalBytes });
  } catch (error) {
    if (isOutputLimitError(error)) {
      throw new HostError(
        'candidate_too_large',
        `归档解压后超过 ${formatMiB(maxTotalBytes)} 上限。`,
      );
    }
    throw new HostError(
      'materialize_failed',
      `归档不是合法的 gzip 数据：${sanitizeMessage(errorMessage(error), 160)}`,
    );
  }

  const drafts = parseTarEntries(new Uint8Array(decompressed), {
    maxEntries,
    maxTotalBytes,
    maxFileBytes,
    maxPathBytes,
  });
  const underPackageRoot =
    drafts.length > 0 &&
    drafts.every((entry) => entry.name === 'package' || entry.name.startsWith('package/'));
  const seen = new Set<string>();
  const planned: Array<{ relativePath: string; segments: string[]; isDirectory: boolean; data: Uint8Array }> = [];
  let fileCount = 0;
  let byteCount = 0;
  for (const draft of drafts) {
    let name = draft.name;
    if (underPackageRoot) {
      if (name === 'package') {
        // The npm root directory entry is dropped; a regular file literally
        // named `package` is kept at the archive root instead of vanishing.
        if (draft.isDirectory) continue;
      } else {
        name = name.slice('package/'.length);
      }
    }
    if (name === '') continue;
    const segments = validateArchivePath(name, maxPathBytes);
    const relativePath = segments.join('/');
    if (seen.has(relativePath)) {
      throw unsafeArchiveEntry(`归档包含重复路径（不允许）：${safeName(relativePath)}`);
    }
    seen.add(relativePath);
    if (!draft.isDirectory) {
      fileCount += 1;
      byteCount += draft.data.byteLength;
    }
    planned.push({ relativePath, segments, isDirectory: draft.isDirectory, data: draft.data });
  }
  if (planned.length === 0) throw unsafeArchiveEntry('归档不包含任何可写条目。');

  const destinationRoot = resolve(destination);
  const rootWithSep = destinationRoot.endsWith(sep) ? destinationRoot : destinationRoot + sep;
  await mkdir(destinationRoot, { recursive: true, mode: 0o700 });
  for (const entry of planned) {
    const target = resolve(destinationRoot, entry.relativePath);
    if (target !== destinationRoot && !target.startsWith(rootWithSep)) {
      throw unsafeArchiveEntry(`归档条目解析到候选目录之外（不允许）：${safeName(entry.relativePath)}`);
    }
    try {
      if (entry.isDirectory) {
        await mkdir(target, { recursive: true, mode: 0o700 });
        continue;
      }
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, entry.data, { flag: 'wx', mode: 0o600 });
    } catch (error) {
      if (isHostError(error)) throw error;
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EEXIST' || code === 'ENOTDIR' || code === 'EISDIR') {
        throw unsafeArchiveEntry(`归档条目与目录结构冲突：${safeName(entry.relativePath)}`);
      }
      throw new HostError(
        'materialize_failed',
        `写入候选文件失败：${sanitizeMessage(errorMessage(error), 160)}`,
      );
    }
  }
  return { files: fileCount, bytes: byteCount };
}

/* ------------------------------------------------------------------------- */
/* HTTP helpers                                                               */
/* ------------------------------------------------------------------------- */

interface HttpOptions {
  readonly fetchImpl: typeof fetch;
  readonly signal?: AbortSignal;
  readonly timeoutMs: number;
}

async function httpRequest(
  url: string,
  init: RequestInit,
  options: HttpOptions,
  errorCode: HostErrorCode,
): Promise<Response> {
  options.signal?.throwIfAborted();
  const timeoutSignal = AbortSignal.timeout(options.timeoutMs);
  const signal = options.signal === undefined ? timeoutSignal : AbortSignal.any([options.signal, timeoutSignal]);
  try {
    return await options.fetchImpl(url, { ...init, signal, redirect: 'follow' });
  } catch (error) {
    if (options.signal?.aborted) throw new HostError('aborted', '审查已取消。');
    if (timeoutSignal.aborted) {
      throw new HostError(errorCode, `网络请求超时（${Math.round(options.timeoutMs / 1000)} 秒）。`);
    }
    throw new HostError(errorCode, `网络请求失败：${sanitizeMessage(errorMessage(error), 200)}`);
  }
}

async function readResponseBytes(
  response: Response,
  maxBytes: number,
  label: string,
): Promise<Uint8Array> {
  const contentLength = Number(response.headers.get('content-length') ?? Number.NaN);
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    throw new HostError('candidate_too_large', `${label}超过 ${formatMiB(maxBytes)} 上限。`);
  }
  if (response.body === null) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maxBytes) {
      throw new HostError('candidate_too_large', `${label}超过 ${formatMiB(maxBytes)} 上限。`);
    }
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new HostError('candidate_too_large', `${label}超过 ${formatMiB(maxBytes)} 上限。`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

/**
 * Validate and normalize an npm registry base URL.
 * Credentials in the registry URL are rejected so they can never leak into a
 * displayed candidate or an error message.
 */
export function normalizeRegistryBase(input: string): string {
  const trimmed = (typeof input === 'string' ? input : '').trim().replace(/\/+$/, '');
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new HostError('invalid_spec', 'registry 地址无效，请提供 http(s) 地址。');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new HostError('invalid_spec', 'registry 地址必须是 http(s) URL。');
  }
  if (url.username !== '' || url.password !== '') {
    throw new HostError('invalid_spec', 'registry 地址不得包含凭据。');
  }
  if (url.search !== '' || url.hash !== '') {
    throw new HostError('invalid_spec', 'registry 地址不能包含查询参数或片段。');
  }
  return `${url.protocol}//${url.host}${url.pathname === '/' ? '' : url.pathname}`;
}

/* ------------------------------------------------------------------------- */
/* npm registry resolution                                                    */
/* ------------------------------------------------------------------------- */

export interface NpmVersionMetadata {
  readonly name?: unknown;
  readonly version?: unknown;
  readonly dist?: unknown;
  readonly repository?: unknown;
  readonly scripts?: unknown;
}

export interface NpmPackument {
  readonly name?: unknown;
  readonly 'dist-tags'?: unknown;
  readonly versions?: unknown;
}

const NPM_ACCEPT_HEADERS: readonly string[] = [
  'application/vnd.npm.install-v1+json',
  'application/json',
];

function versionMetadataMap(packument: NpmPackument): Record<string, NpmVersionMetadata> {
  const versions = packument.versions;
  if (!isRecord(versions)) return {};
  const output: Record<string, NpmVersionMetadata> = {};
  for (const [version, metadata] of Object.entries(versions)) {
    if (isRecord(metadata)) output[version] = metadata;
  }
  return output;
}

function distTagMap(packument: NpmPackument): Record<string, string> {
  const tags = packument['dist-tags'];
  if (!isRecord(tags)) return {};
  const output: Record<string, string> = {};
  for (const [tag, version] of Object.entries(tags)) {
    if (typeof version === 'string' && version !== '') output[tag] = version;
  }
  return output;
}

function encodePackageName(name: string): string {
  if (!name.startsWith('@')) return encodeURIComponent(name);
  const slash = name.indexOf('/');
  if (slash < 0) return encodeURIComponent(name);
  // npm clients keep the leading `@` literal: `@scope%2Fname`.
  return `@${encodeURIComponent(name.slice(1, slash))}%2F${encodeURIComponent(name.slice(slash + 1))}`;
}

async function fetchPackument(name: string, registryBase: string, options: HttpOptions): Promise<NpmPackument> {
  const url = `${registryBase}/${encodePackageName(name)}`;
  let lastError: HostError | undefined;
  for (const accept of NPM_ACCEPT_HEADERS) {
    try {
      const response = await httpRequest(
        url,
        { headers: { accept } },
        options,
        'registry_unreachable',
      );
      if (response.status === 404) {
        await response.body?.cancel().catch(() => undefined);
        lastError = new HostError(
          'version_not_found',
          `registry 中找不到包 ${sanitizeMessage(name, 120)}。`,
        );
        continue;
      }
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        lastError = new HostError('registry_unreachable', `registry 返回 HTTP ${response.status}。`);
        continue;
      }
      const bytes = await readResponseBytes(response, REGISTRY_METADATA_MAX_BYTES, 'registry 元数据');
      let parsed: unknown;
      try {
        parsed = JSON.parse(decodeText(bytes));
      } catch {
        lastError = new HostError('registry_unreachable', 'registry 元数据不是合法 JSON。');
        continue;
      }
      if (!isRecord(parsed)) {
        lastError = new HostError('registry_unreachable', 'registry 元数据格式无效。');
        continue;
      }
      const packument = parsed as NpmPackument;
      if (!isRecord(packument.versions)) {
        lastError = new HostError('registry_unreachable', 'registry 元数据缺少 versions 字段。');
        continue;
      }
      return packument;
    } catch (error) {
      if (isHostError(error)) {
        if (error.code === 'aborted' || error.code === 'candidate_too_large') throw error;
        lastError = error;
        continue;
      }
      lastError = new HostError(
        'registry_unreachable',
        `无法访问 registry：${sanitizeMessage(errorMessage(error), 200)}`,
      );
    }
  }
  throw lastError ?? new HostError('registry_unreachable', '无法访问 registry。');
}

function decodeText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8').decode(bytes);
}

/** Result of resolving a requested npm version/range/tag. */
export interface ResolvedNpmVersion {
  version: string;
  note?: string;
}

/**
 * Resolve the exact version to review.
 *
 * Order: exact version present in `versions`, dist-tag, then a small semver
 * range match. Ranges the local resolver does not understand fall back to
 * `dist-tags.latest` with an explicit note instead of failing the review.
 */
export function resolveNpmVersion(packument: NpmPackument, range?: string): ResolvedNpmVersion {
  const tags = distTagMap(packument);
  const versions = versionMetadataMap(packument);
  const parsedVersions = new Map<string, SemverVersion>();
  for (const version of Object.keys(versions)) {
    const parsed = parseSemver(version);
    if (parsed !== undefined) parsedVersions.set(version, parsed);
  }
  const latest = (): string | undefined => {
    const fromTag = tags.latest;
    if (fromTag !== undefined) return fromTag;
    const sorted = [...parsedVersions.entries()].sort((left, right) =>
      compareSemver(right[1], left[1]),
    );
    return sorted[0]?.[0];
  };

  const requested = range?.trim() ?? '';
  if (requested === '' || requested === '*' || /^[xX]$/.test(requested)) {
    const resolved = latest();
    if (resolved === undefined) {
      throw new HostError('version_not_found', 'registry 元数据中没有可用版本。');
    }
    return { version: resolved };
  }
  if (versions[requested] !== undefined) return { version: requested };
  const tagged = tags[requested];
  if (tagged !== undefined) return { version: tagged };

  const parsedRange = parseSemverRange(requested);
  if (parsedRange === undefined) {
    const resolved = latest();
    if (resolved === undefined) {
      throw new HostError('version_not_found', 'registry 元数据中没有可用版本。');
    }
    return {
      version: resolved,
      note: `无法解析版本范围「${sanitizeMessage(requested, 60)}」，已回退到 dist-tags.latest 的 ${resolved}。`,
    };
  }
  const matching = [...parsedVersions.entries()].filter(([, version]) =>
    satisfiesSemverRange(version, parsedRange),
  );
  if (matching.length === 0) {
    throw new HostError(
      'version_not_found',
      `没有满足版本范围「${sanitizeMessage(requested, 60)}」的已发布版本。`,
    );
  }
  matching.sort((left, right) => compareSemver(right[1], left[1]));
  const best = matching[0];
  if (best === undefined) {
    throw new HostError('version_not_found', '没有满足版本范围的已发布版本。');
  }
  return { version: best[0] };
}

function distOf(metadata: NpmVersionMetadata): Record<string, unknown> | undefined {
  return isRecord(metadata.dist) ? metadata.dist : undefined;
}

function tarballUrlOf(metadata: NpmVersionMetadata): string | undefined {
  const tarball = distOf(metadata)?.tarball;
  if (typeof tarball !== 'string' || !/^https?:\/\//i.test(tarball)) return undefined;
  return tarball;
}

function integrityOf(metadata: NpmVersionMetadata): string | undefined {
  const integrity = distOf(metadata)?.integrity;
  return typeof integrity === 'string' && integrity.trim() !== '' ? integrity.trim() : undefined;
}

function shasumOf(metadata: NpmVersionMetadata): string | undefined {
  const shasum = distOf(metadata)?.shasum;
  return typeof shasum === 'string' && /^[0-9a-f]{40}$/i.test(shasum) ? shasum : undefined;
}

function repositoryOf(value: unknown): string | undefined {
  const raw =
    typeof value === 'string'
      ? value
      : isRecord(value) && typeof value.url === 'string'
        ? value.url
        : undefined;
  if (raw === undefined) return undefined;
  const sanitized = sanitizeMessage(redactUrlCredentials(raw), 300);
  return sanitized === '' ? undefined : sanitized;
}

/**
 * Verify a registry tarball against its SRI `integrity` (or legacy sha1
 * `shasum`). Returns `verified` when a digest was present and matched; returns
 * `unavailable` only when the registry supplied no usable digest.
 */
export function verifyTarballIntegrity(
  bytes: Uint8Array,
  integrity: string | undefined,
  shasum: string | undefined,
): 'verified' | 'unavailable' {
  if (integrity !== undefined) {
    const entries = integrity.trim().split(/\s+/).filter((entry) => entry !== '');
    const supported = entries
      .map((entry) => {
        const dash = entry.indexOf('-');
        if (dash <= 0) return undefined;
        return { algorithm: entry.slice(0, dash).toLowerCase(), digest: entry.slice(dash + 1) };
      })
      .filter(
        (entry): entry is { algorithm: string; digest: string } =>
          entry !== undefined && ['sha512', 'sha256', 'sha1'].includes(entry.algorithm),
      );
    for (const algorithm of ['sha512', 'sha256', 'sha1'] as const) {
      const entry = supported.find((candidate) => candidate.algorithm === algorithm);
      if (entry === undefined) continue;
      let expected: Buffer;
      try {
        expected = Buffer.from(entry.digest, 'base64');
      } catch {
        throw new HostError('tarball_integrity_mismatch', 'registry 提供的 integrity 无法解析。');
      }
      const expectedLength = algorithm === 'sha512' ? 64 : algorithm === 'sha256' ? 32 : 20;
      if (expected.length !== expectedLength) {
        throw new HostError('tarball_integrity_mismatch', 'registry 提供的 integrity 摘要长度无效。');
      }
      const actual = createHash(algorithm).update(bytes).digest();
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
        throw new HostError(
          'tarball_integrity_mismatch',
          'tarball 的 sha 摘要与 registry 提供的 integrity 不一致：可能被篡改或下载不完整。',
        );
      }
      return 'verified';
    }
  }
  if (shasum !== undefined) {
    const actual = createHash('sha1').update(bytes).digest('hex');
    if (actual !== shasum.toLowerCase()) {
      throw new HostError(
        'tarball_integrity_mismatch',
        'tarball 的 sha1 摘要与 registry 提供的 shasum 不一致：可能被篡改或下载不完整。',
      );
    }
    return 'verified';
  }
  return 'unavailable';
}

async function materializeNpm(
  parsed: ParsedCandidateSpec,
  options: MaterializeOptions,
): Promise<MaterializedCandidate> {
  const name = parsed.name;
  if (name === undefined) {
    throw new HostError('invalid_spec', 'npm 规格缺少包名。');
  }
  const registryBase = normalizeRegistryBase(options.registryBase ?? DEFAULT_REGISTRY);
  const httpOptions: HttpOptions = {
    fetchImpl: options.fetchImpl ?? fetch,
    ...(options.signal !== undefined ? { signal: options.signal } : {}),
    timeoutMs: options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS,
  };
  const maxTarballBytes = options.maxTarballBytes ?? MAX_TARBALL_BYTES;
  const packument = await fetchPackument(name, registryBase, httpOptions);
  const resolved = resolveNpmVersion(packument, parsed.range);
  const metadata = versionMetadataMap(packument)[resolved.version];
  if (metadata === undefined) {
    throw new HostError('version_not_found', `registry 中找不到 ${name}@${resolved.version} 的元数据。`);
  }
  const tarballUrl = tarballUrlOf(metadata);
  if (tarballUrl === undefined) {
    throw new HostError('materialize_failed', 'registry 元数据缺少可用的 tarball 地址。');
  }
  const tarballBytes = await downloadBytes(
    tarballUrl,
    httpOptions,
    'materialize_failed',
    maxTarballBytes,
  );
  options.signal?.throwIfAborted();
  const integrity = verifyTarballIntegrity(tarballBytes, integrityOf(metadata), shasumOf(metadata));
  const directory = await options.workspace.createCandidateDir();
  try {
    await extractTarball(tarballBytes, directory, {
      maxTotalBytes: options.maxExtractedBytes ?? MAX_EXTRACTED_BYTES,
      maxFileBytes: maxTarballBytes,
    });
    const identity = await readPackageIdentity(join(directory, 'package.json'));
    const notes: string[] = [];
    if (resolved.note !== undefined) notes.push(resolved.note);
    if (integrity === 'unavailable') {
      notes.push('registry 未提供可核验的 tarball 摘要（integrity/shasum），本次仅记录 tarball SHA-256。');
    }
    if (identity.version !== undefined && identity.version !== resolved.version) {
      notes.push(
        `解压出的 package.json 版本为 ${sanitizeMessage(identity.version, 40)}，与 registry 记录的 ${resolved.version} 不一致。`,
      );
    }
    const repository = repositoryOf(metadata.repository) ?? identity.repository;
    const candidate: MaterializedCandidate = {
      kind: 'npm',
      candidateDir: directory,
      temporary: true,
      install_spec: `${name}@${resolved.version}`,
      name,
      version: resolved.version,
      registry: registryBase,
      tarball_sha256: sha256Hex(tarballBytes),
      integrity,
    };
    if (notes.length > 0) candidate.note = notes.join(' ');
    if (repository !== undefined) candidate.repository = repository;
    return candidate;
  } catch (error) {
    await options.workspace.releaseDir(directory);
    throw error;
  }
}

/* ------------------------------------------------------------------------- */
/* Git acquisition                                                            */
/* ------------------------------------------------------------------------- */

function cloneGitRepository(
  parsed: ParsedCandidateSpec,
  targetDirectory: string,
  options: { signal?: AbortSignal; timeoutMs: number },
): Promise<void> {
  const url = parsed.git_url;
  if (url === undefined) {
    return Promise.reject(new HostError('invalid_spec', 'git 地址无效。'));
  }
  const args = ['clone', '--depth', '1', '--single-branch', '--no-tags'];
  if (parsed.git_ref !== undefined) args.push('--branch', parsed.git_ref);
  args.push('--', url, targetDirectory);

  return new Promise<void>((resolvePromise, rejectPromise) => {
    let settled = false;
    let timedOut = false;
    let stderr = '';
    let timer: NodeJS.Timeout | undefined;
    let onAbort: (() => void) | undefined;
    const finish = (error?: HostError): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (onAbort !== undefined) options.signal?.removeEventListener('abort', onAbort);
      if (error === undefined) resolvePromise();
      else rejectPromise(error);
    };
    let child: ChildProcess;
    try {
      child = spawn('git', args, {
        stdio: ['ignore', 'ignore', 'pipe'],
        windowsHide: true,
      });
    } catch (error) {
      finish(new HostError('git_unavailable', `无法启动 git 进程：${sanitizeMessage(errorMessage(error), 160)}`));
      return;
    }
    timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, options.timeoutMs);
    onAbort = (): void => {
      child.kill('SIGKILL');
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });
    child.stderr?.on('data', (chunk: Buffer | string) => {
      if (stderr.length >= 8192) return;
      stderr += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      if (stderr.length > 8192) stderr = stderr.slice(0, 8192);
    });
    child.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') {
        finish(new HostError('git_unavailable', '系统 PATH 中找不到 git 命令，无法审查 git 规格。'));
      } else if (options.signal?.aborted) {
        finish(new HostError('aborted', '审查已取消。'));
      } else if (timedOut) {
        finish(new HostError('git_clone_failed', `git clone 超时（${Math.round(options.timeoutMs / 1000)} 秒）。`));
      } else {
        finish(new HostError('git_clone_failed', `git 进程启动失败：${sanitizeMessage(error.message, 200)}`));
      }
    });
    child.on('close', (code) => {
      if (settled) return;
      if (options.signal?.aborted) {
        finish(new HostError('aborted', '审查已取消。'));
        return;
      }
      if (timedOut) {
        finish(new HostError('git_clone_failed', `git clone 超时（${Math.round(options.timeoutMs / 1000)} 秒）。`));
        return;
      }
      if (code === 0) {
        finish();
        return;
      }
      const lastLine = stderr.trim().split('\n').filter((line) => line !== '').pop() ?? '';
      const detail = lastLine === '' ? '' : `：${sanitizeMessage(lastLine, 240)}`;
      finish(new HostError('git_clone_failed', `git clone 失败（退出码 ${String(code)}）${detail}`));
    });
  });
}

async function materializeGit(
  parsed: ParsedCandidateSpec,
  options: MaterializeOptions,
): Promise<MaterializedCandidate> {
  const directory = await options.workspace.createCandidateDir();
  try {
    await cloneGitRepository(parsed, directory, {
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
      timeoutMs: options.cloneTimeoutMs ?? GIT_CLONE_TIMEOUT_MS,
    });
    options.signal?.throwIfAborted();
    await rm(join(directory, '.git'), { recursive: true, force: true });
    const identity = await readPackageIdentity(join(directory, 'package.json'));
    const notes = ['该 git 规格未固定 commit：审查的是克隆时默认分支的最新提交。'];
    if (parsed.git_ref !== undefined) {
      notes.push(`已按引用 ${sanitizeMessage(parsed.git_ref, 80)} 克隆。`);
    }
    const candidate: MaterializedCandidate = {
      kind: 'git',
      candidateDir: directory,
      temporary: true,
      install_spec: parsed.raw,
      note: notes.join(' '),
    };
    if (identity.name !== undefined) candidate.name = identity.name;
    if (identity.version !== undefined) candidate.version = identity.version;
    if (identity.repository !== undefined) candidate.repository = identity.repository;
    return candidate;
  } catch (error) {
    await options.workspace.releaseDir(directory);
    throw error;
  }
}

/* ------------------------------------------------------------------------- */
/* Tarball acquisition and package identity                                   */
/* ------------------------------------------------------------------------- */

interface PackageIdentity {
  name?: string;
  version?: string;
  repository?: string;
}

/** Best-effort identity read from an extracted `package.json`. */
async function readPackageIdentity(file: string): Promise<PackageIdentity> {
  try {
    const info = await lstat(file);
    if (!info.isFile() || info.size > MAX_PACKAGE_JSON_BYTES) return {};
    const parsed: unknown = JSON.parse(await readFile(file, 'utf8'));
    if (!isRecord(parsed)) return {};
    const identity: PackageIdentity = {};
    if (typeof parsed.name === 'string') identity.name = sanitizeMessage(parsed.name, 200);
    if (typeof parsed.version === 'string') identity.version = sanitizeMessage(parsed.version, 100);
    const repository = repositoryOf(parsed.repository);
    if (repository !== undefined) identity.repository = repository;
    return identity;
  } catch {
    return {};
  }
}

async function readLocalArchive(file: string, maxBytes: number): Promise<Uint8Array> {
  let info;
  try {
    info = await lstat(file);
  } catch {
    throw new HostError('materialize_failed', '本地归档不可访问，请重新选择。');
  }
  if (!info.isFile()) throw new HostError('materialize_failed', '本地归档不是普通文件。');
  if (info.size > maxBytes) {
    throw new HostError('candidate_too_large', `本地归档超过 ${formatMiB(maxBytes)} 上限。`);
  }
  try {
    return new Uint8Array(await readFile(file));
  } catch {
    throw new HostError('materialize_failed', '本地归档读取失败。');
  }
}

async function downloadBytes(
  url: string,
  httpOptions: HttpOptions,
  errorCode: HostErrorCode,
  maxBytes: number,
): Promise<Uint8Array> {
  const response = await httpRequest(
    url,
    { headers: { accept: 'application/octet-stream' } },
    httpOptions,
    errorCode,
  );
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new HostError(errorCode, `下载归档失败：HTTP ${response.status}。`);
  }
  return readResponseBytes(response, maxBytes, 'tarball');
}

async function materializeTarball(
  parsed: ParsedCandidateSpec,
  options: MaterializeOptions,
): Promise<MaterializedCandidate> {
  const maxTarballBytes = options.maxTarballBytes ?? MAX_TARBALL_BYTES;
  let bytes: Uint8Array;
  let installSpec: string;
  let note: string;
  if (parsed.path !== undefined) {
    bytes = await readLocalArchive(parsed.path, maxTarballBytes);
    installSpec = parsed.path;
    note = '本地归档没有可核验的来源摘要，本次仅记录归档的 SHA-256。';
  } else if (parsed.tarball_url !== undefined) {
    bytes = await downloadBytes(
      parsed.tarball_url,
      {
        fetchImpl: options.fetchImpl ?? fetch,
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
        timeoutMs: options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS,
      },
      'materialize_failed',
      maxTarballBytes,
    );
    installSpec = parsed.tarball_url;
    note = '直链归档没有可核验的期望摘要，本次仅记录归档的 SHA-256。';
  } else {
    throw new HostError('invalid_spec', '归档规格缺少地址。');
  }
  options.signal?.throwIfAborted();
  const directory = await options.workspace.createCandidateDir();
  try {
    await extractTarball(bytes, directory, {
      maxTotalBytes: options.maxExtractedBytes ?? MAX_EXTRACTED_BYTES,
      maxFileBytes: maxTarballBytes,
    });
    const identity = await readPackageIdentity(join(directory, 'package.json'));
    const candidate: MaterializedCandidate = {
      kind: 'tarball',
      candidateDir: directory,
      temporary: true,
      install_spec: installSpec,
      tarball_sha256: sha256Hex(bytes),
      integrity: 'unavailable',
      note,
    };
    if (identity.name !== undefined) candidate.name = identity.name;
    if (identity.version !== undefined) candidate.version = identity.version;
    if (identity.repository !== undefined) candidate.repository = identity.repository;
    return candidate;
  } catch (error) {
    await options.workspace.releaseDir(directory);
    throw error;
  }
}

/* ------------------------------------------------------------------------- */
/* Orchestration                                                              */
/* ------------------------------------------------------------------------- */

/** Per-service context needed to acquire candidates. */
export interface MaterializeOptions {
  /** Store directory; used only through {@link workspace}. */
  storeDir: string;
  workspace: CandidateWorkspace;
  /** Registry base override (default {@link DEFAULT_REGISTRY}). */
  registryBase?: string;
  /** Injectable `fetch` for tests and custom transports. */
  fetchImpl?: typeof fetch;
  /** Cancels acquisition and the review that follows it. */
  signal?: AbortSignal;
  maxTarballBytes?: number;
  maxExtractedBytes?: number;
  requestTimeoutMs?: number;
  cloneTimeoutMs?: number;
}

/** A candidate tree ready for `evaluatePluginTrust`. */
export interface MaterializedCandidate {
  kind: ParsedCandidateSpec['kind'];
  /** Absolute directory the decision layer should inspect. */
  candidateDir: string;
  /** True when the directory belongs to the candidate workspace. */
  temporary: boolean;
  /** Exact install spec the UI should hand to the native install flow. */
  install_spec: string;
  /** Display-only hint, never a wire path of the candidate cache. */
  name?: string;
  version?: string;
  registry?: string;
  tarball_sha256?: string;
  integrity?: 'verified' | 'unavailable';
  note?: string;
  /** Repository URL from registry metadata or the extracted manifest, if any. */
  repository?: string;
}

/**
 * Acquire the candidate described by a parsed spec.
 *
 * Acquisition failures throw {@link HostError} with a stable code; callers map
 * them into the `{ok:false,error}` review response.
 */
export async function materializeCandidate(
  parsed: ParsedCandidateSpec,
  options: MaterializeOptions,
): Promise<MaterializedCandidate> {
  options.signal?.throwIfAborted();
  switch (parsed.kind) {
    case 'local':
      return materializeLocal(parsed);
    case 'npm':
      return materializeNpm(parsed, options);
    case 'git':
      return materializeGit(parsed, options);
    case 'tarball':
      return materializeTarball(parsed, options);
  }
}

async function materializeLocal(parsed: ParsedCandidateSpec): Promise<MaterializedCandidate> {
  const path = parsed.path;
  if (path === undefined) {
    throw new HostError('invalid_spec', '本地规格缺少路径。');
  }
  let info;
  try {
    info = await lstat(path);
  } catch {
    throw new HostError('materialize_failed', '本地路径不可访问，请重新选择。');
  }
  if (!info.isDirectory()) {
    throw new HostError('materialize_failed', '本地路径不再是目录，请重新选择。');
  }
  return { kind: 'local', candidateDir: path, temporary: false, install_spec: path };
}
