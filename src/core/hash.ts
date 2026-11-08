/**
 * Canonical, deterministic content hash for a plugin tree.
 *
 * This hash is the identity of "the bytes the user confirmed": a trust anchor
 * stores it and any later install whose tree hashes differently is treated as a
 * different artifact. The properties below are security properties, not
 * conveniences:
 *
 * - Deterministic: the tree is walked recursively and every entry is sorted by
 *   its POSIX relative path, so filesystem/readdir order never matters.
 * - Path-binding: the aggregate includes the relative path of every entry, so a
 *   rename changes the hash even though file bytes are unchanged.
 * - Symlink-safe: symlinks are never followed. A symlink contributes
 *   `sha256("symlink\0" + target)` and its raw target string; hashing never
 *   leaves `root` and never reads a target file outside the tree.
 * - Fail-closed: any unreadable entry, stat/read/link error, unsupported entry
 *   kind, or configured limit breach yields `hash: null` and `complete: false`
 *   with the failure recorded in `errors`. A partial tree never produces a
 *   hash, so the decision layer can use `hash === null` as the single
 *   "refuse to anchor" trigger.
 * - Empty tree: a valid hash over the empty manifest (domain separator only),
 *   `file_count: 0`, `complete: true`.
 *
 * Aggregate format (UTF-8): a v2 domain line followed by one JSON tuple
 * `[kind, entry_sha256_hex, relative_posix_path]` per sorted path. JSON escaping
 * prevents a filename from adding another entry to the aggregate.
 */

import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, readlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { errorMessage, sha256Hex } from './fs-utils.ts';
import {
  assertTreeDirectory,
  canonicalTreeRoot,
  FileReadLimitError,
  treeDirectoryEntries,
  withTreeFile,
} from './tree-files.ts';

/** Aggregate domain separator; bump only with a documented hash migration. */
export const CONTENT_HASH_DOMAIN = 'dsh-plugin-content-v2';

/** Prefix mixed into a symlink's own digest before the raw link target. */
export const SYMLINK_HASH_DOMAIN = 'symlink\u0000';

/** Default excluded directory/file names (matched against every path segment). */
export const DEFAULT_HASH_EXCLUDES: readonly string[] = ['.git', 'node_modules', '.DS_Store'];

/** Default maximum number of entries (files + symlinks) in one hash. */
export const DEFAULT_HASH_MAX_FILES = 5000;

/** Default maximum number of bytes read in one hash: 256 MiB. */
export const DEFAULT_HASH_MAX_TOTAL_BYTES = 256 * 1024 * 1024;

/** Options accepted by {@link computeContentHash}. */
export interface ContentHashOptions {
  /**
   * Excluded names or relative POSIX sub-paths. When provided this list
   * REPLACES {@link DEFAULT_HASH_EXCLUDES}; pass `[]` to hash everything.
   * A single-segment entry (`.git`) matches that segment at any depth; an entry
   * containing `/` (`dist/cache`) matches that relative path and its subtree.
   */
  excludes?: string[];
  /** Maximum entries (files + symlinks); default {@link DEFAULT_HASH_MAX_FILES}. */
  maxFiles?: number;
  /** Maximum bytes read (regular file bytes + symlink target bytes); default 256 MiB. */
  maxTotalBytes?: number;
  /** Admission mode: hash all files and refuse symlinks, hardlinks and special entries. */
  strict?: boolean;
  /** Existing empty private directory outside the tree that receives the exact hashed bytes. */
  snapshotDir?: string;
  signal?: AbortSignal;
}

/** Kind of a hashed tree entry. */
export type ContentHashEntryKind = 'file' | 'symlink';

/** One entry of the canonical manifest. */
export interface ContentHashFile {
  /** Path relative to the plugin root, POSIX separators, no leading `./`. */
  path: string;
  /** Lowercase hex sha-256: file bytes, or `"symlink\0" + target` for symlinks. */
  sha256: string;
  /** Bytes hashed: file size, or UTF-8 length of the symlink target string. */
  size: number;
  kind: ContentHashEntryKind;
  /** Raw `readlink` result for symlinks; absent for regular files. */
  link_target?: string;
}

/** One fail-closed condition that prevented a complete hash. */
export interface ContentHashError {
  /** Relative path of the offending entry; `.` for the root itself. */
  path: string;
  /** Human-readable description. */
  message: string;
  /**
   * Error category or OS errno. Always `hash_limit` when a limit was exceeded;
   * otherwise an errno such as `EACCES`/`ELOOP`, or a walker category such as
   * `walk_error`, `root_error`, `read_error`, `unsupported_entry`.
   */
  code?: string;
}

/** One tree entry skipped because of an exclusion rule. */
export interface ContentHashExcluded {
  /** Relative POSIX path of the excluded entry. */
  path: string;
  /** Why it was skipped; currently always `excluded`. */
  reason: string;
}

/** Result of {@link computeContentHash}. `hash === null` iff `complete === false`. */
export interface ContentHashResult {
  algorithm: 'sha256';
  /** `sha256:<hex>`, or `null` when the tree could not be hashed completely. */
  hash: string | null;
  /** Hashed entries, sorted by path (may be partial when `complete === false`). */
  files: ContentHashFile[];
  file_count: number;
  byte_count: number;
  /** True only when every entry was hashed and no limit was breached. */
  complete: boolean;
  errors: ContentHashError[];
  excluded: ContentHashExcluded[];
}

/** Normalized options after defaults, validation and exclusion normalization. */
interface ResolvedContentHashLimits {
  excludes: readonly string[];
  maxFiles: number;
  maxTotalBytes: number;
}

/** Mutable walk accumulator. */
interface WalkState {
  files: ContentHashFile[];
  directories: string[];
  errors: ContentHashError[];
  excluded: ContentHashExcluded[];
  byteCount: number;
  aborted: boolean;
}

/**
 * Compute the canonical content hash of a plugin tree.
 *
 * Resolve the caller's root before opening entries. Standalone hashes bind
 * symlinks by target string. Admission hashes reject links and include all files.
 *
 * @param root Absolute or relative path of the plugin tree.
 * @param options Exclusion and resource-limit overrides.
 * @returns A complete result with `hash: 'sha256:<hex>'`, or a fail-closed
 *   result with `hash: null`, `complete: false` and at least one recorded error.
 *   Never returns a hash for a partially inspected tree.
 */
export async function computeContentHash(
  root: string,
  options: ContentHashOptions = {},
): Promise<ContentHashResult> {
  if (typeof root !== 'string' || root.length === 0) {
    throw new TypeError('computeContentHash: root must be a non-empty path string');
  }
  options.signal?.throwIfAborted();
  const strict = options.strict === true;
  if (options.snapshotDir !== undefined && !strict) {
    throw new TypeError('computeContentHash: snapshots require strict mode');
  }
  const limits = resolveLimits(options);
  const rootPath = resolve(root);

  const fail = (error: ContentHashError): ContentHashResult => ({
    algorithm: 'sha256',
    hash: null,
    files: [],
    file_count: 0,
    byte_count: 0,
    complete: false,
    errors: [error],
    excluded: [],
  });

  let realRoot: string;
  let snapshotRoot: string | undefined;
  try {
    realRoot = await canonicalTreeRoot(rootPath, strict);
    if (options.snapshotDir !== undefined) {
      snapshotRoot = await canonicalTreeRoot(resolve(options.snapshotDir), true);
      const relativeSnapshot = relative(realRoot, snapshotRoot);
      if (relativeSnapshot === '' || (!isAbsolute(relativeSnapshot) &&
          relativeSnapshot !== '..' && !relativeSnapshot.startsWith(`..${sep}`))) {
        throw new Error('snapshot directory must be outside the plugin tree');
      }
      if ((await treeDirectoryEntries(snapshotRoot)).length !== 0) {
        throw new Error('snapshot directory must be empty');
      }
    }
  } catch (error) {
    options.signal?.throwIfAborted();
    return fail({
      path: '.',
      message: `cannot resolve plugin root: ${errorMessage(error)}`,
      code: errnoCode(error) === 'ENOTDIR' ? 'root_not_directory' : errnoCode(error) ?? 'root_error',
    });
  }

  const state: WalkState = {
    files: [],
    directories: [],
    errors: [],
    excluded: [],
    byteCount: 0,
    aborted: false,
  };

  /** Record a fail-closed condition and stop walking; never a silent skip. */
  const recordError = (relativePath: string, message: string, code?: string): void => {
    state.errors.push({
      path: relativePath === '' ? '.' : relativePath,
      message,
      ...(code === undefined ? {} : { code }),
    });
    state.aborted = true;
  };

  /** Record a resource-limit breach with the reserved `hash_limit` code. */
  const recordLimit = (relativePath: string, detail: string): void => {
    recordError(relativePath, `hash_limit: ${detail}`, 'hash_limit');
  };

  /** Depth-first walk; `relativeDir` is `''` for the root. */
  async function visit(relativeDir: string, absoluteDir: string, snapshotDir?: string): Promise<void> {
    if (state.aborted) return;
    options.signal?.throwIfAborted();
    let directory;
    let entries;
    try {
      directory = await assertTreeDirectory(absoluteDir);
      entries = await treeDirectoryEntries(absoluteDir);
      await assertTreeDirectory(absoluteDir, directory);
    } catch (error) {
      recordError(
        relativeDir,
        `cannot read directory: ${errorMessage(error)}`,
        errnoCode(error) ?? 'walk_error',
      );
      return;
    }
    entries.sort((left, right) => compareStrings(left.name, right.name));
    for (const entry of entries) {
      if (state.aborted) return;
      options.signal?.throwIfAborted();
      const relativePath = relativeDir === '' ? entry.name : `${relativeDir}/${entry.name}`;
      if (isExcludedPath(relativePath, limits.excludes)) {
        state.excluded.push({ path: relativePath, reason: 'excluded' });
        continue;
      }
      const absolutePath = join(absoluteDir, entry.name);
      try {
        if (entry.isSymbolicLink()) {
          if (strict) {
            recordError(relativePath, 'symbolic links are not allowed in an admission tree', 'unsafe_link');
            return;
          }
          if (state.files.length >= limits.maxFiles) {
            recordLimit(relativePath, `file count would exceed maxFiles=${limits.maxFiles}`);
            return;
          }
          const target = await readlink(absolutePath);
          const size = Buffer.byteLength(target, 'utf8');
          const nextByteCount = state.byteCount + size;
          if (nextByteCount > limits.maxTotalBytes) {
            recordLimit(
              relativePath,
              `total bytes would exceed maxTotalBytes=${limits.maxTotalBytes}`,
            );
            return;
          }
          state.byteCount = nextByteCount;
          state.files.push({
            path: relativePath,
            sha256: sha256Hex(`${SYMLINK_HASH_DOMAIN}${target}`),
            size,
            kind: 'symlink',
            link_target: target,
          });
          continue;
        }
        if (entry.isDirectory()) {
          if (strict) {
            if (state.files.length + state.directories.length >= limits.maxFiles) {
              recordLimit(relativePath, `entry count would exceed maxFiles=${limits.maxFiles}`);
              return;
            }
            state.directories.push(relativePath);
          }
          const destination = snapshotDir === undefined ? undefined : join(snapshotDir, entry.name);
          if (destination !== undefined) await mkdir(destination, { mode: 0o700 });
          await visit(relativePath, absolutePath, destination);
          continue;
        }
        if (entry.isFile()) {
          if (state.files.length + state.directories.length >= limits.maxFiles) {
            recordLimit(relativePath, `file count would exceed maxFiles=${limits.maxFiles}`);
            return;
          }
          const hashed = await withTreeFile(
            absolutePath,
            { rejectHardLinks: strict, signal: options.signal },
            (handle, size) => hashHandle(handle, {
              maxBytes: limits.maxTotalBytes - state.byteCount,
              size,
              signal: options.signal,
              copyTo: snapshotDir === undefined ? undefined : join(snapshotDir, entry.name),
            }),
          );
          const nextByteCount = state.byteCount + hashed.size;
          if (nextByteCount > limits.maxTotalBytes) {
            recordLimit(
              relativePath,
              `total bytes would exceed maxTotalBytes=${limits.maxTotalBytes}`,
            );
            return;
          }
          state.byteCount = nextByteCount;
          state.files.push({
            path: relativePath,
            sha256: hashed.sha256,
            size: hashed.size,
            kind: 'file',
          });
          continue;
        }
        recordError(
          relativePath,
          'unsupported filesystem entry kind (not a regular file, directory or symlink)',
          'unsupported_entry',
        );
        return;
      } catch (error) {
        options.signal?.throwIfAborted();
        if (error instanceof FileReadLimitError) {
          recordLimit(
            relativePath,
            `total bytes would exceed maxTotalBytes=${limits.maxTotalBytes}`,
          );
          return;
        }
        recordError(
          relativePath,
          `cannot hash entry: ${errorMessage(error)}`,
          errnoCode(error) ?? 'read_error',
        );
        return;
      }
    }
    try {
      await assertTreeDirectory(absoluteDir, directory);
    } catch (error) {
      recordError(relativeDir, `directory changed during hashing: ${errorMessage(error)}`, 'walk_error');
    }
  }

  await visit('', realRoot, snapshotRoot);
  options.signal?.throwIfAborted();

  const files = [...state.files].sort((left, right) => compareStrings(left.path, right.path));
  const errors = [...state.errors].sort((left, right) => {
    const byPath = compareStrings(left.path, right.path);
    if (byPath !== 0) return byPath;
    const byMessage = compareStrings(left.message, right.message);
    if (byMessage !== 0) return byMessage;
    return compareStrings(left.code ?? '', right.code ?? '');
  });
  const excluded = [...state.excluded].sort((left, right) =>
    compareStrings(left.path, right.path),
  );
  const complete = state.errors.length === 0;

  let hash: string | null = null;
  if (complete) {
    const entries = files.map((file) => ({ kind: file.kind, sha256: file.sha256, path: file.path }));
    const directories = state.directories.map((path) => ({ kind: 'directory', sha256: '', path }));
    const manifest = [...entries, ...directories]
      .sort((left, right) => compareStrings(left.path, right.path))
      .map(({ kind, sha256, path }) => `${JSON.stringify([kind, sha256, path])}\n`).join('');
    hash = `sha256:${sha256Hex(`${CONTENT_HASH_DOMAIN}\n${manifest}`)}`;
  }

  return {
    algorithm: 'sha256',
    hash,
    files,
    file_count: files.length,
    byte_count: state.byteCount,
    complete,
    errors,
    excluded,
  };
}

/**
 * Raw lowercase hex sha-256 of a file's bytes.
 *
 * Follows symlinks like a normal file read; callers that must not follow links
 * should use {@link computeContentHash}, whose walker opens with `O_NOFOLLOW`.
 *
 * @param file Path of the file to hash.
 * @returns 64-character hex digest (no `sha256:` prefix).
 */
export async function sha256File(file: string): Promise<string> {
  const handle = await open(file, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    if (!(await handle.stat()).isFile()) throw new Error('not a regular file');
    return (await hashHandle(handle)).sha256;
  } finally {
    await handle.close();
  }
}

/** Hash the opened descriptor and optionally stage the exact same stream. */
async function hashHandle(
  handle: FileHandle,
  options: { maxBytes?: number; size?: bigint; signal?: AbortSignal; copyTo?: string } = {},
): Promise<{ sha256: string; size: number }> {
  if (options.maxBytes !== undefined && options.size !== undefined && options.size > options.maxBytes) {
    throw new FileReadLimitError();
  }
  const destination = options.copyTo === undefined ? undefined : await open(options.copyTo, 'wx', 0o600);
  try {
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let size = 0;
    for (;;) {
      options.signal?.throwIfAborted();
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      size += bytesRead;
      if (options.maxBytes !== undefined && size > options.maxBytes) {
        throw new FileReadLimitError();
      }
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      await destination?.writeFile(chunk);
    }
    return { sha256: hash.digest('hex'), size };
  } finally {
    await destination?.close();
  }
}

/** Apply defaults and validate numeric limits and exclusions. */
function resolveLimits(options: ContentHashOptions): ResolvedContentHashLimits {
  return {
    excludes: options.strict === true ? [] : normalizeExcludes(options.excludes),
    maxFiles: resolveLimit(options.maxFiles, DEFAULT_HASH_MAX_FILES, 'maxFiles'),
    maxTotalBytes: resolveLimit(
      options.maxTotalBytes,
      DEFAULT_HASH_MAX_TOTAL_BYTES,
      'maxTotalBytes',
    ),
  };
}

/** Validate one numeric limit; invalid limits fail loudly instead of disabling. */
function resolveLimit(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`computeContentHash: ${name} must be a finite number >= 0`);
  }
  return Math.floor(value);
}

/** Normalize exclusion patterns; invalid entries fail loudly. */
function normalizeExcludes(excludes: readonly string[] | undefined): readonly string[] {
  if (excludes === undefined) return DEFAULT_HASH_EXCLUDES;
  const raw = excludes as unknown;
  if (!Array.isArray(raw)) {
    throw new TypeError('computeContentHash: excludes must be an array of relative path names');
  }
  const normalized = new Set<string>();
  for (const entry of raw) {
    if (typeof entry !== 'string') {
      throw new TypeError('computeContentHash: excludes entries must be strings');
    }
    const cleaned = entry.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
    if (cleaned === '') continue;
    if (isAbsolute(cleaned) || cleaned.startsWith('/')) {
      throw new TypeError(`computeContentHash: excludes entries must be relative: ${entry}`);
    }
    normalized.add(cleaned);
  }
  return [...normalized];
}

/**
 * Exclusion match: single-segment patterns match any path segment (so `.git`
 * excludes nested `.git` directories), multi-segment patterns match the relative
 * path and its subtree.
 */
function isExcludedPath(relativePath: string, excludes: readonly string[]): boolean {
  const segments = relativePath.split('/');
  for (const pattern of excludes) {
    if (pattern.includes('/')) {
      if (relativePath === pattern || relativePath.startsWith(`${pattern}/`)) return true;
    } else if (segments.includes(pattern)) {
      return true;
    }
  }
  return false;
}

/** Deterministic code-unit string comparison (never locale-dependent). */
function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Best-effort OS errno code from a caught value. */
function errnoCode(error: unknown): string | undefined {
  if (error === null || typeof error !== 'object') return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' && code.length > 0 ? code : undefined;
}
