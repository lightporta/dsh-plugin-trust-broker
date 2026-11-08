/**
 * Candidate spec parsing for the pre-install review Host service.
 *
 * A "candidate spec" is whatever the user typed into the review tab or the
 * model handed to `plugin_manager`: a local directory, an npm package spec, a
 * git URL, or a tarball URL/path. This module turns that untrusted string into
 * a small tagged union the acquisition layer can act on, and it is the only
 * place that decides which candidate kind a string means.
 *
 * Security properties:
 * - An existing local path always wins. If the string names something on disk
 *   the user gets that tree reviewed, never a same-named registry package.
 * - Anything malformed, empty, or ambiguous is rejected with a stable error
 *   code and a short user-facing message; no guessing between npm and git.
 * - Credentials inside specs are never parsed into a structured field. URLs are
 *   validated for scheme only and are redacted before they reach error text.
 */

import { lstat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { CandidateKind } from './protocol.ts';

/** Stable error codes surfaced through the review JSON contract. */
export type HostErrorCode =
  | 'invalid_spec'
  | 'invalid_request'
  | 'materialize_failed'
  | 'registry_unreachable'
  | 'version_not_found'
  | 'tarball_integrity_mismatch'
  | 'unsafe_archive_entry'
  | 'candidate_too_large'
  | 'git_unavailable'
  | 'git_clone_failed'
  | 'review_expired'
  | 'review_not_confirmable'
  | 'review_failed'
  | 'aborted'
  | 'internal_error';

/** Error with a stable, wire-safe code and a human-readable Chinese message. */
export class HostError extends Error {
  readonly code: HostErrorCode;

  constructor(code: HostErrorCode, message: string) {
    super(message);
    this.name = 'HostError';
    this.code = code;
  }
}

/** Type guard for {@link HostError}. */
export function isHostError(error: unknown): error is HostError {
  return error instanceof HostError;
}

/** Code of any thrown value; unknown failures map to `review_failed`. */
export function hostErrorCode(error: unknown): HostErrorCode {
  return isHostError(error) ? error.code : 'review_failed';
}

/** Short message of any thrown value (never a stack trace). */
export function hostErrorMessage(error: unknown): string {
  if (isHostError(error)) return error.message;
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

/** Parsed candidate, before any bytes are fetched. */
export interface ParsedCandidateSpec {
  kind: CandidateKind;
  /** Trimmed input exactly as the caller supplied it. */
  raw: string;
  /** Absolute local path for `local` directories and local tarballs. */
  path?: string;
  /** npm package name (unscoped or `@scope/name`). */
  name?: string;
  /** npm version, range or dist-tag, when the caller supplied one. */
  range?: string;
  /** Clone URL for `git` candidates (leading `git+` already stripped). */
  git_url?: string;
  /** Optional ref/fragment carried by a git spec (`owner/repo#main`). */
  git_ref?: string;
  /** HTTP(S) URL for remote tarballs. */
  tarball_url?: string;
}

/** Absolute path to a tarball, or `undefined` when it does not name one. */
const TARBALL_SUFFIX_PATTERN = /\.(?:tgz|tar\.gz)$/i;

/** Longest accepted spec; longer strings are almost certainly pasted garbage. */
const MAX_SPEC_LENGTH = 2048;

/** npm package-name grammar (scoped or unscoped, no whitespace). */
const NPM_NAME_PATTERN =
  /^(?:@[A-Za-z0-9-~][A-Za-z0-9-._~]*\/)?[A-Za-z0-9-~][A-Za-z0-9-._~]*$/;

/** `owner/repo` GitHub shorthand; scoped npm names are handled before this. */
const GITHUB_SHORTHAND_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*(?:#.+)?$/;

/** scp-like git address, e.g. `git@github.com:owner/repo.git`. */
const SCP_GIT_PATTERN = /^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+$/;

interface ExistingPath {
  absolute: string;
  isDirectory: boolean;
  isSymbolicLink: boolean;
  isTarball: boolean;
}

/** `~` and `~/x` expansion without touching the rest of the string. */
function expandHome(input: string): string {
  if (input === '~') return homedir();
  if (input.startsWith('~/') || input.startsWith('~\\')) return join(homedir(), input.slice(2));
  return input;
}

/** True when the string is clearly meant as a filesystem path, not a package. */
function looksLikePath(input: string): boolean {
  return (
    isAbsolute(input) ||
    input === '.' ||
    input === '..' ||
    input.startsWith('./') ||
    input.startsWith('../') ||
    input === '~' ||
    input.startsWith('~/') ||
    input.startsWith('~\\')
  );
}

/** Convert a `file:` URL to an absolute path; malformed URLs are rejected. */
function fileUrlToPath(input: string): string {
  try {
    const url = new URL(input);
    if (url.protocol !== 'file:') {
      throw new HostError('invalid_spec', 'file: 地址的协议无效。');
    }
    return fileURLToPath(url);
  } catch (error) {
    if (isHostError(error)) throw error;
    throw new HostError('invalid_spec', 'file: 地址无效。');
  }
}

/** `lstat` a candidate path; missing paths are `undefined`, other errors rejected. */
async function inspectExistingPath(candidate: string, cwd: string): Promise<ExistingPath | undefined> {
  const absolute = isAbsolute(candidate) ? resolve(candidate) : resolve(cwd, candidate);
  let info;
  try {
    info = await lstat(absolute);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return undefined;
    throw new HostError('invalid_spec', '无法读取本地路径，请检查权限。');
  }
  return {
    absolute,
    isDirectory: info.isDirectory(),
    isSymbolicLink: info.isSymbolicLink(),
    isTarball: TARBALL_SUFFIX_PATTERN.test(absolute),
  };
}

/** Build a local/tarball candidate from an existing path. */
function describeExistingPath(existing: ExistingPath, raw: string): ParsedCandidateSpec {
  if (existing.isSymbolicLink) {
    throw new HostError(
      'invalid_spec',
      '本地路径是符号链接：请提供真实目录或归档路径（审查要求完整可绑定的候选树）。',
    );
  }
  if (existing.isDirectory) {
    return { kind: 'local', raw, path: existing.absolute };
  }
  if (existing.isTarball) {
    return { kind: 'tarball', raw, path: existing.absolute };
  }
  throw new HostError(
    'invalid_spec',
    '本地路径既不是目录，也不是 .tgz/.tar.gz 归档，无法审查。',
  );
}

/** Resolve an explicit local path (file: URI, `~`, absolute, relative). */
async function localCandidate(candidatePath: string, cwd: string, raw: string): Promise<ParsedCandidateSpec> {
  const existing = await inspectExistingPath(expandHome(candidatePath), cwd);
  if (existing === undefined) {
    throw new HostError('invalid_spec', '本地路径不存在，请检查路径是否正确。');
  }
  return describeExistingPath(existing, raw);
}

/** True when the raw spec names a remote tarball URL. */
function isTarballUrl(url: URL): boolean {
  return TARBALL_SUFFIX_PATTERN.test(url.pathname);
}

/** True when an http(s)/ssh URL names a git repository. */
function isGitUrl(url: URL): boolean {
  return url.pathname.endsWith('.git') || url.pathname.includes('.git/');
}

/** Parse a git spec into its clone URL, keeping the original raw string. */
function gitCandidate(raw: string): ParsedCandidateSpec {
  const hashIndex = raw.indexOf('#');
  const hasRef = hashIndex > 0;
  const withoutRef = hasRef ? raw.slice(0, hashIndex) : raw;
  const ref = hasRef ? raw.slice(hashIndex + 1) : undefined;
  if (hasRef && (ref === undefined || ref.trim() === '')) {
    throw new HostError('invalid_spec', 'git 规格的引用（# 之后）不能为空。');
  }
  if (ref !== undefined && (!/^[A-Za-z0-9._/-]+$/.test(ref) || ref.startsWith('-') || ref.length > 200)) {
    // The ref is passed to `git clone --branch <ref>`; refuse option-looking or
    // otherwise unsafe values instead of letting git interpret them.
    throw new HostError('invalid_spec', 'git 规格的引用（# 之后）无效。');
  }
  let url = withoutRef;
  if (/^git\+/i.test(url)) {
    url = url.slice('git+'.length);
  }
  if (/^github:/i.test(url)) {
    const rest = url.slice('github:'.length).replace(/^\/+/, '');
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*$/.test(rest)) {
      throw new HostError('invalid_spec', 'github: 规格必须形如 github:owner/repo。');
    }
    url = `https://github.com/${rest}.git`;
  } else if (GITHUB_SHORTHAND_PATTERN.test(url)) {
    url = `https://github.com/${url}.git`;
  }
  if (/[\u0000-\u001f\u007f\s]/.test(url)) {
    throw new HostError('invalid_spec', 'git 地址包含空白或控制字符。');
  }
  const parsed: ParsedCandidateSpec = { kind: 'git', raw };
  parsed.git_url = url;
  if (hasRef && ref !== undefined) parsed.git_ref = ref;
  return parsed;
}

/** Split `name[@range]` into an npm candidate, or `undefined` when not npm-shaped. */
function parseNpmSpec(raw: string): ParsedCandidateSpec | undefined {
  let name: string;
  let range: string | undefined;
  if (raw.startsWith('@')) {
    const slash = raw.indexOf('/');
    if (slash < 0) return undefined;
    const separator = raw.indexOf('@', slash);
    if (separator > slash) {
      name = raw.slice(0, separator);
      range = raw.slice(separator + 1);
    } else {
      name = raw;
    }
  } else {
    const separator = raw.indexOf('@');
    if (separator > 0) {
      name = raw.slice(0, separator);
      range = raw.slice(separator + 1);
    } else {
      name = raw;
    }
  }
  if (!NPM_NAME_PATTERN.test(name)) return undefined;
  if (range !== undefined) {
    const trimmed = range.trim();
    if (trimmed === '' || trimmed.includes('@') || /[\u0000-\u001f\u007f]/.test(trimmed)) {
      throw new HostError('invalid_spec', 'npm 版本/范围无效。');
    }
    range = trimmed;
  }
  const parsed: ParsedCandidateSpec = { kind: 'npm', raw, name };
  if (range !== undefined) parsed.range = range;
  return parsed;
}

/** Short, control-character-free rendering of a spec for error messages. */
function displayable(input: string): string {
  return input.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?').slice(0, 200);
}

/**
 * Parse one candidate spec.
 *
 * Resolution order (the first match wins):
 * 1. `file:` URI (must exist).
 * 2. A path that exists on disk (absolute, relative to `cwd`, or `~`).
 * 3. `git+…`, scp-like `user@host:path`, `ssh://` / `git://` URLs.
 * 4. HTTP(S) URLs ending in `.tgz` / `.tar.gz` (tarball) or `.git` (git).
 * 5. `github:owner/repo` and bare `owner/repo` (git shorthand).
 * 6. A local-looking path that does not exist (clear `invalid_spec`).
 * 7. `name`, `@scope/name`, `name@version|range|tag` (npm).
 *
 * @param rawInput Text supplied by the UI or an agent tool call.
 * @param options `cwd` for relative paths; defaults to the process directory.
 */
export async function parseCandidateSpec(
  rawInput: string,
  options: { cwd?: string } = {},
): Promise<ParsedCandidateSpec> {
  const raw = typeof rawInput === 'string' ? rawInput.trim() : '';
  if (raw === '') {
    throw new HostError(
      'invalid_spec',
      '插件规格不能为空：请输入 npm 包名、本地路径、git 地址或 .tgz/.tar.gz 归档。',
    );
  }
  if (raw.length > MAX_SPEC_LENGTH) {
    throw new HostError('invalid_spec', '插件规格过长，已拒绝。');
  }
  if (/[\u0000-\u001f\u007f]/.test(raw)) {
    throw new HostError('invalid_spec', '插件规格包含控制字符，已拒绝。');
  }
  const cwd = options.cwd ?? process.cwd();

  if (/^file:/i.test(raw)) {
    return await localCandidate(fileUrlToPath(raw), cwd, raw);
  }

  // Existing path wins over every package interpretation.
  const expanded = expandHome(raw);
  const existing = await inspectExistingPath(expanded, cwd);
  if (existing !== undefined) {
    return describeExistingPath(existing, raw);
  }

  if (/^git\+/i.test(raw)) {
    return gitCandidate(raw);
  }
  if (SCP_GIT_PATTERN.test(raw)) {
    return gitCandidate(raw);
  }

  let url: URL | undefined;
  try {
    url = new URL(raw);
  } catch {
    url = undefined;
  }
  if (url !== undefined) {
    const protocol = url.protocol.toLowerCase();
    if (protocol === 'http:' || protocol === 'https:') {
      if (isTarballUrl(url)) {
        return { kind: 'tarball', raw, tarball_url: raw };
      }
      if (isGitUrl(url)) {
        return gitCandidate(raw);
      }
      throw new HostError(
        'invalid_spec',
        '无法识别的 HTTP(S) 地址：只支持 .tgz/.tar.gz 归档或 .git 仓库地址。',
      );
    }
    if (protocol === 'ssh:' || protocol === 'git:') {
      return gitCandidate(raw);
    }
  }

  if (/^github:/i.test(raw)) {
    return gitCandidate(raw);
  }
  if (GITHUB_SHORTHAND_PATTERN.test(raw)) {
    return gitCandidate(raw);
  }

  const npm = parseNpmSpec(raw);
  if (npm !== undefined) return npm;

  if (looksLikePath(raw)) {
    throw new HostError('invalid_spec', `本地路径不存在：${displayable(raw)}`);
  }
  throw new HostError(
    'invalid_spec',
    '无法识别的插件规格：支持 npm 包名、本地目录、git 地址或 .tgz/.tar.gz 归档。',
  );
}
