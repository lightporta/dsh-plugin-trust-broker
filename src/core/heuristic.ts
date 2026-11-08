/**
 * Built-in fallback detector (explicitly heuristic).
 *
 * This is NOT a full static scanner: it is a small, deterministic, dependency-
 * free rule engine that keeps face two reviewable when `dsh-trust-check` is not
 * installed. Every fact it produces is marked `heuristic: true` and stays in a
 * separate array from scanner-verified facts, so a decision can never mistake a
 * regex hit for a verified capability. Evidence always points at `file:line`
 * (or a `package.json` field pointer for metadata-only facts).
 *
 * The walk is fail-closed: unreadable files, invalid `package.json` or a hit
 * limit set `coverage.complete = false` and record an error, and the detector
 * turns that into an unscannable decision instead of pretending the tree was
 * fully inspected.
 */

import { basename, join, posix, resolve } from 'node:path';
import type {
  CapabilityFact,
  CapabilityPath,
  DetectionError,
  DetectionSource,
  EvidenceRef,
  ScanCoverage,
} from '../types.ts';
import { CAPABILITY_DEFINITIONS, isDeclarable } from './catalog.ts';
import { errorMessage, redactUrlCredentials } from './fs-utils.ts';
import { MAX_PACKAGE_JSON_BYTES, readPath } from './manifest.ts';
import {
  assertTreeDirectory,
  canonicalTreeRoot,
  FileReadLimitError,
  readTreeFile,
  treeDirectoryEntries,
} from './tree-files.ts';
import { TRUST_BROKER_VERSION } from '../version.ts';

/** Name of the built-in heuristic source (shown in decision output). */
export const HEURISTIC_SCANNER_NAME = 'dsh-plugin-trust-broker-heuristic';

/** Source descriptor attached to every heuristic fact. */
export const HEURISTIC_SOURCE: DetectionSource = {
  kind: 'heuristic',
  name: HEURISTIC_SCANNER_NAME,
  version: TRUST_BROKER_VERSION,
  heuristic: true,
};

/** Per-run limits of the heuristic walk. */
export interface HeuristicLimits {
  /** Maximum number of text files analysed. Default 2000. */
  maxFiles?: number;
  /** Maximum size of one analysed file in bytes. Default 2 MiB. */
  maxFileBytes?: number;
  /** Maximum total analysed bytes. Default 16 MiB. */
  maxTotalBytes?: number;
  /** Admission mode: include normally excluded entries and refuse links/special files. */
  strict?: boolean;
  signal?: AbortSignal;
}

/** One hint that the plugin may fetch and execute unreviewed remote content. */
export interface RemoteContentIndicator {
  reason: string;
  evidence: EvidenceRef;
}

/** Result of {@link detectHeuristically}. */
export interface HeuristicScanResult {
  /** Heuristic capability facts; always in a separate array from verified facts. */
  facts: CapabilityFact[];
  coverage: ScanCoverage;
  errors: DetectionError[];
  notes: string[];
  /** Evidence for `auto_update` reasoning; never promoted to verified facts. */
  remote_content_indicators: RemoteContentIndicator[];
}

const DEFAULT_LIMITS = {
  maxFiles: 2000,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 16 * 1024 * 1024,
};

const MAX_SNIPPET_LENGTH = 200;
const MAX_EVIDENCE_PER_FACT = 100;
const MAX_REMOTE_INDICATORS = 50;

const SKIP_DIRECTORIES = new Set(['node_modules', '.git']);
const SKIP_FILE_NAMES = new Set(['.DS_Store']);
const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);
const CONFIG_EXTENSIONS = new Set(['.json', '.yml', '.yaml']);
const PROMPT_DIRECTORIES = new Set(['skills', 'prompts']);

const CATALOG_ORDER = new Map<CapabilityPath, number>(
  CAPABILITY_DEFINITIONS.map((definition, index) => [definition.path, index]),
);

/** One capability rule: a regex plus a stable rule id used as fact detail. */
interface HeuristicRule {
  capability: CapabilityPath;
  detail: string;
  pattern: RegExp;
}

/**
 * Rule catalog. It is intentionally conservative per rule but explicit about
 * the known Host APIs a plugin can use; matches are marked heuristic.
 */
const RULES: readonly HeuristicRule[] = [
  { capability: 'network.fetch', detail: 'fetch-call', pattern: /\bfetch\s*\(/ },
  { capability: 'network.fetch', detail: 'http-request', pattern: /\bhttps?\.request\s*\(/ },
  { capability: 'network.fetch', detail: 'websocket', pattern: /\bWebSocket\b/ },
  { capability: 'network.fetch', detail: 'http-client', pattern: /\b(?:axios|undici)\b/ },
  { capability: 'process.child_process', detail: 'child-process-import', pattern: /\bchild_process\b/ },
  { capability: 'process.child_process', detail: 'command-exec', pattern: /(?<![.\w$])exec\s*\(/ },
  { capability: 'process.child_process', detail: 'spawn-call', pattern: /\bspawn\s*\(/ },
  { capability: 'process.child_process', detail: 'execfile-call', pattern: /\bexecFile\b/ },
  { capability: 'process.child_process', detail: 'fork-call', pattern: /(?<![.\w$])fork\s*\(/ },
  { capability: 'filesystem.read', detail: 'read-file', pattern: /\breadFile(?:Sync)?\s*\(/ },
  { capability: 'filesystem.read', detail: 'create-read-stream', pattern: /\bcreateReadStream\s*\(/ },
  { capability: 'filesystem.write', detail: 'write-file', pattern: /\bwriteFile(?:Sync)?\s*\(/ },
  { capability: 'filesystem.write', detail: 'create-write-stream', pattern: /\bcreateWriteStream\s*\(/ },
  { capability: 'filesystem.write', detail: 'append-file', pattern: /\bappendFile(?:Sync)?\s*\(/ },
  { capability: 'env.read', detail: 'process-env', pattern: /\bprocess\.env(?:\.|\[)/ },
  { capability: 'credentials.read', detail: 'ctx-credentials', pattern: /\bctx\.credentials\b/ },
  { capability: 'credentials.read', detail: 'credentials-api', pattern: /\bcredentials\.(?:resolve|readRecord)\b/ },
  { capability: 'credentials.read', detail: 'keytar', pattern: /\bkeytar\b/ },
  { capability: 'tool_registry.add', detail: 'tools-register', pattern: /\bctx\.tools\.register\s*\(/ },
  {
    capability: 'tool_registry.intercept',
    detail: 'tools-lifecycle-event',
    pattern: /\bctx\.on\(\s*['"]tools\/(?:pre-execute|post-execute|execute)['"]/,
  },
  { capability: 'tool_registry.override', detail: 'tools-override', pattern: /\bctx\.tools\.override\s*\(/ },
  {
    capability: 'context.prompt_inject',
    detail: 'system-prompt-section',
    pattern: /\bctx\.systemPrompt\.(?:section|context)\b/,
  },
  { capability: 'context.prompt_inject', detail: 'agent-inject', pattern: /\bagent\.inject\b/ },
  {
    capability: 'context.prompt_inject',
    detail: 'system-prompt-event',
    pattern: /\bctx\.on\(\s*['"]system-prompt\/assemble['"]/,
  },
  {
    capability: 'context.prompt_inject',
    detail: 'agent-pre-step-event',
    pattern: /\bctx\.on\(\s*['"]agent\/pre-step['"]/,
  },
  {
    capability: 'context.tool_output_rewrite',
    detail: 'tools-post-execute-event',
    pattern: /\bctx\.on\(\s*['"]tools\/post-execute['"]/,
  },
  { capability: 'context.history_compress', detail: 'compaction', pattern: /\bcompaction\b/ },
  { capability: 'context.history_compress', detail: 'ctx-compaction', pattern: /\bctx\.compaction\b/ },
  { capability: 'dynamic_code.eval', detail: 'eval-call', pattern: /\beval\s*\(/ },
  { capability: 'dynamic_code.eval', detail: 'new-function', pattern: /\bnew\s+Function\s*\(/ },
  { capability: 'dynamic_code.eval', detail: 'node-vm', pattern: /\bnode:vm\b/ },
  { capability: 'dynamic_code.eval', detail: 'vm-run', pattern: /\bvm\.runIn\w*\s*\(/ },
  { capability: 'subagent.spawn', detail: 'ctx-subagents', pattern: /\bctx\.subagents\b/ },
  { capability: 'subagent.spawn', detail: 'subagent', pattern: /\bsubagent\b/ },
  { capability: 'llm.call', detail: 'ctx-llm', pattern: /\bctx\.llm\b/ },
  { capability: 'llm.call', detail: 'llm-stream', pattern: /\bllm\/stream\b/ },
  { capability: 'llm.call', detail: 'generate-call', pattern: /\bgenerate\s*\(/ },
];

/** Dynamic-evaluation + network patterns that suggest remote code execution. */
const REMOTE_CODE_PATTERNS: ReadonlyArray<{ reason: string; pattern: RegExp }> = [
  { reason: 'code: fetch( 使用了非字面量 URL（可能获取未审核的远程内容）', pattern: /\bfetch\s*\(\s*[A-Za-z_$][\w$]*/ },
  { reason: 'code: eval( 执行变量代码', pattern: /\beval\s*\(\s*[A-Za-z_$][\w$]*/ },
  { reason: 'code: new Function( 执行变量代码', pattern: /\bnew\s+Function\s*\(\s*[A-Za-z_$][\w$]*/ },
  { reason: 'code: 动态 import( 加载变量模块', pattern: /\bimport\s*\(\s*[A-Za-z_$][\w$]*\s*\)/ },
];

/** Shell-ish install script fragments that pull remote content. */
const REMOTE_SCRIPT_PATTERN = /(?:curl|wget|npx|npm\s+(?:i|install)|git\s+clone|https?:\/\/)/i;

/** Lifecycle scripts the heuristic inspects for remote content (manifest.ts owns install facts). */
const REMOTE_SCRIPT_NAMES = ['prepublish', 'prepare', 'postinstall'] as const;

/** `cordis.patch.yml` rows that override or disable a composition row. */
const PATCH_OVERRIDE_ROW = /(?:^|\s)override\s*:/;
const PATCH_DISABLED_ROW = /(?:^|\s)disabled\s*:\s*true/;

/** Core bundle package prefix that makes an override a composition override. */
const CORE_PACKAGE_PREFIX = '@deepseek-ai/';

/** Package prefix that identifies a DSH host-runtime dependency. */
const HOST_RUNTIME_PACKAGE_PREFIX = '@deepseek-ai/dsh-';

/** Plain-object guard for untrusted package.json content. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Trim one source line and cap the snippet length (evidence contract: <= 200). */
function trimSnippet(value: string): string {
  return redactUrlCredentials(value.trim()).slice(0, MAX_SNIPPET_LENGTH);
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

/** Byte-order string comparison (locale-independent, deterministic across OSes). */
function compareNames(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

/** A NUL byte in the head of a file means it is binary for our purposes. */
function looksBinary(buffer: Uint8Array): boolean {
  const limit = Math.min(buffer.length, 8000);
  for (let index = 0; index < limit; index += 1) {
    if (buffer[index] === 0) return true;
  }
  return false;
}

/** Accumulator for one capability path. */
interface FactBuilder {
  capability: CapabilityPath;
  evidence: EvidenceRef[];
  evidenceKeys: Set<string>;
  details: string[];
}

/** Mutable walk state; passed by reference through the recursive walker. */
interface ScanState {
  root: string;
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  builders: Map<CapabilityPath, FactBuilder>;
  errors: DetectionError[];
  notes: string[];
  coverageNotes: string[];
  remoteIndicators: RemoteContentIndicator[];
  remoteKeys: Set<string>;
  filesTotal: number;
  filesScanned: number;
  filesRead: number;
  filesSkipped: ScanCoverage['files_skipped'];
  bytesScanned: number;
  bytesRead: number;
  notScannedByExtension: number;
  binarySkipped: number;
  symlinkSkipped: number;
  evidenceTruncated: boolean;
  remoteTruncated: boolean;
  complete: boolean;
  stop: boolean;
  excludedDirectories: Set<string>;
  strict: boolean;
  signal?: AbortSignal;
}

/**
 * Run the built-in heuristic scanner over a plugin directory.
 *
 * The walk is recursive and sorted by path; `node_modules`, `.git` and
 * `.DS_Store` are excluded, symlinks are never followed, binary and oversized
 * files are skipped. Any skip that reduces the inspected surface (unreadable
 * file, invalid manifest, hit limit) sets `coverage.complete = false` and adds
 * a {@link DetectionError}, so the decision layer can fail closed.
 */
export async function detectHeuristically(
  root: string,
  limits: HeuristicLimits = {},
): Promise<HeuristicScanResult> {
  limits.signal?.throwIfAborted();
  let absoluteRoot: string;
  try {
    absoluteRoot = await canonicalTreeRoot(resolve(root), limits.strict === true);
  } catch (error) {
    limits.signal?.throwIfAborted();
    const state = createScanState(resolve(root), limits);
    state.complete = false;
    state.errors.push({
      code: 'scan_root_unreadable',
      message: `无法读取扫描根目录：${errorMessage(error)}`,
      file: '.',
    });
    return buildScanResult(state);
  }

  const state = createScanState(absoluteRoot, limits);
  await analyzePackageJson(state);
  await walkDirectory(state, absoluteRoot, '');
  limits.signal?.throwIfAborted();

  return buildScanResult(state);
}

/** Initialise mutable walk state with resolved limits. */
function createScanState(root: string, limits: HeuristicLimits): ScanState {
  return {
    root,
    maxFiles: positiveInteger(limits.maxFiles, DEFAULT_LIMITS.maxFiles),
    maxFileBytes: positiveInteger(limits.maxFileBytes, DEFAULT_LIMITS.maxFileBytes),
    maxTotalBytes: positiveInteger(limits.maxTotalBytes, DEFAULT_LIMITS.maxTotalBytes),
    builders: new Map<CapabilityPath, FactBuilder>(),
    errors: [],
    notes: [],
    coverageNotes: [],
    remoteIndicators: [],
    remoteKeys: new Set<string>(),
    filesTotal: 0,
    filesScanned: 0,
    filesRead: 0,
    filesSkipped: [],
    bytesScanned: 0,
    bytesRead: 0,
    notScannedByExtension: 0,
    binarySkipped: 0,
    symlinkSkipped: 0,
    evidenceTruncated: false,
    remoteTruncated: false,
    complete: true,
    stop: false,
    excludedDirectories: new Set<string>(),
    strict: limits.strict === true,
    signal: limits.signal,
  };
}

/** Fall back to the default unless the caller passed a positive safe integer. */
function positiveInteger(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

/** Get (or create) the accumulator for one capability path. */
function ensureBuilder(state: ScanState, capability: CapabilityPath): FactBuilder {
  const existing = state.builders.get(capability);
  if (existing !== undefined) return existing;
  const created: FactBuilder = {
    capability,
    evidence: [],
    evidenceKeys: new Set<string>(),
    details: [],
  };
  state.builders.set(capability, created);
  return created;
}

/** Attach one de-duplicated evidence row to a capability. */
function addEvidence(state: ScanState, capability: CapabilityPath, evidence: EvidenceRef): void {
  const builder = ensureBuilder(state, capability);
  if (builder.evidence.length >= MAX_EVIDENCE_PER_FACT) {
    state.evidenceTruncated = true;
    return;
  }
  const key = evidenceKey(evidence);
  if (builder.evidenceKeys.has(key)) return;
  builder.evidenceKeys.add(key);
  builder.evidence.push({ ...evidence });
}

/** Attach a rule id to an already-created fact (never creates a fact alone). */
function addDetail(state: ScanState, capability: CapabilityPath, detail: string): void {
  const builder = state.builders.get(capability);
  if (builder === undefined) return;
  if (!builder.details.includes(detail)) builder.details.push(detail);
}

/** Record a remote-content indicator, de-duplicated and capped. */
function addRemoteIndicator(state: ScanState, reason: string, evidence: EvidenceRef): void {
  if (state.remoteIndicators.length >= MAX_REMOTE_INDICATORS) {
    state.remoteTruncated = true;
    return;
  }
  const key = `${reason}\u0000${evidenceKey(evidence)}`;
  if (state.remoteKeys.has(key)) return;
  state.remoteKeys.add(key);
  state.remoteIndicators.push({ reason, evidence: { ...evidence } });
}

/** True for files this scanner is allowed to analyse. */
function isEligibleFile(relativePath: string): boolean {
  const extension = posix.extname(relativePath).toLowerCase();
  if (CODE_EXTENSIONS.has(extension)) return true;
  if (CONFIG_EXTENSIONS.has(extension)) return true;
  return isPromptMarkdown(relativePath);
}

/** Markdown is only in scope under `skills/` or `prompts/` (prompt surface). */
function isPromptMarkdown(relativePath: string): boolean {
  if (posix.extname(relativePath).toLowerCase() !== '.md') return false;
  return relativePath
    .split('/')
    .some((segment) => PROMPT_DIRECTORIES.has(segment.toLowerCase()));
}

/** True for files the raw code rule catalog runs against. */
function isRuleTarget(relativePath: string): boolean {
  const extension = posix.extname(relativePath).toLowerCase();
  return CODE_EXTENSIONS.has(extension) || isPromptMarkdown(relativePath);
}

/** Read `package.json` once for dependency / auto-update / install-script hints. */
async function analyzePackageJson(state: ScanState): Promise<void> {
  const packagePath = join(state.root, 'package.json');
  let text: string;
  try {
    text = (await readTreeFile(packagePath, MAX_PACKAGE_JSON_BYTES, {
      rejectHardLinks: true,
      signal: state.signal,
    })).toString('utf8');
  } catch (error) {
    state.signal?.throwIfAborted();
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      state.notes.push('未找到 package.json：跳过依赖、autoUpdate 与安装脚本的启发式分析。');
      return;
    }
    state.complete = false;
    state.errors.push({
      code: 'package_json_unreadable',
      message: `无法读取 package.json：${errorMessage(error)}`,
      file: 'package.json',
    });
    return;
  }

  let packageJson: unknown;
  try {
    packageJson = JSON.parse(text) as unknown;
  } catch {
    state.complete = false;
    state.errors.push({
      code: 'package_json_invalid',
      message: 'package.json 不是合法 JSON，无法完成 autoUpdate/依赖启发式分析。',
      file: 'package.json',
    });
    return;
  }
  if (!isPlainObject(packageJson)) {
    state.complete = false;
    state.errors.push({
      code: 'package_json_invalid',
      message: 'package.json 顶层不是对象，无法完成 autoUpdate/依赖启发式分析。',
      file: 'package.json',
    });
    return;
  }

  analyzeAutoUpdateDeclaration(state, packageJson);
  analyzeInstallScripts(state, packageJson);
  analyzeDependencySources(state, packageJson);
}

/** Manifest-level `autoUpdate: true` declarations (same fields manifest.ts reads). */
function analyzeAutoUpdateDeclaration(state: ScanState, packageJson: Record<string, unknown>): void {
  const candidates: ReadonlyArray<{ field: string; path: string }> = [
    { field: 'package.json#dsh.autoUpdate', path: 'dsh.autoUpdate' },
    { field: 'package.json#dsh.bundle.autoUpdate', path: 'dsh.bundle.autoUpdate' },
    { field: 'package.json#autoUpdate', path: 'autoUpdate' },
  ];
  for (const candidate of candidates) {
    if (readPath(packageJson, candidate.path) !== true) continue;
    addRemoteIndicator(
      state,
      'package.json 声明 autoUpdate: true（运行中可能获取并执行未审核内容）',
      { field: candidate.field },
    );
    return;
  }
}

/** Install-time scripts that fetch remote content (lifecycle facts stay in manifest.ts). */
function analyzeInstallScripts(state: ScanState, packageJson: Record<string, unknown>): void {
  const scripts = isPlainObject(packageJson.scripts) ? packageJson.scripts : undefined;
  if (scripts === undefined) return;
  for (const name of REMOTE_SCRIPT_NAMES) {
    const command = scripts[name];
    if (typeof command !== 'string' || !REMOTE_SCRIPT_PATTERN.test(command)) continue;
    addRemoteIndicator(state, `安装生命周期脚本 ${name} 包含远程内容获取或执行命令`, {
      field: `package.json#scripts.${name}`,
      snippet: trimSnippet(command),
    });
  }
}

/** Host-runtime dependencies plus non-registry dependency sources. */
function analyzeDependencySources(state: ScanState, packageJson: Record<string, unknown>): void {
  const hostPackages: string[] = [];
  for (const section of ['dependencies', 'peerDependencies', 'optionalDependencies'] as const) {
    const sectionValue = packageJson[section];
    if (!isPlainObject(sectionValue)) continue;
    for (const [name, spec] of Object.entries(sectionValue)) {
      if (typeof spec !== 'string' || spec.trim() === '') continue;
      if (
        (section === 'dependencies' || section === 'peerDependencies') &&
        name.startsWith(HOST_RUNTIME_PACKAGE_PREFIX)
      ) {
        addEvidence(state, 'host_runtime.dependency', {
          field: `package.json#${section}.${name}`,
        });
        hostPackages.push(`${name}@${redactUrlCredentials(spec)}`);
      }
      // Non-registry dependency sources are reported by manifest.ts and the
      // type-C diff. They are install-time provenance facts, not evidence that
      // the plugin fetches code at runtime, so they must not become an
      // auto_update finding here.
    }
  }
  for (const entry of hostPackages) {
    addDetail(state, 'host_runtime.dependency', `dsh-host-package:${entry}`);
  }
}

/** Recursively walk one directory in deterministic name order. */
async function walkDirectory(
  state: ScanState,
  absoluteDirectory: string,
  relativeDirectory: string,
): Promise<void> {
  if (state.stop) return;
  state.signal?.throwIfAborted();

  let directory;
  let entries;
  try {
    directory = await assertTreeDirectory(absoluteDirectory);
    entries = await treeDirectoryEntries(absoluteDirectory);
    await assertTreeDirectory(absoluteDirectory, directory);
  } catch (error) {
    state.complete = false;
    state.errors.push({
      code: 'scan_unreadable_directory',
      message: `无法读取目录：${errorMessage(error)}`,
      file: relativeDirectory === '' ? '.' : relativeDirectory,
    });
    return;
  }
  entries.sort((left, right) => compareNames(left.name, right.name));

  for (const entry of entries) {
    if (state.stop) return;
    state.signal?.throwIfAborted();
    const relativePath = relativeDirectory === '' ? entry.name : `${relativeDirectory}/${entry.name}`;
    const absolutePath = join(absoluteDirectory, entry.name);

    if (entry.isDirectory()) {
      if (!state.strict && SKIP_DIRECTORIES.has(entry.name)) {
        if (!state.excludedDirectories.has(relativePath)) {
          state.excludedDirectories.add(relativePath);
          state.coverageNotes.push(`已跳过目录 ${relativePath}（内置排除）`);
        }
        continue;
      }
      await walkDirectory(state, absolutePath, relativePath);
      continue;
    }

    if (entry.isSymbolicLink()) {
      state.filesTotal += 1;
      state.symlinkSkipped += 1;
      state.filesSkipped.push({ path: relativePath, reason: 'symlink' });
      if (state.strict) markUnreadable(state, relativePath, new Error('symbolic links are not allowed'));
      continue;
    }

    if (!entry.isFile()) {
      if (state.strict) markUnreadable(state, relativePath, new Error('expected a regular file'));
      continue;
    }

    state.filesTotal += 1;
    if (!state.strict && SKIP_FILE_NAMES.has(entry.name)) {
      state.filesSkipped.push({ path: relativePath, reason: 'excluded_file' });
      continue;
    }
    if (!isEligibleFile(relativePath)) {
      state.notScannedByExtension += 1;
      continue;
    }
    await analyzeFile(state, absolutePath, relativePath);
  }
  try {
    await assertTreeDirectory(absoluteDirectory, directory);
  } catch (error) {
    state.complete = false;
    state.errors.push({
      code: 'scan_unreadable_directory',
      message: `目录在扫描期间发生变化：${errorMessage(error)}`,
      file: relativeDirectory === '' ? '.' : relativeDirectory,
    });
  }
}

/** Analyse one eligible file, enforcing per-file and global limits. */
async function analyzeFile(state: ScanState, absolutePath: string, relativePath: string): Promise<void> {
  if (state.stop) return;

  if (state.filesRead >= state.maxFiles) {
    state.complete = false;
    state.stop = true;
    state.errors.push({
      code: 'scan_limit_files',
      message: `达到最大扫描文件数 ${state.maxFiles}，遍历已停止（fail-closed）。`,
    });
    return;
  }
  const remaining = state.maxTotalBytes - state.bytesRead;
  let buffer: Buffer;
  try {
    buffer = await readTreeFile(absolutePath, Math.min(state.maxFileBytes, remaining), {
      rejectHardLinks: state.strict,
      signal: state.signal,
    });
  } catch (error) {
    state.signal?.throwIfAborted();
    if (error instanceof FileReadLimitError) {
      state.complete = false;
      if (remaining < state.maxFileBytes) {
        state.stop = true;
        state.errors.push({
          code: 'scan_limit_bytes',
          message: `达到最大扫描字节数 ${state.maxTotalBytes}，遍历已停止（fail-closed）。`,
        });
      } else {
        state.filesSkipped.push({ path: relativePath, reason: 'too_large' });
        state.errors.push({
          code: 'scan_limit_file_size',
          message: `文件超过单文件扫描上限 ${state.maxFileBytes} 字节，已跳过（fail-closed）：${relativePath}`,
          file: relativePath,
        });
      }
    } else {
      markUnreadable(state, relativePath, error);
    }
    return;
  }
  state.filesRead += 1;
  state.bytesRead += buffer.byteLength;

  if (looksBinary(buffer)) {
    state.binarySkipped += 1;
    state.filesSkipped.push({ path: relativePath, reason: 'binary' });
    return;
  }

  state.filesScanned += 1;
  state.bytesScanned += buffer.byteLength;
  const text = buffer.toString('utf8');

  if (basename(relativePath) === 'cordis.patch.yml') {
    analyzeCordisPatch(state, relativePath, text);
    return;
  }
  if (!isRuleTarget(relativePath)) return;

  const lines = text.split('\n');
  for (const [index, rawLine] of lines.entries()) {
    analyzeCodeLine(state, relativePath, index + 1, rawLine);
  }
}

/** Mark a file as unreadable and fail closed. */
function markUnreadable(state: ScanState, relativePath: string, error: unknown): void {
  state.complete = false;
  state.filesSkipped.push({ path: relativePath, reason: 'unreadable' });
  state.errors.push({
    code: 'scan_unreadable_file',
    message: `无法读取文件：${errorMessage(error)}`,
    file: relativePath,
  });
}

/** Apply the raw line rule catalog to one source line. */
function analyzeCodeLine(
  state: ScanState,
  relativePath: string,
  lineNumber: number,
  rawLine: string,
): void {
  const snippet = trimSnippet(rawLine);
  if (snippet === '') return;

  for (const rule of RULES) {
    if (!rule.pattern.test(rawLine)) continue;
    addEvidence(state, rule.capability, { file: relativePath, line: lineNumber, snippet });
    addDetail(state, rule.capability, rule.detail);
  }

  for (const candidate of REMOTE_CODE_PATTERNS) {
    if (!candidate.pattern.test(rawLine)) continue;
    addRemoteIndicator(state, candidate.reason, { file: relativePath, line: lineNumber, snippet });
  }
}

/**
 * Inspect `cordis.patch.yml` for composition overrides.
 *
 * Any `override:` / `disabled: true` row is a tool-registry override; when the
 * file targets `@deepseek-ai/*` packages it is additionally a composition
 * override of the host bundle. Rows keep their `file:line` evidence.
 */
function analyzeCordisPatch(state: ScanState, relativePath: string, text: string): void {
  const targetsCoreBundles = text.includes(CORE_PACKAGE_PREFIX);
  const lines = text.split('\n');
  for (const [index, rawLine] of lines.entries()) {
    const isOverrideRow = PATCH_OVERRIDE_ROW.test(rawLine) || PATCH_DISABLED_ROW.test(rawLine);
    if (!isOverrideRow) continue;
    const snippet = trimSnippet(rawLine);
    if (snippet === '') continue;
    const evidence: EvidenceRef = { file: relativePath, line: index + 1, snippet };
    addEvidence(state, 'tool_registry.override', evidence);
    addDetail(state, 'tool_registry.override', 'cordis-patch-row');
    if (targetsCoreBundles) {
      addEvidence(state, 'composition.override', evidence);
      addDetail(state, 'composition.override', 'cordis-patch-core-override');
    }
  }
}

/** Finalise coverage notes, then materialise sorted facts and indicators. */
function buildScanResult(state: ScanState): HeuristicScanResult {
  if (state.binarySkipped > 0) {
    state.coverageNotes.push(`跳过 ${state.binarySkipped} 个二进制文件。`);
  }
  if (state.symlinkSkipped > 0) {
    state.coverageNotes.push(`跳过 ${state.symlinkSkipped} 个符号链接。`);
  }
  if (state.notScannedByExtension > 0) {
    state.coverageNotes.push(
      `按扩展名跳过 ${state.notScannedByExtension} 个文件（仅扫描代码、配置与 skills/prompts 下的 Markdown）。`,
    );
  }
  if (state.evidenceTruncated) {
    state.notes.push(`单个能力的证据超过 ${MAX_EVIDENCE_PER_FACT} 条，已截断。`);
  }
  if (state.remoteTruncated) {
    state.notes.push(`远程内容指示器超过 ${MAX_REMOTE_INDICATORS} 条，已截断。`);
  }
  if (state.filesScanned === 0 && state.filesTotal > 0) {
    state.notes.push('没有可分析的代码/配置文件：启发式能力事实可能为空。');
  }

  const ordered = [...state.builders.values()]
    .filter((builder) => builder.evidence.length > 0)
    .sort(
      (left, right) =>
        (CATALOG_ORDER.get(left.capability) ?? Number.MAX_SAFE_INTEGER) -
        (CATALOG_ORDER.get(right.capability) ?? Number.MAX_SAFE_INTEGER),
    );

  const facts: CapabilityFact[] = ordered.map((builder) => {
    const detail = builder.details.join(', ');
    return {
      capability: builder.capability,
      ...(isDeclarable(builder.capability) ? { path: builder.capability } : {}),
      evidence: builder.evidence,
      source: HEURISTIC_SOURCE,
      heuristic: true,
      ...(detail !== '' ? { detail } : {}),
    };
  });

  const coverage: ScanCoverage = {
    complete: state.complete,
    files_total: state.filesTotal,
    files_scanned: state.filesScanned,
    files_skipped: state.filesSkipped,
    bytes_scanned: state.bytesScanned,
    notes: state.coverageNotes,
  };

  return {
    facts,
    coverage,
    errors: state.errors,
    notes: state.notes,
    remote_content_indicators: state.remoteIndicators,
  };
}
