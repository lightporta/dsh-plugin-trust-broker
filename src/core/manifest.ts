/**
 * Face one input: read the plugin manifest (`package.json`), locate and validate
 * its permission declaration, and collect install-script / dependency-source /
 * auto-update facts that are independent of any capability declaration.
 *
 * Declaration semantics that matter for the trust decision:
 * - `undefined` (absent) is not `false`; presence is tracked per slot.
 * - a malformed declaration is kept (valid subset preserved) but marked
 *   `malformed`, so the decision can fail closed and say why.
 */

import { basename, join, posix, resolve, win32 } from 'node:path';
import type {
  DeclarationResult,
  DeclarationSlotState,
  DependencySourceFact,
  InstallScriptFact,
  ManifestIssue,
  PluginManifest,
} from '../types.ts';
import { declaredTrueKeys, declarationSlots } from './catalog.ts';
import { errorMessage, redactUrlCredentials } from './fs-utils.ts';
import { canonicalTreeRoot, readTreeFile } from './tree-files.ts';

export type ManifestReadFailureReason =
  | 'unreadable_root'
  | 'missing_package_json'
  | 'invalid_package_json';

/** Raised when the plugin tree cannot even be identified. */
export class ManifestReadError extends Error {
  readonly reason: ManifestReadFailureReason;
  readonly issues: ManifestIssue[];

  constructor(reason: ManifestReadFailureReason, message: string, issues: ManifestIssue[] = []) {
    super(message);
    this.name = 'ManifestReadError';
    this.reason = reason;
    this.issues = issues;
  }
}

/** Declaration fields the broker recognises, in priority order. */
export const DECLARATION_FIELDS = [
  'dsh.capabilities',
  'dsh.bundle.capabilities',
  'dsh.permissions',
  'permissions',
] as const;

export type DeclarationField = (typeof DECLARATION_FIELDS)[number];

const LIFECYCLE_SCRIPT_NAMES = ['preinstall', 'install', 'postinstall', 'prepare'] as const;

export const MAX_PACKAGE_JSON_BYTES = 2 * 1024 * 1024;

const DECLARATION_FAMILIES = new Set([
  'network',
  'process',
  'filesystem',
  'env',
  'tool_registry',
  'context',
  'lifecycle',
  'credentials',
  'subagent',
  'llm',
  'dynamic_code',
]);

type PlainObject = Record<string, unknown>;

function isPlainObject(value: unknown): value is PlainObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Read `a.b.c` from a plain object; `undefined` when any hop is absent. */
export function readPath(source: unknown, dottedPath: string): unknown {
  let current: unknown = source;
  for (const segment of dottedPath.split('.')) {
    if (!isPlainObject(current)) return undefined;
    current = current[segment];
  }
  return current;
}

/**
 * Read the plugin manifest plus its declaration facts.
 *
 * Throws `ManifestReadError` when the tree cannot be identified at all; a
 * declaration that merely fails to parse is returned as `status: 'malformed'`
 * so the decision can still show detection facts and the parse error.
 */
export async function readPluginManifest(
  root: string,
  options: { signal?: AbortSignal } = {},
): Promise<PluginManifest> {
  const requestedRoot = resolve(root);
  options.signal?.throwIfAborted();
  let absoluteRoot: string;
  try {
    absoluteRoot = await canonicalTreeRoot(requestedRoot, true);
  } catch (error) {
    options.signal?.throwIfAborted();
    throw new ManifestReadError(
      'unreadable_root',
      `插件目录不可读：${errorMessage(error)}`,
      [{ code: 'root_unreadable', message: requestedRoot }],
    );
  }

  const packageJsonPath = join(absoluteRoot, 'package.json');
  let packageText: string;
  try {
    packageText = (await readTreeFile(packageJsonPath, MAX_PACKAGE_JSON_BYTES, {
      rejectHardLinks: true,
      signal: options.signal,
    })).toString('utf8');
  } catch (error) {
    options.signal?.throwIfAborted();
    throw new ManifestReadError(
      'missing_package_json',
      `缺少可读的 package.json：${errorMessage(error)}`,
      [{ code: 'package_json_missing', message: packageJsonPath }],
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(packageText) as unknown;
  } catch {
    throw new ManifestReadError(
      'invalid_package_json',
      'package.json 不是合法 JSON',
      [{ code: 'package_json_invalid', message: packageJsonPath }],
    );
  }
  if (!isPlainObject(parsed)) {
    throw new ManifestReadError('invalid_package_json', 'package.json 顶层必须是对象', [
      { code: 'package_json_not_object', message: packageJsonPath },
    ]);
  }

  const name = typeof parsed.name === 'string' ? parsed.name.trim() : '';
  const version = typeof parsed.version === 'string' ? parsed.version.trim() : '';
  if (name === '' || version === '') {
    throw new ManifestReadError(
      'invalid_package_json',
      'package.json 缺少 name 或 version，无法建立插件身份与信任锚点',
      [
        ...(name === '' ? [{ code: 'name_missing', message: 'package.json#name' }] : []),
        ...(version === '' ? [{ code: 'version_missing', message: 'package.json#version' }] : []),
      ],
    );
  }

  const errors: ManifestIssue[] = [];
  const dsh = isPlainObject(parsed.dsh) ? parsed.dsh : undefined;
  const dshBundle = dsh !== undefined && isPlainObject(dsh.bundle) ? dsh.bundle : undefined;
  const bundlePatches = readBundlePatchDeclaration(dshBundle, errors);
  validateEntryPaths(parsed, dshBundle);

  const declarationDiscovery = discoverDeclaration(parsed);
  const declaration =
    declarationDiscovery.found === false
      ? emptyDeclaration()
      : parseDeclaredCapabilities(declarationDiscovery.raw, declarationDiscovery.field);

  const installScripts = readInstallScripts(parsed.scripts, errors);
  const dependencies = readDependencySources(parsed, errors);
  dependencies.push(...await readNpmLockSources(absoluteRoot, errors, options.signal));
  const autoUpdate = readAutoUpdateDeclaration(parsed, dsh, dshBundle);
  const repository = normalizeRepository(parsed.repository);

  return {
    plugin_id: name,
    version,
    root: absoluteRoot,
    package_json_path: packageJsonPath,
    ...(typeof parsed.description === 'string' ? { description: parsed.description } : {}),
    ...(repository !== undefined ? { repository: redactUrlCredentials(repository) } : {}),
    ...(typeof parsed.homepage === 'string' ? { homepage: redactUrlCredentials(parsed.homepage) } : {}),
    ...(readMainEntry(parsed) !== undefined ? { main_entry: readMainEntry(parsed) } : {}),
    dsh_bundle_patches: bundlePatches,
    install_scripts: installScripts,
    dependencies,
    auto_update_declared: autoUpdate.declared,
    ...(autoUpdate.field !== undefined ? { auto_update_field: autoUpdate.field } : {}),
    declaration,
    errors,
  };
}

/** Refuse manifest entry paths that can resolve beyond the hashed package. */
function validateEntryPaths(packageJson: PlainObject, bundle?: PlainObject): void {
  const check = (path: string, field: string): void => {
    const normalized = path.replace(/\\/g, '/');
    const cleaned = posix.normalize(normalized);
    if (posix.isAbsolute(normalized) || win32.isAbsolute(path) || /^[a-zA-Z][\w+.-]*:/.test(path) ||
        cleaned === '..' || cleaned.startsWith('../') || normalized.includes('\0')) {
      throw new ManifestReadError('invalid_package_json', '插件入口指向候选目录之外', [
        { code: 'unsafe_manifest_entry', message: field },
      ]);
    }
  };
  if (typeof packageJson.main === 'string') check(packageJson.main, 'package.json#main');
  const declaredPatch = bundle?.patch;
  const patchEntries =
    typeof declaredPatch === 'string'
      ? [declaredPatch]
      : Array.isArray(declaredPatch)
        ? declaredPatch.filter((entry): entry is string => typeof entry === 'string')
        : [];
  for (const [index, entry] of patchEntries.entries()) {
    check(
      entry,
      typeof declaredPatch === 'string'
        ? 'package.json#dsh.bundle.patch'
        : `package.json#dsh.bundle.patch[${index}]`,
    );
  }

  const exports: unknown[] = [packageJson.exports];
  while (exports.length > 0) {
    const entry = exports.pop();
    if (typeof entry === 'string') check(entry, 'package.json#exports');
    else if (Array.isArray(entry)) for (const value of entry) exports.push(value);
    else if (isPlainObject(entry)) for (const value of Object.values(entry)) exports.push(value);
  }
}

interface DeclarationDiscovery {
  found: boolean;
  raw?: unknown;
  field: string;
}

/**
 * Normalize the declared DSH bundle patch surface.
 *
 * DSH accepts either a single relative path or an ordered string array. Both
 * forms are recorded so the detector can analyse exactly the files the loader
 * would apply; non-string entries are fail-closed manifest issues because their
 * composition effect cannot be reviewed.
 */
export function readBundlePatchDeclaration(
  bundle: PlainObject | undefined,
  errors: ManifestIssue[],
): string[] {
  const raw = bundle?.patch;
  if (raw === undefined) return [];
  const field = 'package.json#dsh.bundle.patch';
  if (typeof raw === 'string') {
    if (raw.trim() === '') {
      errors.push({ code: 'bundle_patch_invalid', message: `${field} 不能为空字符串`, field });
      return [];
    }
    return [raw];
  }
  if (Array.isArray(raw)) {
    const paths: string[] = [];
    for (const [index, entry] of raw.entries()) {
      if (typeof entry !== 'string' || entry.trim() === '') {
        errors.push({
          code: 'bundle_patch_invalid',
          message: `${field}[${index}] 必须是非空字符串`,
          field: `${field}[${index}]`,
        });
        continue;
      }
      paths.push(entry);
    }
    return paths;
  }
  errors.push({
    code: 'bundle_patch_invalid',
    message: `${field} 必须是字符串或字符串数组`,
    field,
  });
  return [];
}

/** Locate the first declaration field present in package.json. */
export function discoverDeclaration(packageJson: PlainObject): DeclarationDiscovery {
  for (const field of DECLARATION_FIELDS) {
    const raw = readPath(packageJson, field);
    if (raw !== undefined) {
      return { found: true, raw, field: `package.json#${field}` };
    }
  }
  return { found: false, field: '' };
}

/** Declaration result for a plugin that declares nothing. */
export function emptyDeclaration(): DeclarationResult {
  return {
    status: 'unstated',
    declared: {},
    slots: [],
    declared_true_keys: [],
    errors: [],
    notes: ['该插件未提供权限声明（unstated）；检出事实构成其实际能力面。'],
  };
}

/**
 * Parse and validate a raw declaration object.
 *
 * Unknown keys are ignored with a note; a wrong type produces a `malformed`
 * result while the successfully parsed slots are preserved.
 */
export function parseDeclaredCapabilities(raw: unknown, field = 'package.json#dsh.capabilities'): DeclarationResult {
  const errors: ManifestIssue[] = [];
  const notes: string[] = [];

  if (!isPlainObject(raw)) {
    return {
      status: 'malformed',
      source_field: field,
      declared: {},
      slots: [],
      declared_true_keys: [],
      errors: [{ code: 'declaration_not_object', message: `${field} 必须是对象`, field }],
      notes: ['权限声明无法解析，按 unstated 处理。'],
    };
  }

  for (const key of Object.keys(raw)) {
    if (!DECLARATION_FAMILIES.has(key) && key !== 'auto_update') {
      notes.push(`忽略未知的权限声明字段 "${key}"。`);
    }
  }

  const declared: NonNullable<DeclarationResult['declared']> = {};

  const networkRaw = raw.network;
  if (networkRaw !== undefined) {
    if (!isPlainObject(networkRaw)) {
      declarationTypeError(errors, `${field}.network`, '对象');
    } else {
      const network: NonNullable<typeof declared.network> = {};
      const fetch = readBoolean(networkRaw, 'fetch', `${field}.network.fetch`, errors);
      if (fetch !== undefined) network.fetch = fetch;
      const socket = readBoolean(networkRaw, 'socket', `${field}.network.socket`, errors);
      if (socket !== undefined) network.socket = socket;
      const domains = readStringArray(
        networkRaw,
        'outbound_domains',
        `${field}.network.outbound_domains`,
        errors,
      );
      if (domains !== undefined) network.outbound_domains = domains;
      declared.network = network;
    }
  }

  const processRaw = raw.process;
  if (processRaw !== undefined) {
    if (!isPlainObject(processRaw)) {
      declarationTypeError(errors, `${field}.process`, '对象');
    } else {
      const process: NonNullable<typeof declared.process> = {};
      const child = readBoolean(processRaw, 'child_process', `${field}.process.child_process`, errors);
      if (child !== undefined) process.child_process = child;
      const exec = readBoolean(processRaw, 'exec', `${field}.process.exec`, errors);
      if (exec !== undefined) process.exec = exec;
      declared.process = process;
    }
  }

  const filesystemRaw = raw.filesystem;
  if (filesystemRaw !== undefined) {
    if (!isPlainObject(filesystemRaw)) {
      declarationTypeError(errors, `${field}.filesystem`, '对象');
    } else {
      const filesystem: NonNullable<typeof declared.filesystem> = {};
      const read = readBoolean(filesystemRaw, 'read', `${field}.filesystem.read`, errors);
      if (read !== undefined) filesystem.read = read;
      const write = readBoolean(filesystemRaw, 'write', `${field}.filesystem.write`, errors);
      if (write !== undefined) filesystem.write = write;
      const roots = readStringArray(filesystemRaw, 'roots', `${field}.filesystem.roots`, errors);
      if (roots !== undefined) filesystem.roots = roots;
      declared.filesystem = filesystem;
    }
  }

  const envRaw = raw.env;
  if (envRaw !== undefined) {
    if (!isPlainObject(envRaw)) {
      declarationTypeError(errors, `${field}.env`, '对象');
    } else {
      const env: NonNullable<typeof declared.env> = {};
      const read = readStringArray(envRaw, 'read', `${field}.env.read`, errors);
      if (read !== undefined) env.read = read;
      declared.env = env;
    }
  }

  const toolRegistryRaw = raw.tool_registry;
  if (toolRegistryRaw !== undefined) {
    if (!isPlainObject(toolRegistryRaw)) {
      declarationTypeError(errors, `${field}.tool_registry`, '对象');
    } else {
      const toolRegistry: NonNullable<typeof declared.tool_registry> = {};
      for (const key of ['add', 'override', 'intercept'] as const) {
        const value = readBoolean(toolRegistryRaw, key, `${field}.tool_registry.${key}`, errors);
        if (value !== undefined) toolRegistry[key] = value;
      }
      declared.tool_registry = toolRegistry;
    }
  }

  const contextRaw = raw.context;
  if (contextRaw !== undefined) {
    if (!isPlainObject(contextRaw)) {
      declarationTypeError(errors, `${field}.context`, '对象');
    } else {
      const context: NonNullable<typeof declared.context> = {};
      for (const key of ['prompt_inject', 'tool_output_rewrite', 'history_compress'] as const) {
        const value = readBoolean(contextRaw, key, `${field}.context.${key}`, errors);
        if (value !== undefined) context[key] = value;
      }
      declared.context = context;
    }
  }

  const lifecycleRaw = raw.lifecycle;
  if (lifecycleRaw !== undefined) {
    if (!isPlainObject(lifecycleRaw)) {
      declarationTypeError(errors, `${field}.lifecycle`, '对象');
    } else {
      const lifecycle: NonNullable<typeof declared.lifecycle> = {};
      for (const key of ['preinstall', 'install', 'postinstall', 'prepare'] as const) {
        const value = readBoolean(lifecycleRaw, key, `${field}.lifecycle.${key}`, errors);
        if (value !== undefined) lifecycle[key] = value;
      }
      declared.lifecycle = lifecycle;
    }
  }

  const autoUpdate = readBoolean(raw, 'auto_update', `${field}.auto_update`, errors);
  if (autoUpdate !== undefined) declared.auto_update = autoUpdate;

  const credentialsRaw = raw.credentials;
  if (credentialsRaw !== undefined) {
    if (!isPlainObject(credentialsRaw)) {
      declarationTypeError(errors, `${field}.credentials`, '对象');
    } else {
      const credentials: NonNullable<typeof declared.credentials> = {};
      const read = readBoolean(credentialsRaw, 'read', `${field}.credentials.read`, errors);
      if (read !== undefined) credentials.read = read;
      declared.credentials = credentials;
    }
  }

  const subagentRaw = raw.subagent;
  if (subagentRaw !== undefined) {
    if (!isPlainObject(subagentRaw)) {
      declarationTypeError(errors, `${field}.subagent`, '对象');
    } else {
      const subagent: NonNullable<typeof declared.subagent> = {};
      const spawn = readBoolean(subagentRaw, 'spawn', `${field}.subagent.spawn`, errors);
      if (spawn !== undefined) subagent.spawn = spawn;
      declared.subagent = subagent;
    }
  }

  const llmRaw = raw.llm;
  if (llmRaw !== undefined) {
    if (!isPlainObject(llmRaw)) {
      declarationTypeError(errors, `${field}.llm`, '对象');
    } else {
      const llm: NonNullable<typeof declared.llm> = {};
      const call = readBoolean(llmRaw, 'call', `${field}.llm.call`, errors);
      if (call !== undefined) llm.call = call;
      declared.llm = llm;
    }
  }

  const dynamicCodeRaw = raw.dynamic_code;
  if (dynamicCodeRaw !== undefined) {
    if (!isPlainObject(dynamicCodeRaw)) {
      declarationTypeError(errors, `${field}.dynamic_code`, '对象');
    } else {
      const dynamicCode: NonNullable<typeof declared.dynamic_code> = {};
      const evaluate = readBoolean(dynamicCodeRaw, 'eval', `${field}.dynamic_code.eval`, errors);
      if (evaluate !== undefined) dynamicCode.eval = evaluate;
      declared.dynamic_code = dynamicCode;
    }
  }

  const slots: DeclarationSlotState[] = declarationSlots(declared);
  const status: DeclarationResult['status'] =
    errors.length > 0
      ? 'malformed'
      : slots.length > 0
        ? 'declared'
        : Object.keys(raw).length > 0
          ? 'incomplete'
          : 'unstated';

  if (status === 'incomplete') {
    notes.push('权限声明存在但没有任何可识别的能力槽位，视为不完整。');
  }
  if (status === 'malformed') {
    notes.push('权限声明存在但无法完整解析：按 unstated 处理，并保留已解析出的部分。');
  }

  return {
    status,
    source_field: field,
    declared,
    slots,
    declared_true_keys: declaredTrueKeys(declared),
    errors,
    notes,
  };
}

function declarationTypeError(errors: ManifestIssue[], field: string, expected: string): void {
  errors.push({
    code: 'declaration_type',
    message: `${field} 必须是${expected}`,
    field,
  });
}

function readBoolean(
  container: PlainObject,
  key: string,
  field: string,
  errors: ManifestIssue[],
): boolean | undefined {
  const value = container[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') {
    declarationTypeError(errors, `${field}`, '布尔值');
    return undefined;
  }
  return value;
}

function readStringArray(
  container: PlainObject,
  key: string,
  field: string,
  errors: ManifestIssue[],
): string[] | undefined {
  const value = container[key];
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    declarationTypeError(errors, `${field}`, '字符串数组');
    return undefined;
  }
  return [...new Set(value as string[])];
}

function readInstallScripts(scripts: unknown, errors: ManifestIssue[]): InstallScriptFact[] {
  if (scripts === undefined) return [];
  if (!isPlainObject(scripts)) {
    errors.push({ code: 'scripts_invalid', message: 'package.json#scripts 不是对象' });
    return [];
  }
  const facts: InstallScriptFact[] = [];
  for (const name of LIFECYCLE_SCRIPT_NAMES) {
    const command = scripts[name];
    if (command === undefined) continue;
    if (typeof command !== 'string') {
      errors.push({ code: 'script_invalid', message: `package.json#scripts.${name} 必须是字符串` });
      continue;
    }
    facts.push({
      name,
      command: redactUrlCredentials(command),
      evidence: { field: `package.json#scripts.${name}` },
    });
  }
  return facts;
}

/** Classify a dependency specifier by where the code would come from. */
export function classifyDependencySpec(spec: string): DependencySourceFact['kind'] {
  const trimmed = spec.trim();
  if (/^npm:/i.test(trimmed)) return 'registry';
  if (/^(git\+|git:|github:|gitlab:|bitbucket:)/i.test(trimmed)) return 'git';
  if (/^(file:|link:)/i.test(trimmed)) return 'file';
  if (/^https?:/i.test(trimmed)) return 'url';
  if (/^workspace:/i.test(trimmed)) return 'workspace';
  if (/^(npm:)?(\^|~|>=|<=|>|<|=)?\s*v?\d/.test(trimmed)) return 'registry';
  if (/^\*$|^x$/i.test(trimmed)) return 'registry';
  if (/^(latest|next|beta|alpha)$/i.test(trimmed)) return 'registry';
  return 'other';
}

function readDependencySources(packageJson: PlainObject, errors: ManifestIssue[]): DependencySourceFact[] {
  const facts: DependencySourceFact[] = [];
  for (const section of ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies'] as const) {
    const value = packageJson[section];
    if (value === undefined) continue;
    if (!isPlainObject(value)) {
      errors.push({ code: 'dependencies_invalid', message: `package.json#${section} 不是对象` });
      continue;
    }
    for (const [name, spec] of Object.entries(value)) {
      if (typeof spec !== 'string') {
        errors.push({
          code: 'dependency_invalid',
          message: `package.json#${section}.${name} 必须是字符串`,
        });
        continue;
      }
      facts.push({
        name,
        spec: redactUrlCredentials(spec),
        kind: classifyDependencySpec(spec),
        evidence: { field: `package.json#${section}.${name}` },
      });
    }
  }
  return facts;
}

/** npm gives shrinkwrap precedence over package-lock when both are present. */
async function readNpmLockSources(
  root: string,
  errors: ManifestIssue[],
  signal?: AbortSignal,
): Promise<DependencySourceFact[]> {
  for (const file of ['npm-shrinkwrap.json', 'package-lock.json']) {
    let lock: unknown;
    try {
      const bytes = await readTreeFile(join(root, file), MAX_PACKAGE_JSON_BYTES, {
        rejectHardLinks: true, signal,
      });
      lock = JSON.parse(bytes.toString('utf8')) as unknown;
    } catch (error) {
      signal?.throwIfAborted();
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      errors.push({ code: 'dependency_invalid', message: `${file} 无法完整读取或解析`, field: file });
      return [];
    }
    if (!isPlainObject(lock) || (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) ||
        !isPlainObject(lock.packages)) {
      errors.push({ code: 'dependency_lock_unsupported', message: `${file} 不是可识别的 npm v2/v3 锁文件`, field: file });
      return [];
    }

    const facts: DependencySourceFact[] = [];
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (path === '' || !isPlainObject(entry) || typeof entry.resolved !== 'string') continue;
      const spec = entry.resolved;
      const kind = /^https:\/\/registry\.npmjs\.org\//i.test(spec)
        ? 'registry'
        : entry.link === true ? 'file' : classifyDependencySpec(spec);
      facts.push({
        name: typeof entry.name === 'string' ? entry.name : path.split('node_modules/').at(-1) ?? path,
        spec: redactUrlCredentials(spec),
        kind,
        evidence: { file, field: `${file}#packages[${JSON.stringify(path)}].resolved` },
      });
    }
    return facts;
  }
  return [];
}

function readAutoUpdateDeclaration(
  packageJson: PlainObject,
  dsh: PlainObject | undefined,
  dshBundle: PlainObject | undefined,
): { declared: boolean; field?: string } {
  const candidates: Array<[string, unknown]> = [
    ['package.json#dsh.autoUpdate', dsh?.autoUpdate],
    ['package.json#dsh.bundle.autoUpdate', dshBundle?.autoUpdate],
    ['package.json#autoUpdate', packageJson.autoUpdate],
  ];
  for (const [field, value] of candidates) {
    if (value === true) return { declared: true, field };
  }
  return { declared: false };
}

function normalizeRepository(repository: unknown): string | undefined {
  if (typeof repository === 'string') {
    const trimmed = repository.trim();
    return trimmed === '' ? undefined : trimmed;
  }
  if (isPlainObject(repository) && typeof repository.url === 'string') {
    const trimmed = repository.url.trim();
    return trimmed === '' ? undefined : trimmed;
  }
  return undefined;
}

function readMainEntry(packageJson: PlainObject): string | undefined {
  if (typeof packageJson.main === 'string') return packageJson.main;
  const exports = packageJson.exports;
  if (typeof exports === 'string') return exports;
  if (isPlainObject(exports)) {
    const root = exports['.'];
    if (typeof root === 'string') return root;
    if (isPlainObject(root) && typeof root.default === 'string') return root.default;
  }
  return undefined;
}

/** Folder name fallback, used only for diagnostics and error messages. */
export function fallbackPluginId(root: string): string {
  return basename(resolve(root));
}
