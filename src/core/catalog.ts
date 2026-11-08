/**
 * Capability catalog: the single vocabulary shared by the declaration parser,
 * the static detector, the diff engine and the runtime scope checker.
 *
 * Every path here is either declarable (has a slot inside `DeclaredCapabilities`)
 * or observable-only (e.g. `host_runtime.dependency`). The `high_privilege` flag
 * implements the brief's binary marker: it defines when a diff counts as
 * `new_capability: true` and therefore enters the mandatory confirmation queue.
 * The flag is a catalog decision, documented in docs/SECURITY-MODEL.md, not a
 * per-decision judgement.
 */

import type {
  CapabilityFamily,
  CapabilityKey,
  CapabilityPath,
  DeclaredCapabilities,
  DeclarationSlotState,
} from '../types.ts';

export interface CapabilityDefinition {
  path: CapabilityPath;
  family: CapabilityFamily;
  label_zh: string;
  label_en: string;
  high_privilege: boolean;
  /** True when the path has a slot inside `DeclaredCapabilities`. */
  declarable: boolean;
  /** Metadata pointer inside `dsh.capabilities`. */
  declaration_pointer: string;
  /** Ids reported by `dsh-trust-check` (schema 2) that imply this path. */
  scanner_ids: readonly string[];
}

export const CAPABILITY_DEFINITIONS: readonly CapabilityDefinition[] = [
  {
    path: 'network.fetch',
    family: 'network',
    label_zh: '网络访问（fetch/http/https）',
    label_en: 'Network fetch (http/https)',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'network.fetch',
    scanner_ids: ['network'],
  },
  {
    path: 'network.socket',
    family: 'network',
    label_zh: '网络套接字（socket/tcp/ws）',
    label_en: 'Network socket (tcp/ws)',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'network.socket',
    scanner_ids: [],
  },
  {
    path: 'process.child_process',
    family: 'process',
    label_zh: '子进程（child_process）',
    label_en: 'Spawns child processes',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'process.child_process',
    scanner_ids: ['shell'],
  },
  {
    path: 'process.exec',
    family: 'process',
    label_zh: '命令执行（exec/spawn）',
    label_en: 'Executes commands',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'process.exec',
    scanner_ids: [],
  },
  {
    path: 'filesystem.read',
    family: 'filesystem',
    label_zh: '读取文件',
    label_en: 'Reads files',
    high_privilege: false,
    declarable: true,
    declaration_pointer: 'filesystem.read',
    scanner_ids: ['fs-read'],
  },
  {
    path: 'filesystem.write',
    family: 'filesystem',
    label_zh: '写入文件',
    label_en: 'Writes files',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'filesystem.write',
    scanner_ids: ['fs-write'],
  },
  {
    path: 'env.read',
    family: 'env',
    label_zh: '读取环境变量',
    label_en: 'Reads environment variables',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'env.read',
    scanner_ids: ['env'],
  },
  {
    path: 'tool_registry.add',
    family: 'tool_registry',
    label_zh: '注册工具',
    label_en: 'Registers tools',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'tool_registry.add',
    scanner_ids: [],
  },
  {
    path: 'tool_registry.override',
    family: 'tool_registry',
    label_zh: '覆盖工具/组合',
    label_en: 'Overrides tools or composition rows',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'tool_registry.override',
    scanner_ids: [],
  },
  {
    path: 'tool_registry.intercept',
    family: 'tool_registry',
    label_zh: '拦截工具调用',
    label_en: 'Intercepts tool calls',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'tool_registry.intercept',
    scanner_ids: [],
  },
  {
    path: 'context.prompt_inject',
    family: 'context',
    label_zh: '注入提示词/上下文',
    label_en: 'Injects prompt or context text',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'context.prompt_inject',
    scanner_ids: [],
  },
  {
    path: 'context.tool_output_rewrite',
    family: 'context',
    label_zh: '改写工具输出',
    label_en: 'Rewrites tool output',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'context.tool_output_rewrite',
    scanner_ids: [],
  },
  {
    path: 'context.history_compress',
    family: 'context',
    label_zh: '压缩/替换会话历史',
    label_en: 'Compresses or replaces session history',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'context.history_compress',
    scanner_ids: [],
  },
  {
    path: 'lifecycle.preinstall',
    family: 'lifecycle',
    label_zh: '安装前脚本（preinstall）',
    label_en: 'preinstall script',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'lifecycle.preinstall',
    scanner_ids: [],
  },
  {
    path: 'lifecycle.install',
    family: 'lifecycle',
    label_zh: '安装脚本（install）',
    label_en: 'install script',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'lifecycle.install',
    scanner_ids: [],
  },
  {
    path: 'lifecycle.postinstall',
    family: 'lifecycle',
    label_zh: '安装后脚本（postinstall）',
    label_en: 'postinstall script',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'lifecycle.postinstall',
    scanner_ids: [],
  },
  {
    path: 'lifecycle.prepare',
    family: 'lifecycle',
    label_zh: '打包/安装准备脚本（prepare）',
    label_en: 'prepare script',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'lifecycle.prepare',
    scanner_ids: [],
  },
  {
    path: 'auto_update',
    family: 'auto_update',
    label_zh: '自动更新或运行中获取远程内容',
    label_en: 'Auto-update or runtime remote content',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'auto_update',
    scanner_ids: [],
  },
  {
    path: 'credentials.read',
    family: 'credentials',
    label_zh: '读取凭据/密钥',
    label_en: 'Reads credentials or secrets',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'credentials.read',
    scanner_ids: ['credentials'],
  },
  {
    path: 'subagent.spawn',
    family: 'subagent',
    label_zh: '启动子代理',
    label_en: 'Starts sub-agents',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'subagent.spawn',
    scanner_ids: ['subagent'],
  },
  {
    path: 'llm.call',
    family: 'llm',
    label_zh: '调用模型',
    label_en: 'Calls a model',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'llm.call',
    scanner_ids: ['llm'],
  },
  {
    path: 'dynamic_code.eval',
    family: 'dynamic_code',
    label_zh: '运行时执行代码（eval/Function/vm）',
    label_en: 'Evaluates code at runtime',
    high_privilege: true,
    declarable: true,
    declaration_pointer: 'dynamic_code.eval',
    scanner_ids: ['dynamic-code'],
  },
  {
    path: 'host_runtime.dependency',
    family: 'host_runtime',
    label_zh: '依赖 DSH 宿主运行时包',
    label_en: 'Depends on the DSH host runtime',
    high_privilege: false,
    declarable: false,
    declaration_pointer: '',
    scanner_ids: ['host-runtime'],
  },
  {
    path: 'composition.override',
    family: 'composition',
    label_zh: '覆盖/禁用 DSH 核心组合行',
    label_en: 'Overrides or disables a core bundle row',
    high_privilege: true,
    declarable: false,
    declaration_pointer: '',
    scanner_ids: [],
  },
] as const;

export const CAPABILITY_BY_PATH: ReadonlyMap<CapabilityPath, CapabilityDefinition> = new Map(
  CAPABILITY_DEFINITIONS.map((definition) => [definition.path, definition]),
);

export const FAMILY_LABELS: Readonly<Record<CapabilityFamily, { zh: string; en: string }>> = {
  network: { zh: '网络', en: 'Network' },
  process: { zh: '子进程与命令执行', en: 'Process and command execution' },
  filesystem: { zh: '文件系统', en: 'Filesystem' },
  env: { zh: '环境变量', en: 'Environment' },
  tool_registry: { zh: '工具注册表', en: 'Tool registry' },
  context: { zh: '上下文', en: 'Context' },
  lifecycle: { zh: '安装生命周期', en: 'Install lifecycle' },
  auto_update: { zh: '自动更新', en: 'Auto-update' },
  credentials: { zh: '凭据', en: 'Credentials' },
  subagent: { zh: '子代理', en: 'Sub-agents' },
  llm: { zh: '模型调用', en: 'LLM calls' },
  dynamic_code: { zh: '动态代码', en: 'Dynamic code' },
  host_runtime: { zh: '宿主运行时依赖', en: 'Host runtime dependency' },
  composition: { zh: '组合覆盖', en: 'Composition override' },
};

/** Declarable paths, in catalog order. */
export const DECLARABLE_PATHS: readonly CapabilityPath[] = CAPABILITY_DEFINITIONS.filter(
  (definition) => definition.declarable,
).map((definition) => definition.path);

/** Scanner capability id -> paths implied by it (primary path first). */
export const SCANNER_CAPABILITY_MAP: Readonly<Record<string, readonly CapabilityPath[]>> = (() => {
  const map: Record<string, CapabilityPath[]> = {};
  for (const definition of CAPABILITY_DEFINITIONS) {
    for (const scannerId of definition.scanner_ids) {
      const current = map[scannerId];
      if (current === undefined) {
        map[scannerId] = [definition.path];
      } else {
        current.push(definition.path);
      }
    }
  }
  return map;
})();

export function definitionOf(path: CapabilityPath): CapabilityDefinition | undefined {
  return CAPABILITY_BY_PATH.get(path);
}

export function capabilityPathOfKey(key: CapabilityKey): CapabilityPath {
  return key;
}

export function isDeclarable(path: CapabilityPath): boolean {
  return definitionOf(path)?.declarable === true;
}

/** Binary marker used by diff records; unknown paths are treated as high privilege. */
export function isHighPrivilege(key: CapabilityKey): boolean {
  return definitionOf(key)?.high_privilege ?? true;
}

export function labelForPath(path: CapabilityPath, language: 'zh' | 'en' = 'zh'): string {
  const definition = definitionOf(path);
  if (definition === undefined) return path;
  return language === 'zh' ? definition.label_zh : definition.label_en;
}

export function familyLabel(family: CapabilityFamily, language: 'zh' | 'en' = 'zh'): string {
  return FAMILY_LABELS[family][language];
}

export function capabilityPathsForScannerId(scannerId: string): readonly CapabilityPath[] {
  return SCANNER_CAPABILITY_MAP[scannerId] ?? [];
}

/** Raw declaration slot value; `undefined` means "not declared at all". */
export function declarationSlotValue(
  declared: DeclaredCapabilities,
  path: CapabilityPath,
): boolean | string[] | undefined {
  switch (path) {
    case 'network.fetch':
      return declared.network?.fetch;
    case 'network.socket':
      return declared.network?.socket;
    case 'process.child_process':
      return declared.process?.child_process;
    case 'process.exec':
      return declared.process?.exec;
    case 'filesystem.read':
      return declared.filesystem?.read;
    case 'filesystem.write':
      return declared.filesystem?.write;
    case 'env.read':
      return declared.env?.read;
    case 'tool_registry.add':
      return declared.tool_registry?.add;
    case 'tool_registry.override':
      return declared.tool_registry?.override;
    case 'tool_registry.intercept':
      return declared.tool_registry?.intercept;
    case 'context.prompt_inject':
      return declared.context?.prompt_inject;
    case 'context.tool_output_rewrite':
      return declared.context?.tool_output_rewrite;
    case 'context.history_compress':
      return declared.context?.history_compress;
    case 'lifecycle.preinstall':
      return declared.lifecycle?.preinstall;
    case 'lifecycle.install':
      return declared.lifecycle?.install;
    case 'lifecycle.postinstall':
      return declared.lifecycle?.postinstall;
    case 'lifecycle.prepare':
      return declared.lifecycle?.prepare;
    case 'auto_update':
      return declared.auto_update;
    case 'credentials.read':
      return declared.credentials?.read;
    case 'subagent.spawn':
      return declared.subagent?.spawn;
    case 'llm.call':
      return declared.llm?.call;
    case 'dynamic_code.eval':
      return declared.dynamic_code?.eval;
    case 'host_runtime.dependency':
    case 'composition.override':
      return undefined;
  }
}

export type DeclarationPathState = 'true' | 'false' | 'absent';

/**
 * Three-state view of one declaration slot: explicit true (including a non-empty
 * `env.read` list), explicit denial (false / empty list), or absent.
 */
export function declarationPathState(
  declared: DeclaredCapabilities,
  path: CapabilityPath,
): DeclarationPathState {
  const value = declarationSlotValue(declared, path);
  if (value === undefined) return 'absent';
  if (Array.isArray(value)) return value.length > 0 ? 'true' : 'false';
  return value ? 'true' : 'false';
}

/** Explicitly present declaration slots (presence is what makes `false` meaningful). */
export function declarationSlots(declared: DeclaredCapabilities): DeclarationSlotState[] {
  const slots: DeclarationSlotState[] = [];
  for (const path of DECLARABLE_PATHS) {
    const value = declarationSlotValue(declared, path);
    if (value === undefined) continue;
    slots.push({ path, present: true, value: Array.isArray(value) ? [...value] : value });
  }
  return slots;
}

/** Keys implied by explicit `true` / non-empty arrays. */
export function declaredTrueKeys(declared: DeclaredCapabilities): CapabilityKey[] {
  return DECLARABLE_PATHS.filter((path) => declarationPathState(declared, path) === 'true');
}

/** Paths explicitly denied by the declaration (`false` or empty array). */
export function declaredFalsePaths(declared: DeclaredCapabilities): CapabilityPath[] {
  return DECLARABLE_PATHS.filter((path) => declarationPathState(declared, path) === 'false');
}

/**
 * Default capability categories a DSH tool call can exercise. Only used to
 * estimate scope; argument-based inference augments/overrides it at runtime.
 */
export const DEFAULT_TOOL_CAPABILITIES: Readonly<Record<string, readonly CapabilityKey[]>> = {
  bash: ['process.exec', 'process.child_process', 'filesystem.read', 'filesystem.write'],
  read: ['filesystem.read'],
  write: ['filesystem.write'],
  edit: ['filesystem.write'],
  apply_patch: ['filesystem.write'],
  glob: ['filesystem.read'],
  grep: ['filesystem.read'],
  read_image: ['filesystem.read'],
  working_directory: [],
  load_workspace_dependencies: [],
  web_search: ['network.fetch'],
  web_fetch: ['network.fetch'],
  subagent: ['subagent.spawn'],
  subagent_fork: ['subagent.spawn'],
  spawn_teammate: ['subagent.spawn'],
  send_message: ['subagent.spawn'],
  workflow: ['subagent.spawn'],
  skill: ['context.prompt_inject'],
  job_output: [],
  job_list: [],
  job_kill: [],
  present: [],
};

/** Argument key fragments that strongly suggest a capability category. */
export const ARGUMENT_CAPABILITY_HINTS: ReadonlyArray<{
  match: RegExp;
  capability: CapabilityKey;
  evidence: string;
}> = [
  { match: /^(https?:\/\/[^\s"']+)/im, capability: 'network.fetch', evidence: 'network-url-argument' },
  { match: /(^|\s)(curl|wget|npx|pnpm|npm|node|python|sh|bash|zsh|exec|spawn)\s/, capability: 'process.exec', evidence: 'shell-command-argument' },
  { match: /(api[_-]?key|token|password|secret|authorization|bearer)/i, capability: 'credentials.read', evidence: 'secret-like-argument' },
];
