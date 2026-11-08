/**
 * `dsh-trust-broker` CLI: the terminal surface of the trust broker.
 *
 * Commands: review / confirm / anchors / audit / scan / version / help.
 * Exit codes are part of the contract: 0 = proceed or admitted, 2 = explicit
 * confirmation required (or content changed), 3 = blocked / unscannable,
 * 1 = usage or internal error. `--json` prints machine-readable output.
 */

import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import type {
  AdmissionOutcome,
  ConfirmationRequirement,
  PolicyConfig,
  SourceMetadata,
  TrustDecision,
} from '../types.ts';
import {
  admitDecision,
  computeDecisionDigest,
} from '../admission/gate.ts';
import { AnchorStore, anchorStorePath } from '../core/anchor-store.ts';
import { detectCapabilities } from '../core/detector.ts';
import { decideStatus, evaluatePluginTrust } from '../core/decision.ts';
import { errorMessage } from '../core/fs-utils.ts';
import { computeContentHash } from '../core/hash.ts';
import { appendJsonLine, readJsonlFile } from '../core/jsonl.ts';
import { ManifestReadError, readPluginManifest } from '../core/manifest.ts';
import { defaultPolicy, loadPolicyFile } from '../core/policy.ts';
import {
  ACK_NEW_CAPABILITY_TOKEN,
  ACK_RED_LINE_TOKEN,
  ACK_SCAN_INCOMPLETE_TOKEN,
  ACK_SOURCE_MISMATCH_TOKEN,
  ACK_SUPPLY_CHAIN_TOKEN,
  ACK_UNSTATED_TOKEN,
  TRUST_BROKER_NAME,
  TRUST_BROKER_VERSION,
} from '../version.ts';
import { confirmRequirement, confirmYesNo, createStdioPrompt } from './prompt.ts';
import type { PromptFn } from './prompt.ts';
import { renderAnchorsList, renderAuditTail, renderDecision, terminalField, terminalJson } from './render.ts';

/** Injectable terminal I/O; CLI tests construct one from memory buffers. */
export interface CliIO {
  stdout(text: string): void;
  stderr(text: string): void;
  prompt: PromptFn;
  closePrompt?(): void;
  isTTY?: boolean;
  env?: NodeJS.ProcessEnv;
}

/** Real terminal I/O. */
export function createNodeIO(): CliIO {
  let prompter: ReturnType<typeof createStdioPrompt> | undefined;
  return {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    isTTY: process.stdin.isTTY === true && process.stdout.isTTY === true,
    env: process.env,
    async prompt(question) {
      prompter ??= createStdioPrompt();
      return prompter.prompt(question);
    },
    closePrompt() {
      prompter?.close();
      prompter = undefined;
    },
  };
}

function helpText(): string {
  return `${TRUST_BROKER_NAME} v${TRUST_BROKER_VERSION} —— DSH 插件信任代理（安装前审查 / 锚定 / 运行时审计）

用法：
  dsh-trust-broker review  <插件目录> [选项]     审查并（可选）确认写入信任锚点
  dsh-trust-broker confirm <插件目录> --accept-hash <内容哈希> [选项]
  dsh-trust-broker anchors [插件名] [选项]       列出信任锚点
  dsh-trust-broker audit [--lines N] [--verify]  查看/校验运行时审计 JSONL
  dsh-trust-broker scan <插件目录> [--json]      只跑静态检出（调试用）
  dsh-trust-broker version | help

审查选项：
  --json                        输出决策 JSON（供 GUI/CI 消费），不进入交互
  --trust-check-report <file>   消费 dsh-trust-check --dir --json 的报告（schemaVersion 2）
  --no-external-scanner         仅用启发式回退检出（heuristic:true）
  --source-metadata <file>      可信来源元数据 JSON（repository / content_sha256 / registry_signature）
  --expected-hash <sha256:...>  期望的规范化内容哈希
  --policy <file>               profile 级策略 JSON（见 docs/SECURITY-MODEL.md）
  --store-dir <dir>             锚点与审计日志目录（默认 $DSH_HOME/trust-broker）
  --anchors-file <file>         覆盖 anchors.jsonl 路径
  --decisions-file <file>       覆盖 decisions.jsonl 路径
  --accept-hash <sha256:...>    确认写入锚点；必须与当前内容哈希一致
  --acknowledge-unstated        确认「未声明权限」
  --acknowledge-new-capability  确认「新增高权限能力」
  --acknowledge-supply-chain    确认「registry 之外的依赖来源」
  --acknowledge-red-line        确认「静态扫描器红线」
  --acknowledge-source-mismatch 确认「来源不一致」（仅当策略允许降级）
  --non-interactive             禁止交互提示（缺少确认时退出码 2）
  --notes <text>                写入锚点的备注

退出码：0 继续/已锚定 · 2 需要确认或内容已变化 · 3 中止/不可扫描 · 1 用法错误
`;
}

function reviewHelp(): string {
  return helpText();
}

const REVIEW_OPTIONS = {
  json: { type: 'boolean' },
  'trust-check-report': { type: 'string' },
  'no-external-scanner': { type: 'boolean' },
  'source-metadata': { type: 'string' },
  'expected-hash': { type: 'string' },
  policy: { type: 'string' },
  'store-dir': { type: 'string' },
  'anchors-file': { type: 'string' },
  'decisions-file': { type: 'string' },
  'accept-hash': { type: 'string' },
  'acknowledge-unstated': { type: 'boolean' },
  'acknowledge-new-capability': { type: 'boolean' },
  'acknowledge-supply-chain': { type: 'boolean' },
  'acknowledge-red-line': { type: 'boolean' },
  'acknowledge-scan-incomplete': { type: 'boolean' },
  'acknowledge-source-mismatch': { type: 'boolean' },
  'non-interactive': { type: 'boolean' },
  notes: { type: 'string' },
  help: { type: 'boolean' },
} as const;

type Values = Record<string, unknown>;

function flag(values: Values, key: string): boolean {
  return values[key] === true;
}

function text(values: Values, key: string): string | undefined {
  const value = values[key];
  return typeof value === 'string' ? value : undefined;
}

const ACK_FLAG_BY_CODE: Record<ConfirmationRequirement['code'], string> = {
  unstated_capabilities: '--acknowledge-unstated',
  new_capability: '--acknowledge-new-capability',
  supply_chain_dependency: '--acknowledge-supply-chain',
  red_line: '--acknowledge-red-line',
  scan_incomplete: '--acknowledge-scan-incomplete',
  source_mismatch: '--acknowledge-source-mismatch',
};

function acknowledgementsFromFlags(values: Values): ConfirmationRequirement['code'][] {
  const codes: ConfirmationRequirement['code'][] = [];
  if (flag(values, 'acknowledge-unstated')) codes.push('unstated_capabilities');
  if (flag(values, 'acknowledge-new-capability')) codes.push('new_capability');
  if (flag(values, 'acknowledge-supply-chain')) codes.push('supply_chain_dependency');
  if (flag(values, 'acknowledge-red-line')) codes.push('red_line');
  if (flag(values, 'acknowledge-scan-incomplete')) codes.push('scan_incomplete');
  if (flag(values, 'acknowledge-source-mismatch')) codes.push('source_mismatch');
  return codes;
}

function readJsonObject(file: string): Record<string, unknown> {
  const source = readFileSync(file, 'utf8');
  let raw: unknown;
  try {
    raw = JSON.parse(source) as unknown;
  } catch {
    throw new Error('来源元数据不是合法 JSON。');
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`不是 JSON 对象：${file}`);
  }
  return raw as Record<string, unknown>;
}

function loadSourceMetadata(
  cwd: string,
  metadataPath: string | undefined,
  expectedHash: string | undefined,
): SourceMetadata | undefined {
  let metadata: SourceMetadata | undefined;
  if (metadataPath !== undefined) {
    const raw = readJsonObject(resolve(cwd, metadataPath));
    for (const field of ['content_sha256', 'tarball_sha256']) {
      if (raw[field] !== undefined && typeof raw[field] !== 'string') {
        throw new Error(`来源元数据字段 ${field} 必须是字符串。`);
      }
    }
    metadata = {
      ...(typeof raw.spec === 'string' ? { spec: raw.spec } : {}),
      ...(typeof raw.repository === 'string' ? { repository: raw.repository } : {}),
      ...(typeof raw.content_sha256 === 'string' ? { content_sha256: raw.content_sha256 } : {}),
      ...(typeof raw.tarball_sha256 === 'string' ? { tarball_sha256: raw.tarball_sha256 } : {}),
      ...(raw.registry_signature === 'verified' ||
      raw.registry_signature === 'unverified' ||
      raw.registry_signature === 'absent'
        ? { registry_signature: raw.registry_signature }
        : {}),
      ...(typeof raw.published_at === 'string' ? { published_at: raw.published_at } : {}),
      ...(typeof raw.deprecated === 'boolean' ? { deprecated: raw.deprecated } : {}),
    };
  }
  if (expectedHash !== undefined) {
    metadata = { ...(metadata ?? {}), content_sha256: expectedHash };
  }
  return metadata;
}

function readOptionString(values: Values, key: string): string | undefined {
  return text(values, key);
}

interface ReviewContext {
  values: Values;
  positionals: string[];
  cwd: string;
  io: CliIO;
  env: NodeJS.ProcessEnv;
  mode: 'review' | 'confirm';
}

/** Resolve shared paths (store dir, journals) for review/confirm. */
async function resolveReviewPaths(context: ReviewContext): Promise<{
  storeDir: string;
  anchorsFile: string;
  decisionsFile: string;
  policyOverrides: Partial<PolicyConfig>;
}> {
  const { values, cwd } = context;
  const policyOverrides: Partial<PolicyConfig> = {};
  const policyPath = readOptionString(values, 'policy');
  if (policyPath !== undefined) {
    Object.assign(policyOverrides, await loadPolicyFile(resolve(cwd, policyPath)));
  }
  const storeDir =
    readOptionString(values, 'store-dir') ??
    (typeof policyOverrides.store_dir === 'string' ? policyOverrides.store_dir : undefined) ??
    defaultPolicy(context.env).store_dir;
  policyOverrides.store_dir = storeDir;
  const anchorsFile =
    readOptionString(values, 'anchors-file') ?? anchorStorePath(storeDir);
  const decisionsFile =
    readOptionString(values, 'decisions-file') ?? join(storeDir, 'decisions.jsonl');
  return { storeDir, anchorsFile, decisionsFile, policyOverrides };
}

function decisionExitCode(decision: TrustDecision, missing: readonly unknown[]): number {
  if (decision.action === 'block_for_review') return 3;
  if (decision.action === 'confirm' || missing.length > 0) return 2;
  return 0;
}

interface JournalOptions {
  outcome?: AdmissionOutcome | null;
  accepted?: boolean;
  reason?: string;
  acknowledgements?: readonly string[];
}

/** Append one decision-journal line; never fails the command. */
function recordDecisionJournal(
  io: CliIO,
  file: string,
  decision: TrustDecision,
  options: JournalOptions = {},
): void {
  const outcome = options.outcome ?? null;
  const accepted = outcome !== null ? outcome.accepted : (options.accepted ?? false);
  const record = {
    schema_version: 1 as const,
    type: 'decision',
    ts: new Date().toISOString(),
    plugin_id: decision.plugin.id,
    plugin_version: decision.plugin.version,
    content_hash: decision.content_hash,
    status: decision.status,
    action: decision.action,
    accepted,
    ...(outcome?.accepted === false ? { reason: outcome.reason } : options.reason !== undefined ? { reason: options.reason } : {}),
    acknowledged:
      outcome !== null && outcome.accepted
        ? outcome.acknowledged
        : (options.acknowledgements ?? []),
    decision_digest: computeDecisionDigest(decision),
    confirmations_required: decision.confirmations_required.map((item) => item.code),
    diff_ids: decision.diffs.map((diff) => diff.id),
    error_codes: decision.errors.map((issue) => issue.code),
    red_lines_count: decision.red_lines.length,
    scanner: decision.scanner.name,
    anchor_version:
      outcome !== null && outcome.accepted && outcome.anchor !== undefined
        ? outcome.anchor.version
        : null,
  };
  try {
    appendJsonLine(file, record);
  } catch (error) {
    io.stderr(`警告：决策记录写入失败（${terminalField(file)}）：${terminalField(errorMessage(error))}\n`);
  }
}

async function reviewCommand(
  args: string[],
  io: CliIO,
  cwd: string,
  mode: 'review' | 'confirm',
): Promise<number> {
  const parsed = parseArgs({
    args,
    options: REVIEW_OPTIONS,
    allowPositionals: true,
    strict: true,
  });
  const values = parsed.values as unknown as Values;
  const positionals = parsed.positionals;
  const env = io.env ?? process.env;

  if (values.help === true) {
    io.stdout(reviewHelp());
    return 0;
  }
  if (positionals.length !== 1) {
    io.stderr('用法：dsh-trust-broker review <插件目录> [选项]\n');
    return 1;
  }

  const root = resolve(cwd, positionals[0] as string);
  const json = flag(values, 'json');
  const interactive = io.isTTY === true && !flag(values, 'non-interactive') && !json;
  const acceptHash = readOptionString(values, 'accept-hash');

  if (mode === 'confirm' && !interactive && acceptHash === undefined) {
    io.stderr('confirm 需要 --accept-hash <内容哈希>（或在交互终端中运行）。\n');
    return 1;
  }

  const { anchorsFile, decisionsFile, policyOverrides } = await resolveReviewPaths({
    values,
    positionals,
    cwd,
    io,
    env,
    mode,
  });

  let sourceMetadata: SourceMetadata | undefined;
  try {
    sourceMetadata = loadSourceMetadata(
      cwd,
      readOptionString(values, 'source-metadata'),
      readOptionString(values, 'expected-hash'),
    );
  } catch (error) {
    io.stderr(`来源元数据错误：${terminalField(errorMessage(error))}\n`);
    return 1;
  }

  const decision = await evaluatePluginTrust({
    root,
    ...(readOptionString(values, 'trust-check-report') !== undefined
      ? {
          scannerReportPath: resolve(
            cwd,
            readOptionString(values, 'trust-check-report') as string,
          ),
        }
      : {}),
    ...(flag(values, 'no-external-scanner') ? { noExternalScanner: true } : {}),
    ...(sourceMetadata !== undefined ? { sourceMetadata } : {}),
    policy: policyOverrides,
    anchorsFile,
  });

  const acknowledgements = acknowledgementsFromFlags(values);
  if (!json) io.stdout(renderDecision(decision, { color: io.isTTY === true && env.NO_COLOR === undefined }));
  let missing = decision.confirmations_required.filter(
    (requirement) => !acknowledgements.includes(requirement.code),
  );

  if (interactive && missing.length > 0 && decision.action !== 'block_for_review') {
    for (const requirement of missing) {
      const accepted = await confirmRequirement(io.prompt, requirement);
      if (!accepted) {
        io.stdout('已中止：未完成强制确认，未写入信任锚点。\n');
        recordDecisionJournal(io, decisionsFile, decision, {
          accepted: false,
          reason: 'user_aborted_confirmation',
          acknowledgements,
        });
        return 2;
      }
      acknowledgements.push(requirement.code);
    }
    missing = [];
  }

  if (json) {
    let outcome = null;
    if (acceptHash !== undefined) {
      outcome = await admitDecision(decision, {
        acknowledgements,
        acceptedContentHash: acceptHash,
        anchorsFile,
        notes: readOptionString(values, 'notes'),
      });
      recordDecisionJournal(io, decisionsFile, decision, { outcome });
    } else {
      recordDecisionJournal(io, decisionsFile, decision, {
        accepted: false,
        reason: missing.length > 0 ? 'confirmation_required' : 'review_only',
        acknowledgements,
      });
    }
    io.stdout(`${terminalJson({ decision, admission: outcome })}\n`);
    if (outcome !== null) {
      if (outcome.accepted) return 0;
      return outcome.reason === 'blocked_for_review' ? 3 : 2;
    }
    return decisionExitCode(decision, missing);
  }

  if (decision.action === 'block_for_review') {
    recordDecisionJournal(io, decisionsFile, decision, {
      accepted: false,
      reason: 'blocked_for_review',
      acknowledgements,
    });
    return 3;
  }

  if (missing.length > 0) {
    io.stdout('\n缺少强制确认，默认暂停等待确认（不得进入加载）。补充以下参数后重试：\n');
    for (const requirement of missing) {
      io.stdout(`  ${ACK_FLAG_BY_CODE[requirement.code]}   # ${requirement.ack_token}\n`);
    }
    recordDecisionJournal(io, decisionsFile, decision, {
      accepted: false,
      reason: 'confirmation_required',
      acknowledgements,
    });
    return 2;
  }

  let shouldAnchor = false;
  if (acceptHash !== undefined) {
    shouldAnchor = true;
  } else if (interactive) {
    shouldAnchor = await confirmYesNo(
      io.prompt,
      '以上信息已核对，写入信任锚点？',
    );
    if (!shouldAnchor) {
      io.stdout('已中止：未写入信任锚点。\n');
      recordDecisionJournal(io, decisionsFile, decision, {
        accepted: false,
        reason: 'user_declined_anchor',
        acknowledgements,
      });
      return 2;
    }
  } else if (mode === 'confirm') {
    io.stderr('confirm 需要 --accept-hash（非交互模式）。\n');
    return 1;
  }

  if (!shouldAnchor) {
    io.stdout('\n审查完成（未写入锚点；使用 --accept-hash 或交互确认可写入信任锚点）。\n');
    recordDecisionJournal(io, decisionsFile, decision, {
      accepted: false,
      reason: 'review_only',
      acknowledgements,
    });
    return decision.action === 'confirm' ? 2 : 0;
  }

  const outcome = await admitDecision(decision, {
    acknowledgements,
    acceptedContentHash: acceptHash ?? decision.content_hash ?? undefined,
    anchorsFile,
    notes: readOptionString(values, 'notes'),
  });
  recordDecisionJournal(io, decisionsFile, decision, { outcome });

  if (outcome.accepted) {
    io.stdout(
      `\n已写入信任锚点：${terminalField(outcome.anchor.plugin_id)}@${terminalField(outcome.anchor.version)}\n  内容哈希  ${outcome.anchor.content_hash}\n  锚点文件  ${terminalField(anchorsFile)}\n  决策摘要  ${computeDecisionDigest(decision)}\n`,
    );
    return 0;
  }

  io.stdout(`\n未进入加载：${outcome.message}\n`);
  for (const requirement of outcome.required) {
    io.stdout(`  [${requirement.code}] ${requirement.message}（确认口令：「${requirement.ack_token}」）\n`);
  }
  return outcome.reason === 'blocked_for_review' ? 3 : 2;
}

const ANCHORS_OPTIONS = {
  json: { type: 'boolean' },
  'store-dir': { type: 'string' },
  'anchors-file': { type: 'string' },
  help: { type: 'boolean' },
} as const;

async function anchorsCommand(args: string[], io: CliIO, cwd: string): Promise<number> {
  const parsed = parseArgs({
    args,
    options: ANCHORS_OPTIONS,
    allowPositionals: true,
    strict: true,
  });
  const values = parsed.values as unknown as Values;
  const positionals = parsed.positionals;
  const env = io.env ?? process.env;
  if (values.help === true) {
    io.stdout('用法：dsh-trust-broker anchors [插件名] [--store-dir DIR] [--json]\n');
    return 0;
  }
  const storeDir =
    text(values, 'store-dir') ?? defaultPolicy(env).store_dir;
  const anchorsFile = text(values, 'anchors-file') ?? anchorStorePath(storeDir);
  const pluginId = positionals[0];
  const store = new AnchorStore({ file: anchorsFile });
  const anchors = await store.list(pluginId);
  const snapshot = await store.snapshot();
  if (snapshot.errors.length > 0) {
    io.stderr(`警告：锚点文件存在 ${snapshot.errors.length} 行无法解析，已跳过。\n`);
  }
  if (flag(values, 'json')) {
    io.stdout(`${terminalJson({ anchors_file: anchorsFile, anchors })}\n`);
  } else {
    io.stdout(renderAnchorsList(anchors, { color: io.isTTY === true }));
    io.stdout(`  文件：${terminalField(anchorsFile)}\n`);
  }
  void cwd;
  return 0;
}

const AUDIT_OPTIONS = {
  json: { type: 'boolean' },
  verify: { type: 'boolean' },
  lines: { type: 'string' },
  'store-dir': { type: 'string' },
  'audit-file': { type: 'string' },
  help: { type: 'boolean' },
} as const;

function verifyAuditRecord(record: unknown): string[] {
  if (record === null || typeof record !== 'object') return ['不是 JSON 对象'];
  const entry = record as Record<string, unknown>;
  const problems: string[] = [];
  if (entry.schema_version !== 1) problems.push('schema_version 必须为 1');
  if (typeof entry.event !== 'string') problems.push('缺少 event');
  if (typeof entry.seq !== 'number') problems.push('缺少 seq');
  if (typeof entry.id !== 'string') problems.push('缺少 id');
  if (typeof entry.ts !== 'string') problems.push('缺少 ts');
  return problems;
}

async function auditCommand(args: string[], io: CliIO): Promise<number> {
  const parsed = parseArgs({ args, options: AUDIT_OPTIONS, strict: true });
  const values = parsed.values as unknown as Values;
  const env = io.env ?? process.env;
  if (values.help === true) {
    io.stdout(
      '用法：dsh-trust-broker audit [--lines N] [--verify] [--store-dir DIR] [--audit-file FILE]\n',
    );
    return 0;
  }
  const storeDir = text(values, 'store-dir') ?? defaultPolicy(env).store_dir;
  const auditFile = text(values, 'audit-file') ?? join(storeDir, 'audit.jsonl');
  let lineLimit = 20;
  if (text(values, 'lines') !== undefined) {
    const parsed = Number.parseInt(text(values, 'lines') as string, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      io.stderr('--lines 必须是正整数\n');
      return 1;
    }
    lineLimit = parsed;
  }

  const { records, errors } = readJsonlFile(auditFile);
  const tail = records.slice(-lineLimit);

  if (flag(values, 'verify')) {
    const problems: string[] = [];
    for (const error of errors) {
      problems.push(`第 ${error.line} 行无法解析：${error.message}`);
    }
    records.forEach((record, index) => {
      for (const problem of verifyAuditRecord(record)) {
        problems.push(`记录 ${index + 1}：${problem}`);
      }
    });
    if (flag(values, 'json')) {
      io.stdout(`${terminalJson({ audit_file: auditFile, records: records.length, problems })}\n`);
    } else {
      io.stdout(`审计日志：${terminalField(auditFile)}\n  记录数：${records.length}\n  格式问题：${problems.length}\n`);
      for (const problem of problems.slice(0, 20)) io.stdout(`  · ${terminalField(problem)}\n`);
    }
    return problems.length === 0 ? 0 : 1;
  }

  if (flag(values, 'json')) {
    io.stdout(`${terminalJson({ audit_file: auditFile, records: tail })}\n`);
  } else {
    io.stdout(`审计日志：${terminalField(auditFile)}（最后 ${tail.length} 条）\n`);
    io.stdout(renderAuditTail(tail));
  }
  return 0;
}

const SCAN_OPTIONS = {
  json: { type: 'boolean' },
  'trust-check-report': { type: 'string' },
  'no-external-scanner': { type: 'boolean' },
  'store-dir': { type: 'string' },
  policy: { type: 'string' },
  help: { type: 'boolean' },
} as const;

async function scanCommand(args: string[], io: CliIO, cwd: string): Promise<number> {
  const parsed = parseArgs({
    args,
    options: SCAN_OPTIONS,
    allowPositionals: true,
    strict: true,
  });
  const values = parsed.values as unknown as Values;
  const positionals = parsed.positionals;
  if (values.help === true) {
    io.stdout(
      '用法：dsh-trust-broker scan <插件目录> [--json] [--trust-check-report FILE] [--no-external-scanner]\n',
    );
    return 0;
  }
  if (positionals.length !== 1) {
    io.stderr('用法：dsh-trust-broker scan <插件目录> [--json]\n');
    return 1;
  }
  const root = resolve(cwd, positionals[0] as string);
  const snapshotDir = await mkdtemp(join(tmpdir(), 'dsh-trust-broker-'));
  try {
    return await scanSnapshot(root, snapshotDir, values, io, cwd);
  } finally {
    await rm(snapshotDir, { recursive: true, force: true });
  }
}

async function scanSnapshot(
  root: string, snapshotDir: string, values: Values, io: CliIO, cwd: string,
): Promise<number> {
  const hashResult = await computeContentHash(root, { strict: true, snapshotDir });
  if (!hashResult.complete) {
    if (flag(values, 'json')) io.stdout(`${terminalJson({ content_hash: hashResult })}\n`);
    else io.stderr(`无法读取插件：${terminalField(hashResult.errors.map((issue) => issue.message).join('；'))}\n`);
    return 3;
  }
  let manifest;
  try {
    manifest = await readPluginManifest(snapshotDir);
  } catch (error) {
    if (error instanceof ManifestReadError) {
      io.stderr(`无法读取插件：${terminalField(error.message)}\n`);
      return 3;
    }
    throw error;
  }
  const policyPath = text(values, 'policy');
  const policy = policyPath === undefined ? {} : await loadPolicyFile(resolve(cwd, policyPath));
  const detection = await detectCapabilities({
    root: manifest.root,
    candidateRoot: root,
    manifest,
    limits: { strict: true },
    bin: policy.trust_check_bin,
    ...(text(values, 'trust-check-report') !== undefined
      ? { scannerReportPath: resolve(cwd, text(values, 'trust-check-report') as string) }
      : {}),
    ...(flag(values, 'no-external-scanner') ? { noExternalScanner: true } : {}),
  });
  const code = decideStatus(manifest, detection) === 'unscannable' ? 3 : 0;
  if (flag(values, 'json')) {
    io.stdout(`${terminalJson({
      plugin: { id: manifest.plugin_id, version: manifest.version },
      declaration: { status: manifest.declaration.status, source_field: manifest.declaration.source_field },
      detection,
      content_hash: hashResult,
    })}\n`);
    return code;
  }
  io.stdout(
    [
      `插件：${terminalField(manifest.plugin_id)}@${terminalField(manifest.version)}`,
      `声明状态：${manifest.declaration.status}`,
      `事实层能力：${detection.facts.length} 条（source: ${terminalField(detection.primary_source.name)}）`,
      `启发式事实：${detection.heuristic_facts.length} 条（heuristic:true）`,
      `红线：${detection.red_lines.length} 条（事实陈列）`,
      `内容哈希：${hashResult.hash}`,
      `扫描覆盖：${detection.coverage.complete ? '完整' : '不完整'}`,
    ].join('\n') + '\n',
  );
  return code;
}

/**
 * Run the CLI. Returns the process exit code; never throws for user errors.
 * `cwd` and `io` are injectable for tests.
 */
export async function runCli(
  argv: string[],
  io: CliIO = createNodeIO(),
  cwd: string = process.cwd(),
): Promise<number> {
  const [command = 'help', ...rest] = argv;
  try {
    switch (command) {
      case 'review':
        return await reviewCommand(rest, io, cwd, 'review');
      case 'confirm':
        return await reviewCommand(rest, io, cwd, 'confirm');
      case 'anchors':
        return await anchorsCommand(rest, io, cwd);
      case 'audit':
        return await auditCommand(rest, io);
      case 'scan':
        return await scanCommand(rest, io, cwd);
      case 'version':
      case '--version':
      case '-V':
        io.stdout(`${TRUST_BROKER_NAME} ${TRUST_BROKER_VERSION}\n`);
        return 0;
      case 'help':
      case '--help':
      case '-h':
        io.stdout(helpText());
        return 0;
      default:
        io.stderr(`未知命令：${terminalField(command)}\n\n${helpText()}`);
        return 1;
    }
  } catch (error) {
    io.stderr(`错误：${terminalField(errorMessage(error))}\n`);
    return 1;
  } finally {
    io.closePrompt?.();
  }
}

/** Every acknowledgement token exported for documentation/tests. */
export const ACK_TOKENS = {
  unstated: ACK_UNSTATED_TOKEN,
  new_capability: ACK_NEW_CAPABILITY_TOKEN,
  supply_chain: ACK_SUPPLY_CHAIN_TOKEN,
  red_line: ACK_RED_LINE_TOKEN,
  scan_incomplete: ACK_SCAN_INCOMPLETE_TOKEN,
  source_mismatch: ACK_SOURCE_MISMATCH_TOKEN,
} as const;
