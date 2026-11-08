/**
 * Terminal renderer for a trust decision.
 *
 * The layout follows the brief's minimum acceptance list: host-code disclosure,
 * declaration status, detected surface with file:line evidence, install scripts /
 * auto-update / remote content, a copyable content hash, at least one diff, and a
 * suggested binary action. No score, no "safe/malicious" verdict.
 */

import type {
  CapabilityCategorySummary,
  SourceTrust,
  TrustAnchor,
  TrustDecision,
  TrustDiff,
} from '../types.ts';
import { labelForPath } from '../core/catalog.ts';
import { digestHex, shortDigest } from '../core/fs-utils.ts';
import {
  HOST_CODE_NOTICE_ZH,
  TRUST_BROKER_LABEL_ZH,
  TRUST_BROKER_VERSION,
} from '../version.ts';

export interface RenderOptions {
  color?: boolean;
}

interface Palette {
  bold(text: string): string;
  dim(text: string): string;
  red(text: string): string;
  yellow(text: string): string;
  green(text: string): string;
  cyan(text: string): string;
}

function palette(enabled: boolean): Palette {
  const wrap = (code: string) => (text: string) => (enabled ? `\u001b[${code}m${text}\u001b[0m` : text);
  return {
    bold: wrap('1'),
    dim: wrap('2'),
    red: wrap('31'),
    yellow: wrap('33'),
    green: wrap('32'),
    cyan: wrap('36'),
  };
}

const LABEL_WIDTH = 18;

/** Escape controls and line breaks in untrusted text before rendering it. */
export function terminalField(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/gu, (character) =>
    character.split('').map((unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
  );
}

/** JSON.stringify already escapes C0 controls inside JSON strings. */
export function terminalJson(value: unknown): string {
  return JSON.stringify(value, null, 2).replace(/[\u007f-\u009f\u2028\u2029\p{Cf}]/gu, terminalField);
}

function row(label: string, value: string): string {
  return `  ${label.padEnd(LABEL_WIDTH)}${value}`;
}

function section(title: string): string {
  return `\n${title}`;
}

/** `file:line` or metadata-field pointer for one evidence row. */
export function formatEvidence(
  evidence: { file?: string; line?: number; field?: string; snippet?: string } | undefined,
): string {
  if (evidence === undefined) return '-';
  const location =
    evidence.file !== undefined
      ? `${evidence.file}${evidence.line !== undefined ? `:${evidence.line}` : ''}`
      : evidence.field !== undefined
        ? evidence.field
        : '-';
  return evidence.snippet !== undefined && evidence.snippet !== ''
    ? `${terminalField(location)}  ${terminalField(truncate(evidence.snippet, 96))}`
    : terminalField(location);
}

function truncate(text: string, length: number): string {
  const trimmed = text.replace(/\s+/g, ' ').trim();
  return trimmed.length <= length ? trimmed : `${trimmed.slice(0, length)}…`;
}

export function declarationStatusLabel(status: TrustDecision['declaration']['status']): string {
  switch (status) {
    case 'declared':
      return '已声明（declared）';
    case 'unstated':
      return '未声明（unstated）';
    case 'incomplete':
      return '声明不完整（incomplete）';
    case 'malformed':
      return '声明无法解析（malformed）';
  }
}

export function sourceTrustLabel(trust: SourceTrust): string {
  switch (trust.kind) {
    case 'registry_signature':
      return '调用方报告 registry 签名已核验，内容哈希匹配';
    case 'hash_match':
      return '来源哈希匹配';
    case 'hash_mismatch':
      return '来源哈希不匹配';
    case 'unverified':
      return '未验证';
    case 'undeclared':
      return '来源未声明';
  }
}

export function actionLabel(action: TrustDecision['action']): string {
  switch (action) {
    case 'proceed':
      return '建议继续（proceed）';
    case 'confirm':
      return '需要确认（confirm）';
    case 'block_for_review':
      return '暂停并人工复核（block_for_review）';
  }
}

function diffTypeLabel(type: TrustDiff['type']): string {
  switch (type) {
    case 'A_declaration_insufficient':
      return 'A 声明不足';
    case 'B_capability_drift':
      return 'B 声明漂移';
    case 'C_source_content_mismatch':
      return 'C 来源不一致';
  }
}

function renderCategoryLine(category: CapabilityCategorySummary): string {
  const paths = category.capability_paths.map((path) => labelForPath(path)).join('、');
  const evidence = category.evidence[0] !== undefined ? `  （${formatEvidence(category.evidence[0])}）` : '';
  return `  · ${terminalField(category.label)}：${terminalField(paths)}${evidence}`;
}

function renderDiff(diff: TrustDiff): string[] {
  const lines: string[] = [];
  const capability = diff.capability !== undefined ? labelForPath(diff.capability) : '(元数据)';
  lines.push(
    `  [${diffTypeLabel(diff.type)}] ${terminalField(capability)}  new_capability=${diff.new_capability ? 'true' : 'false'}${diff.heuristic ? '  heuristic=true' : ''}`,
  );
  lines.push(`      ${terminalField(diff.summary)}`);
  if (diff.declared !== undefined) {
    lines.push(`      声明：${terminalField(diff.declared.field)} = ${terminalField(String(JSON.stringify(diff.declared.value)))}`);
  }
  if (diff.previous !== undefined) {
    lines.push(
      `      上一确认版本：v${terminalField(diff.previous.version)}（${terminalField(diff.previous.confirmed_at)}，${diff.previous.confirmed_by}）`,
    );
  }
  for (const evidence of diff.evidence.slice(0, 3)) {
    lines.push(`      证据：${formatEvidence(evidence)}`);
  }
  return lines;
}

function renderCapabilitySections(
  decision: TrustDecision,
  out: string[],
  color: Palette,
): void {
  const verifiable = decision.capabilities.categories.filter((category) => !category.heuristic);
  const heuristic = decision.capabilities.categories.filter((category) => category.heuristic);

  out.push(
    section(
      `${color.bold('检出能力面（可复核事实）')}  ${color.dim(terminalField(`source: ${decision.scanner.name}${decision.scanner.version !== undefined ? `@${decision.scanner.version}` : ''}`))}`,
    ),
  );
  if (verifiable.length === 0) {
    out.push('  （本次静态检出未发现可归类的可复核能力）');
  } else {
    for (const category of verifiable) out.push(renderCategoryLine(category));
  }

  out.push(section(color.bold('检出能力面（启发式 heuristic:true，与事实分区）')));
  if (heuristic.length === 0) {
    out.push('  （无：未使用启发式回退，或回退未检出能力）');
  } else {
    for (const category of heuristic) out.push(renderCategoryLine(category));
  }
}

/** Render the full human-readable decision. */
export function renderDecision(decision: TrustDecision, options: RenderOptions = {}): string {
  const color = palette(options.color === true);
  const out: string[] = [];

  out.push(`${color.bold(`${TRUST_BROKER_LABEL_ZH} v${TRUST_BROKER_VERSION}`)}  ·  安装前审查`);
  out.push(color.dim('─'.repeat(78)));

  out.push(row('插件', terminalField(`${decision.plugin.id}@${decision.plugin.version}`)));
  out.push(row('插件目录', terminalField(decision.plugin.root)));
  out.push(row('作为 Host 代码运行', `是 —— ${HOST_CODE_NOTICE_ZH}`));

  out.push(row('来源可信度', `${sourceTrustLabel(decision.source_trust)} · ${terminalField(decision.source_trust.detail)}`));
  if (decision.source_trust.expected_hash !== undefined) {
    out.push(row('', `来源期望哈希：${decision.source_trust.expected_hash}`));
  }
  if (decision.source_trust.actual_hash !== undefined) {
    out.push(row('', `实际内容哈希：${decision.source_trust.actual_hash ?? '未能计算'}`));
  }

  const declarationField =
    decision.declaration.source_field !== undefined
      ? ` · 声明字段 ${decision.declaration.source_field}`
      : '';
  out.push(
    row(
      '权限声明状态',
      `${declarationStatusLabel(decision.declaration.status)}${declarationField}`,
    ),
  );

  renderCapabilitySections(decision, out, color);

  out.push(section(color.bold('安装脚本 / 更新机制')));
  if (decision.summary.install_scripts.length === 0) {
    out.push('  · 安装脚本：无（未声明 preinstall / install / postinstall / prepare）');
  } else {
    for (const script of decision.summary.install_scripts) {
      out.push(`  · 安装脚本：${script.name} —— ${terminalField(truncate(script.command, 110))}`);
    }
  }
  if (decision.summary.auto_update.detected || decision.summary.auto_update.declared) {
    out.push(
      `  · AUTO_UPDATE / 远程内容获取：${color.yellow('检出')} ${terminalField(decision.summary.auto_update.reasons.join('；'))}`,
    );
  } else {
    out.push('  · AUTO_UPDATE / 远程内容获取：未检出');
  }
  if (decision.summary.continuous_trust_warning) {
    out.push(
      `  ${color.yellow('! 该插件在运行中可能获取并执行安装时未审查的远程内容，应视为持续信任而非一次性信任。')}`,
    );
  }
  const nonRegistry = decision.summary.dependency_sources.filter(
    (dependency) => dependency.kind !== 'registry',
  );
  out.push(
    row(
      '依赖来源',
      nonRegistry.length === 0
        ? '全部为 registry 版本范围'
        : `registry 之外：${terminalField(nonRegistry.map((dependency) => `${dependency.name}(${dependency.kind})`).join('、'))}`,
    ),
  );

  out.push(
    row(
      '内容哈希',
      decision.content_hash !== null
        ? color.cyan(decision.content_hash)
        : color.red(`未能计算：${terminalField(decision.content_hash_error ?? '未知原因')}`),
    ),
  );
  out.push(row('信任锚点', terminalField(renderAnchorLine(decision))));

  out.push(section(color.bold(`差异（${decision.diffs.length}）`)));
  if (decision.diffs.length === 0) {
    out.push('  （无差异：声明与检出事实一致，且无上一版本的漂移）');
  } else {
    for (const diff of decision.diffs) out.push(...renderDiff(diff));
  }

  out.push(section(color.bold('建议动作')));
  const actionColor =
    decision.action === 'proceed'
      ? color.green
      : decision.action === 'confirm'
        ? color.yellow
        : color.red;
  out.push(`  ${actionColor(actionLabel(decision.action))}`);
  if (decision.action === 'confirm') {
    out.push('  默认动作：暂停等待显式确认；缺少确认时不得进入加载。');
  } else if (decision.action === 'block_for_review') {
    out.push('  默认动作：中止进入加载，转人工复核。');
  } else {
    out.push('  未引入需要强制确认的高权限能力；确认后可写入信任锚点。');
  }

  if (decision.confirmations_required.length > 0) {
    out.push(section(color.bold(`强制确认（${decision.confirmations_required.length}）`)));
    decision.confirmations_required.forEach((requirement, index) => {
      out.push(`  ${index + 1}. [${requirement.code}] ${terminalField(requirement.message)}`);
      out.push(`     确认口令：「${requirement.ack_token}」`);
    });
  }

  const coverageText = decision.coverage.complete
    ? `完整（${decision.coverage.files_scanned}/${decision.coverage.files_total} 个文件，${decision.coverage.bytes_scanned} 字节）`
    : color.red(
        `不完整（跳过 ${decision.coverage.files_skipped.length} 个文件；${terminalField(decision.coverage.notes.join('；') || '原因见错误列表')}）`,
      );
  out.push(row('扫描覆盖', coverageText));

  if (decision.red_lines.length > 0) {
    out.push(section(color.bold('静态扫描器红线（事实陈列，本工具不裁决）')));
    for (const redLine of decision.red_lines.slice(0, 8)) out.push(`  · ${terminalField(redLine)}`);
  }

  if (decision.errors.length > 0) {
    out.push(section(color.bold(`问题（${decision.errors.length}）`)));
    for (const issue of decision.errors.slice(0, 10)) {
      out.push(`  · [${terminalField(issue.code)}] ${terminalField(issue.message)}`);
    }
  }

  return `${out.join('\n')}\n`;
}

function renderAnchorLine(decision: TrustDecision): string {
  if (decision.anchor.matched !== undefined) {
    const matched = decision.anchor.matched;
    return `与已确认版本 v${matched.version} 的内容哈希一致，已确认能力覆盖本次检出（${matched.confirmed_at}，${matched.confirmed_by}）`;
  }
  if (decision.anchor.latest !== undefined) {
    const latest = decision.anchor.latest;
    return `已有历史锚点 v${latest.version}（${latest.confirmed_at}，${latest.confirmed_by}）；本次内容哈希不同，将按新版本处理`;
  }
  return '无历史锚点（本次确认后将持久化为锚点）';
}

/** Render the anchor journal as a small table. */
export function renderAnchorsList(anchors: readonly TrustAnchor[], options: RenderOptions = {}): string {
  const color = palette(options.color === true);
  const out: string[] = [`${color.bold('信任锚点')}（${anchors.length}）`, color.dim('─'.repeat(78))];
  if (anchors.length === 0) {
    out.push('  （无锚点）');
    return `${out.join('\n')}\n`;
  }
  for (const anchor of anchors) {
    out.push(
      `  ${terminalField(`${anchor.plugin_id}@${anchor.version}`)}`,
      `    内容哈希  ${terminalField(anchor.content_hash)}`,
      `    确认      ${terminalField(anchor.confirmed_at)} by ${anchor.confirmed_by}`,
      `    能力面    ${terminalField(anchor.capability_keys.map((key) => labelForPath(key)).join('、') || '（空）')}`,
      `    决策摘要  ${terminalField(shortDigest(anchor.decision_digest, 16))}  （declaration: ${anchor.declaration_status}）`,
    );
  }
  return `${out.join('\n')}\n`;
}

/** Render raw audit records as a compact tail. */
export function renderAuditTail(records: readonly unknown[]): string {
  const out: string[] = [];
  for (const record of records) {
    if (record === null || typeof record !== 'object') {
      out.push(`  ${terminalField(String(record))}`);
      continue;
    }
    const entry = record as Record<string, unknown>;
    const seq = typeof entry.seq === 'number' ? String(entry.seq).padStart(4, ' ') : '   ?';
    const ts = typeof entry.ts === 'string' ? entry.ts : '-';
    const event = typeof entry.event === 'string' ? entry.event : '-';
    const tool = typeof entry.tool === 'string' ? entry.tool : '';
    const scope = typeof entry.scope === 'string' ? entry.scope : '';
    const extra = [tool, scope].filter((part) => part !== '').join(' · ');
    out.push(`  ${terminalField(`${seq}  ${ts}  ${event}${extra !== '' ? `  ${extra}` : ''}`)}`);
  }
  return `${out.join('\n')}\n`;
}

/** Hex body of a digest for display in tests and messages. */
export function hashBody(hash: string): string {
  return digestHex(hash);
}
