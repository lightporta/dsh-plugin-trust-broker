/**
 * Compact projections and approval-prompt text for the review Host service.
 *
 * The Web client never receives the full `TrustDecision`: it only needs the
 * facts a human decides on. This module maps the decision into the frozen
 * `src/host/protocol.ts` wire types, strips control characters out of every
 * plugin-controlled string, and builds the native approval prompt shown when a
 * model tries to install a plugin through `plugin_manager`.
 */

import type {
  CapabilityFamily,
  ConfirmationRequirement,
  DecisionAction,
  DecisionStatus,
  EvidenceRef,
  TrustDecision,
  TrustDiff,
} from '../types.ts';
import { FAMILY_LABELS, isHighPrivilege, labelForPath } from '../core/catalog.ts';
import { shortDigest } from '../core/fs-utils.ts';
import type { CapabilityPath } from '../types.ts';
import type {
  AgentGateReview,
  UiCapabilityCategory,
  UiConfirmation,
  UiDecision,
  UiDiff,
  UiResolvedCandidate,
} from './protocol.ts';

/** Longest Chinese approval reason; longer text is truncated with an ellipsis. */
export const AGENT_GATE_REASON_LIMIT = 1200;

/** Maximum labels / diff rows shown in one approval prompt. */
const MAX_HIGH_PRIVILEGE_LABELS = 8;
const MAX_DIFF_LINES = 6;

const STATUS_LABELS: Record<DecisionStatus, { zh: string; en: string }> = {
  scanned: { zh: '已扫描', en: 'scanned' },
  unscannable: { zh: '无法完整扫描', en: 'unscannable' },
  malformed_manifest: { zh: '清单无法解析', en: 'malformed manifest' },
};

const ACTION_LABELS: Record<DecisionAction, { zh: string; en: string }> = {
  proceed: { zh: '可继续（无强制确认项）', en: 'proceed (no mandatory confirmation)' },
  confirm: { zh: '需要用户确认', en: 'confirmation required' },
  block_for_review: { zh: '阻断，需人工复核', en: 'blocked for review' },
};

const DECLARATION_LABELS: Record<TrustDecision['declaration']['status'], { zh: string; en: string }> = {
  declared: { zh: '已声明', en: 'declared' },
  unstated: { zh: '未声明', en: 'unstated' },
  incomplete: { zh: '声明不完整', en: 'incomplete' },
  malformed: { zh: '声明无法解析', en: 'malformed' },
};

const SOURCE_KIND_LABELS: Record<UiResolvedCandidate['kind'], { zh: string; en: string }> = {
  local: { zh: '本地目录', en: 'local directory' },
  npm: { zh: 'npm registry', en: 'npm registry' },
  git: { zh: 'git 仓库', en: 'git repository' },
  tarball: { zh: '归档文件', en: 'tarball' },
};

/**
 * Strip control/format characters from untrusted text and cap its length.
 *
 * `multiline` keeps newlines (approval prompts are multi-line); the default
 * collapses all whitespace so a plugin cannot forge fake prompt lines inside a
 * one-line field.
 */
export function sanitizeUntrustedText(input: unknown, maxLength = 400, multiline = false): string {
  const text = typeof input === 'string' ? input : String(input ?? '');
  let cleaned = text.replace(
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/gu,
    ' ',
  );
  cleaned = cleaned.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  cleaned = multiline
    ? cleaned
        .split('\n')
        .map((line) => line.replace(/[ \t]+/g, ' ').trim())
        .filter((line) => line !== '')
        .join('\n')
    : cleaned.replace(/\s+/g, ' ').trim();
  if (cleaned.length <= maxLength) return cleaned;
  return `${cleaned.slice(0, Math.max(0, maxLength - 1))}…`;
}

/** Copy one evidence pointer, sanitizing every plugin-controlled string. */
function toUiEvidence(evidence: EvidenceRef): EvidenceRef {
  const output: EvidenceRef = {};
  if (evidence.file !== undefined) output.file = sanitizeUntrustedText(evidence.file, 300);
  if (evidence.line !== undefined && Number.isInteger(evidence.line)) output.line = evidence.line;
  if (evidence.field !== undefined) output.field = sanitizeUntrustedText(evidence.field, 300);
  if (evidence.snippet !== undefined) output.snippet = sanitizeUntrustedText(evidence.snippet, 200);
  return output;
}

/** Project one diff into the wire shape. */
export function toUiDiff(diff: TrustDiff): UiDiff {
  const output: UiDiff = {
    id: sanitizeUntrustedText(diff.id, 300),
    type: diff.type,
    code: diff.code,
    new_capability: diff.new_capability,
    heuristic: diff.heuristic,
    summary: sanitizeUntrustedText(diff.summary, 600),
    evidence: diff.evidence.map(toUiEvidence),
  };
  if (diff.capability !== undefined) output.capability = diff.capability;
  return output;
}

/** Project one mandatory confirmation into the wire shape. */
export function toUiConfirmation(requirement: ConfirmationRequirement): UiConfirmation {
  const output: UiConfirmation = {
    code: requirement.code,
    message: sanitizeUntrustedText(requirement.message, 600),
    ack_token: sanitizeUntrustedText(requirement.ack_token, 100),
  };
  if (requirement.diff_ids !== undefined) output.diff_ids = [...requirement.diff_ids];
  if (requirement.capability_keys !== undefined) output.capability_keys = [...requirement.capability_keys];
  return output;
}

/** Project one capability category. Category labels come from the broker catalog. */
function toUiCategory(category: TrustDecision['capabilities']['categories'][number]): UiCapabilityCategory {
  return {
    family: category.family,
    label: sanitizeUntrustedText(category.label, 60),
    capability_paths: [...category.capability_paths],
    heuristic: category.heuristic,
  };
}

/**
 * Map the full decision into the compact client projection.
 *
 * Everything the client needs to render one review is preserved; file-system
 * paths of the candidate cache never appear here.
 */
export function toUiDecision(decision: TrustDecision): UiDecision {
  const declaration: UiDecision['declaration'] = { status: decision.declaration.status };
  if (decision.declaration.source_field !== undefined) {
    declaration.source_field = sanitizeUntrustedText(decision.declaration.source_field, 200);
  }
  return {
    status: decision.status,
    action: decision.action,
    host_code: true,
    plugin: {
      id: sanitizeUntrustedText(decision.plugin.id, 200),
      version: sanitizeUntrustedText(decision.plugin.version, 100),
    },
    source_trust: {
      kind: decision.source_trust.kind,
      detail: sanitizeUntrustedText(decision.source_trust.detail, 500),
    },
    declaration,
    categories: decision.capabilities.categories.map(toUiCategory),
    facts_count: decision.capabilities.facts.length,
    heuristic_count: decision.capabilities.heuristic_facts.length,
    install_scripts: decision.summary.install_scripts.map((script) => ({
      name: script.name,
      command: sanitizeUntrustedText(script.command, 500),
    })),
    auto_update: {
      detected: decision.summary.auto_update.detected,
      declared: decision.summary.auto_update.declared,
      reasons: decision.summary.auto_update.reasons.map((reason) => sanitizeUntrustedText(reason, 300)),
    },
    continuous_trust_warning: decision.summary.continuous_trust_warning,
    content_hash: decision.content_hash,
    diffs: decision.diffs.map(toUiDiff),
    confirmations_required: decision.confirmations_required.map(toUiConfirmation),
    errors: decision.errors.map((issue) => ({
      code: sanitizeUntrustedText(issue.code, 100),
      message: sanitizeUntrustedText(issue.message, 500),
    })),
    red_lines: decision.red_lines.map((line) => sanitizeUntrustedText(line, 500)),
    coverage_complete: decision.coverage.complete,
  };
}

/** Human-facing category label in the requested language. */
function categoryLabel(category: UiCapabilityCategory, language: 'zh' | 'en'): string {
  if (language === 'zh') return sanitizeUntrustedText(category.label, 60);
  const definition = FAMILY_LABELS[category.family as CapabilityFamily] as
    | { readonly zh: string; readonly en: string }
    | undefined;
  return definition === undefined
    ? sanitizeUntrustedText(category.family, 60)
    : definition.en;
}

/**
 * High-privilege capability labels detected in this review.
 *
 * Sources: detected capability categories plus the `capability` field of
 * `new_capability` diffs (which may not appear in a category).
 */
export function highPrivilegeLabels(decision: UiDecision, language: 'zh' | 'en'): string[] {
  const paths = new Set<string>();
  for (const category of decision.categories) {
    for (const path of category.capability_paths) {
      if (isHighPrivilege(path as CapabilityPath)) paths.add(path);
    }
  }
  for (const diff of decision.diffs) {
    if (!diff.new_capability || diff.capability === undefined) continue;
    if (isHighPrivilege(diff.capability as CapabilityPath)) paths.add(diff.capability);
  }
  return [...paths].map((path) => sanitizeUntrustedText(labelForPath(path as CapabilityPath, language), 60));
}

/** Short content-hash rendering shared by both prompt languages. */
function contentHashLabel(decision: UiDecision): string {
  return decision.content_hash === null ? '' : shortDigest(decision.content_hash, 12);
}

function resolvedSourceLabel(resolved: UiResolvedCandidate, language: 'zh' | 'en'): string {
  const kind = SOURCE_KIND_LABELS[resolved.kind]?.[language] ?? resolved.kind;
  const registry = resolved.registry === undefined ? '' : ` ${sanitizeUntrustedText(resolved.registry, 120)}`;
  return `${kind}${registry}`;
}

/** Compose the Chinese approval prompt (the primary `reason` text). */
function buildChineseSummary(input: { decision: UiDecision; resolved: UiResolvedCandidate }): string {
  const { decision, resolved } = input;
  const id = decision.plugin.id;
  const version = decision.plugin.version;
  const labels = highPrivilegeLabels(decision, 'zh');
  const shownLabels = labels.slice(0, MAX_HIGH_PRIVILEGE_LABELS);
  const scripts = decision.install_scripts.map((script) => script.name);
  const lines: string[] = [];

  lines.push(`【插件信任代理 · 预安装审查】${id}@${version}`);
  lines.push(`建议动作：${ACTION_LABELS[decision.action].zh}（状态：${STATUS_LABELS[decision.status].zh}）`);
  lines.push(`权限声明：${DECLARATION_LABELS[decision.declaration.status].zh}`);
  lines.push(
    `检出高权限能力（${labels.length}）：${
      shownLabels.length === 0 ? '未检出高权限能力' : shownLabels.join('、')
    }`,
  );
  lines.push(`安装脚本：${scripts.length === 0 ? '无' : scripts.join('、')}`);
  if (decision.auto_update.declared || decision.auto_update.detected) {
    const reasons = decision.auto_update.reasons.slice(0, 3).map((reason) => sanitizeUntrustedText(reason, 120));
    lines.push(
      `AUTO_UPDATE / 远程内容：${
        decision.auto_update.declared ? '清单声明了自动更新' : '检出运行期远程内容获取'
      }${reasons.length === 0 ? '' : `（${reasons.join('；')}）`}`,
    );
  }
  if (decision.continuous_trust_warning) {
    lines.push('持续信任提示：安装时审查的内容不等于运行中执行的内容。');
  }
  const hash = contentHashLabel(decision);
  lines.push(`内容哈希：${hash === '' ? '不可用（无法写入信任锚点）' : `sha256:${hash}`}`);
  lines.push(`来源：${resolvedSourceLabel(resolved, 'zh')}；安装规格：${sanitizeUntrustedText(resolved.install_spec, 200)}`);
  if (resolved.note !== undefined) {
    lines.push(`说明：${sanitizeUntrustedText(resolved.note, 240)}`);
  }
  if (decision.diffs.length > 0) {
    const rows = decision.diffs.slice(0, MAX_DIFF_LINES).map((diff) => {
      const tag = `${diff.type}/${diff.code}${diff.new_capability ? '（新增高权限）' : ''}`;
      const summary = sanitizeUntrustedText(diff.summary, 120);
      return summary === '' ? tag : `${tag}：${summary}`;
    });
    const omitted = decision.diffs.length > MAX_DIFF_LINES ? `；另有 ${decision.diffs.length - MAX_DIFF_LINES} 条未显示` : '';
    lines.push(`差异（共 ${decision.diffs.length} 条）：${rows.join('；')}${omitted}`);
  } else {
    lines.push('差异：无');
  }
  if (decision.confirmations_required.length > 0) {
    lines.push(`强制确认项：${decision.confirmations_required.map((item) => item.code).join('、')}`);
  }
  if (!decision.coverage_complete) {
    lines.push('警告：扫描覆盖不完整，结论只能基于已读取的部分。');
  }
  lines.push('请选择“批准安装”允许模型继续安装，或选择“取消”中止。该审批本身不会写入信任锚点；如需锚定，请使用「安全审查」标签页的确认流程。');
  return lines.join('\n');
}

/** Compose the English approval prompt (`displayReason.en`). */
function buildEnglishSummary(input: { decision: UiDecision; resolved: UiResolvedCandidate }): string {
  const { decision, resolved } = input;
  const labels = highPrivilegeLabels(decision, 'en');
  const shownLabels = labels.slice(0, MAX_HIGH_PRIVILEGE_LABELS);
  const scripts = decision.install_scripts.map((script) => script.name);
  const lines: string[] = [];
  lines.push(`[Plugin Trust Broker - pre-install review] ${decision.plugin.id}@${decision.plugin.version}`);
  lines.push(
    `Suggested action: ${ACTION_LABELS[decision.action].en} (status: ${STATUS_LABELS[decision.status].en})`,
  );
  lines.push(`Permission declaration: ${DECLARATION_LABELS[decision.declaration.status].en}`);
  lines.push(
    `Detected high-privilege capabilities (${labels.length}): ${
      shownLabels.length === 0 ? 'none detected' : shownLabels.join(', ')
    }`,
  );
  if (decision.categories.length > 0) {
    lines.push(`Detected surface: ${decision.categories.map((category) => categoryLabel(category, 'en')).join(', ')}`);
  }
  lines.push(`Install scripts: ${scripts.length === 0 ? 'none' : scripts.join(', ')}`);
  if (decision.auto_update.declared || decision.auto_update.detected) {
    lines.push(
      `Auto-update / remote content: ${decision.auto_update.declared ? 'declared in manifest' : 'remote content fetch detected'}`,
    );
  }
  if (decision.continuous_trust_warning) {
    lines.push('Continuous-trust warning: reviewed install-time content may differ from what runs later.');
  }
  const hash = contentHashLabel(decision);
  lines.push(`Content hash: ${hash === '' ? 'unavailable (cannot anchor)' : `sha256:${hash}`}`);
  lines.push(`Source: ${resolvedSourceLabel(resolved, 'en')}; install spec: ${sanitizeUntrustedText(resolved.install_spec, 200)}`);
  lines.push(
    decision.diffs.length === 0
      ? 'Diffs: none'
      : `Diffs (${decision.diffs.length}): ${decision.diffs
          .slice(0, MAX_DIFF_LINES)
          .map((diff) => {
            const tag = `${diff.type}/${diff.code}${diff.new_capability ? ' (new high-privilege)' : ''}`;
            const summary = sanitizeUntrustedText(diff.summary, 120);
            return summary === '' ? tag : `${tag}: ${summary}`;
          })
          .join('; ')}`,
  );
  if (decision.confirmations_required.length > 0) {
    lines.push(`Mandatory acknowledgements: ${decision.confirmations_required.map((item) => item.code).join(', ')}`);
  }
  if (!decision.coverage_complete) lines.push('Warning: scan coverage is incomplete.');
  lines.push('Approve to install / Cancel. Approving allows the model to install; it does not write a trust anchor.');
  return lines.join('\n');
}

/** Input accepted by {@link buildAgentGateReview}. */
export interface AgentGateInput {
  /** Compact decision from the just-completed review. */
  decision: UiDecision;
  /** How the candidate was acquired. */
  resolved: UiResolvedCandidate;
}

/**
 * Build the native approval payload for a model-initiated install.
 *
 * Always `kind:'ask'`; the review gives the human context, never an automatic
 * allow decision.
 */
export function buildAgentGateReview(input: AgentGateInput): AgentGateReview {
  const zh = sanitizeUntrustedText(buildChineseSummary(input), AGENT_GATE_REASON_LIMIT, true);
  const en = sanitizeUntrustedText(buildEnglishSummary(input), AGENT_GATE_REASON_LIMIT, true);
  return { kind: 'ask', reason: zh, displayReason: { en, zh } };
}

/** Build the approval payload used when the pre-install review itself failed. */
export function buildAgentGateFailure(error: { code: string; message: string }): AgentGateReview {
  const code = sanitizeUntrustedText(error.code, 60);
  const message = sanitizeUntrustedText(error.message, 400);
  const zh = sanitizeUntrustedText(
    [
      '【插件信任代理 · 预安装审查未能完成】',
      `错误：${code}：${message}`,
      '本次无法在安装前核对插件的权限声明、检出能力与内容哈希。',
      '批准安装将跳过预安装审查；建议选择“取消”，并在「安全审查」标签页重试或改用本地目录。',
      'Approve to install without a completed review / Cancel.',
    ].join('\n'),
    AGENT_GATE_REASON_LIMIT,
    true,
  );
  const en = sanitizeUntrustedText(
    [
      '[Plugin Trust Broker - pre-install review could not complete]',
      `Error: ${code}: ${message}`,
      'The declaration, detected capabilities and content hash could not be checked before install.',
      'Approving skips the pre-install review. Prefer Cancel, then retry in the "Security Review" tab.',
      'Approve to install without a completed review / Cancel.',
    ].join('\n'),
    AGENT_GATE_REASON_LIMIT,
    true,
  );
  return { kind: 'ask', reason: zh, displayReason: { en, zh } };
}
