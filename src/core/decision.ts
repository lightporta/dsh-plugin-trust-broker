/**
 * Face one output: assemble one reviewable `TrustDecision` from manifest facts,
 * declared capabilities, detected capabilities, the canonical content hash,
 * anchored history and the resolved policy.
 *
 * The decision is the only object consumed by the CLI, the bundle service and
 * the admission gate. It contains facts, diffs, a binary `new_capability` flag
 * and a suggested action — never a score or a security verdict.
 */

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import type {
  CapabilityCategorySummary,
  ConfirmationRequirement,
  DecisionAction,
  DecisionStatus,
  DeclarationResult,
  DetectionResult,
  EvaluateOptions,
  EvidenceRef,
  ManifestIssue,
  PolicyConfig,
  TrustAnchor,
  TrustDecision,
  TrustDiff,
} from '../types.ts';
import {
  ACK_NEW_CAPABILITY_TOKEN,
  ACK_RED_LINE_TOKEN,
  ACK_SOURCE_MISMATCH_TOKEN,
  ACK_SUPPLY_CHAIN_TOKEN,
  ACK_UNSTATED_TOKEN,
  HOST_CODE_NOTICE_ZH,
} from '../version.ts';
import { TRUST_SCHEMA_VERSION } from '../types.ts';
import { AnchorStore, anchorStorePath } from './anchor-store.ts';
import {
  FATAL_MANIFEST_ISSUE_CODES,
  assessSourceTrust,
  buildCategories,
  buildDiffs,
  collectDecisionIssues,
  effectiveCapabilityKeys,
  normalizeSha256,
  upgradeDeclarationStatus,
} from './diff.ts';
import { detectCapabilities } from './detector.ts';
import { detectCapabilityDrift } from './drift.ts';
import { isoNow } from './fs-utils.ts';
import { computeContentHash, type ContentHashResult } from './hash.ts';
import { ManifestReadError, readPluginManifest } from './manifest.ts';
import { resolvePolicy } from './policy.ts';
import { labelForPath } from './catalog.ts';

/** Fail-closed status mapping (kept exported for the decision test suite). */
export function decideStatus(
  manifest: { errors: ManifestIssue[]; declaration: DeclarationResult },
  detection: Pick<DetectionResult, 'errors' | 'coverage'>,
): DecisionStatus {
  const fatalDetection = !detection.coverage.complete || detection.errors.length > 0;
  const fatalManifest = manifest.errors.some((issue) =>
    FATAL_MANIFEST_ISSUE_CODES.has(issue.code),
  );
  if (fatalDetection || fatalManifest) return 'unscannable';
  if (manifest.declaration.status === 'malformed') return 'malformed_manifest';
  return 'scanned';
}

export interface ConfirmationInput {
  declarationStatus: DeclarationResult['status'];
  diffs: TrustDiff[];
  drift: { skipped_reconfirmation: boolean };
  policy: PolicyConfig;
  redLines: string[];
}

/** Mandatory confirmations only: unstated declaration + new high-privilege capability. */
export function buildConfirmations(input: ConfirmationInput): ConfirmationRequirement[] {
  const { declarationStatus, diffs, drift, policy } = input;
  const requirements: ConfirmationRequirement[] = [];

  if (
    (declarationStatus === 'unstated' || declarationStatus === 'malformed') &&
    policy.require_ack_for_unstated && !drift.skipped_reconfirmation
  ) {
    requirements.push({
      code: 'unstated_capabilities',
      message:
        declarationStatus === 'malformed'
          ? '该插件的权限声明存在但无法解析（按 unstated 处理）：需明确知悉“检出事实即其实际能力面”。'
          : '该插件未提供权限声明（unstated）：需明确知悉“检出事实即其实际能力面”。',
      ack_token: ACK_UNSTATED_TOKEN,
    });
  }

  const newCapabilityDiffs = diffs.filter((diff) => diff.new_capability);
  if (newCapabilityDiffs.length > 0 && policy.confirm_on_new_capability && !drift.skipped_reconfirmation) {
    const capabilityKeys = [
      ...new Set(
        newCapabilityDiffs
          .map((diff) => diff.capability)
          .filter((key): key is NonNullable<typeof key> => key !== undefined),
      ),
    ];
    const labels = capabilityKeys.map((key) => labelForPath(key)).join('、');
    const hasDrift = newCapabilityDiffs.some((diff) => diff.type === 'B_capability_drift');
    requirements.push({
      code: 'new_capability',
      message: hasDrift
        ? `本次更新在已确认能力集之上新增了以下高权限能力：${labels}。需明确确认后才能进入加载。`
        : `检出声明之外的高权限能力：${labels}。需明确确认后才能进入加载。`,
      diff_ids: newCapabilityDiffs.map((diff) => diff.id),
      capability_keys: capabilityKeys,
      ack_token: ACK_NEW_CAPABILITY_TOKEN,
    });
  }

  if (
    policy.confirm_on_non_registry_dependency &&
    diffs.some((diff) => diff.code === 'non_registry_dependency')
  ) {
    requirements.push({
      code: 'supply_chain_dependency',
      message: '依赖中存在 registry 之外的来源（git:/file:/URL），需确认供应链差异。',
      diff_ids: diffs
        .filter((diff) => diff.code === 'non_registry_dependency')
        .map((diff) => diff.id),
      ack_token: ACK_SUPPLY_CHAIN_TOKEN,
    });
  }

  if (policy.external_red_lines === 'confirm' && input.redLines.length > 0) {
    requirements.push({
      code: 'red_line',
      message: `静态扫描器报告了 ${input.redLines.length} 条高置信度红线（仅陈列事实，不是本工具裁决）：需确认后继续。`,
      ack_token: ACK_RED_LINE_TOKEN,
    });
  }

  return requirements;
}

/** Suggested action; never a verdict. */
export function suggestAction(
  status: DecisionStatus,
  diffs: TrustDiff[],
  requirements: ConfirmationRequirement[],
  policy: PolicyConfig,
): DecisionAction {
  if (status === 'unscannable') return 'block_for_review';
  if (
    diffs.some((diff) => diff.code === 'source_hash_mismatch') &&
    policy.block_on_source_hash_mismatch
  ) {
    return 'block_for_review';
  }
  if (requirements.length > 0) return 'confirm';
  return 'proceed';
}

/** Latest anchor per file order; later confirmed_at wins, ties go to the later line. */
export function latestAnchorOf(anchors: readonly TrustAnchor[]): TrustAnchor | undefined {
  let latest: TrustAnchor | undefined;
  let latestTime = Number.NEGATIVE_INFINITY;
  for (const anchor of anchors) {
    const time = Date.parse(anchor.confirmed_at);
    if (latest === undefined || time >= latestTime) {
      latest = anchor;
      latestTime = time;
    }
  }
  return latest;
}

/** Evidence index for the drift comparison. */
export function buildEvidenceMap(
  detection: DetectionResult,
): Partial<Record<string, EvidenceRef[]>> {
  const map: Partial<Record<string, EvidenceRef[]>> = {};
  for (const fact of [...detection.facts, ...detection.heuristic_facts]) {
    const key = fact.path ?? fact.capability;
    map[key] = [...(map[key] ?? []), ...fact.evidence];
  }
  return map;
}

function toManifestIssues(error: ManifestReadError): ManifestIssue[] {
  return error.issues.length > 0 ? error.issues : [{ code: error.reason, message: error.message }];
}

/** Minimal decision for a tree that cannot be identified or fully inspected. */
function buildFailedDecision(
  root: string,
  issues: ManifestIssue[],
  policy: PolicyConfig,
  now: () => Date,
): TrustDecision {
  const messages = issues.map((issue) => issue.message);

  return {
    schema_version: TRUST_SCHEMA_VERSION,
    generated_at: isoNow(now),
    plugin: { id: basename(resolve(root)), version: '0.0.0', root: resolve(root) },
    host_code: true,
    status: 'unscannable',
    action: 'block_for_review',
    scanner: { kind: 'heuristic', name: 'none', heuristic: true },
    source_trust: {
      kind: 'unverified',
      detail: '插件树无法完整读取，本次未完成来源-内容比对。',
    },
    declaration: { status: 'unstated', errors: issues, declared: {} },
    capabilities: { facts: [], heuristic_facts: [], categories: [] },
    summary: {
      install_scripts: [],
      auto_update: { detected: false, declared: false, reasons: [], evidence: [] },
      dependency_sources: [],
      continuous_trust_warning: false,
    },
    diffs: [],
    confirmations_required: [],
    capability_keys: [],
    content_hash: null,
    content_hash_error: messages.join('；'),
    anchor: { found: false },
    coverage: {
      complete: false,
      files_total: 0,
      files_scanned: 0,
      files_skipped: [],
      bytes_scanned: 0,
      notes: messages,
    },
    errors: issues,
    red_lines: [],
    policy,
  };
}

/**
 * Evaluate one plugin tree and return the complete trust decision.
 *
 * Inspect a private snapshot of the exact bytes hashed from the candidate.
 * The caller (CLI / loader) decides when to persist a TrustAnchor.
 */
export async function evaluatePluginTrust(options: EvaluateOptions): Promise<TrustDecision> {
  const now = options.now ?? (() => new Date());
  const policy = resolvePolicy({
    ...options.policy,
    ...(options.storeDir !== undefined ? { store_dir: options.storeDir } : {}),
  });
  policy.hash_excludes = [];
  policy.block_on_unscannable = true;
  const root = resolve(options.root);
  const expectedHash = options.sourceMetadata?.content_sha256 ?? options.sourceMetadata?.tarball_sha256;
  if (expectedHash !== undefined && normalizeSha256(expectedHash) === null) {
    return buildFailedDecision(root, [{ code: 'expected_hash_invalid', message: '期望内容哈希必须是完整的 SHA-256 摘要。' }], policy, now);
  }

  const { signal } = options;
  signal?.throwIfAborted();
  const snapshotDir = await mkdtemp(join(tmpdir(), 'dsh-trust-broker-'));
  try {
    const hashResult = await computeContentHash(root, { strict: true, snapshotDir, signal });
    if (!hashResult.complete) return hashFailedDecision(root, hashResult, policy, now);
    return await evaluateSnapshot(options, root, snapshotDir, hashResult, policy, now);
  } finally {
    await rm(snapshotDir, { recursive: true, force: true });
  }
}

function hashFailedDecision(root: string, result: ContentHashResult, policy: PolicyConfig, now: () => Date): TrustDecision {
  return buildFailedDecision(root, result.errors.map((error) => ({
    code: error.code ?? 'content_hash_failed', message: error.message, file: error.path,
  })), policy, now);
}

async function evaluateSnapshot(
  options: EvaluateOptions,
  root: string,
  snapshotDir: string,
  hashResult: ContentHashResult,
  policy: PolicyConfig,
  now: () => Date,
): Promise<TrustDecision> {
  const { signal } = options;

  let manifest;
  try {
    manifest = await readPluginManifest(snapshotDir, { signal });
  } catch (error) {
    if (error instanceof ManifestReadError) return buildFailedDecision(root, toManifestIssues(error), policy, now);
    throw error;
  }

  const detection = await detectCapabilities({
    root: manifest.root,
    candidateRoot: root,
    manifest,
    limits: { strict: true, signal },
    signal,
    ...(options.scannerReport !== undefined ? { scannerReport: options.scannerReport } : {}),
    ...(options.scannerReportPath !== undefined
      ? { scannerReportPath: options.scannerReportPath }
      : {}),
    ...(options.noExternalScanner === true ? { noExternalScanner: true } : {}),
    ...(policy.trust_check_bin !== undefined ? { bin: policy.trust_check_bin } : {}),
  });

  const currentHash = await computeContentHash(root, { strict: true, signal });
  if (!currentHash.complete) return hashFailedDecision(root, currentHash, policy, now);
  if (currentHash.hash !== hashResult.hash) {
    return buildFailedDecision(root, [{ code: 'content_changed_during_review', message: '候选插件内容在扫描期间发生变化，请重新审查。' }], policy, now);
  }

  const anchorsFile = options.anchorsFile ?? anchorStorePath(policy.store_dir);
  const store = new AnchorStore({ file: anchorsFile });
  const snapshot = await store.snapshot();
  signal?.throwIfAborted();
  manifest.errors.push(...snapshot.errors.map((error) => ({
    code: error.line === 0 ? 'anchor_journal_unreadable' : 'anchor_journal_invalid',
    message: error.line === 0
      ? '无法读取锚点日志，无法建立可靠的更新审查基线。'
      : `锚点日志第 ${error.line} 行无法解析或校验，无法建立可靠的更新审查基线。`,
    field: error.line === 0 ? anchorsFile : `${anchorsFile}:${error.line}`,
  })));
  const anchors = snapshot.anchors.filter((anchor) => anchor.plugin_id === manifest.plugin_id);

  const declarationStatus = upgradeDeclarationStatus(manifest, manifest.declaration, detection);
  const declarationView: DeclarationResult = { ...manifest.declaration, status: declarationStatus };
  const capabilityKeys = effectiveCapabilityKeys(manifest, declarationView, detection);
  const drift = detectCapabilityDrift({
    plugin_id: manifest.plugin_id,
    current_version: manifest.version,
    current_content_hash: hashResult.hash,
    current_capability_keys: capabilityKeys,
    evidence: buildEvidenceMap(detection),
    anchors,
  });

  const sourceTrust = assessSourceTrust({
    manifest,
    contentHash: hashResult.hash,
    ...(options.sourceMetadata !== undefined ? { sourceMetadata: options.sourceMetadata } : {}),
  });

  const diffs = buildDiffs({
    manifest,
    declaration: declarationView,
    detection,
    drift,
    contentHash: hashResult.hash,
    ...(options.sourceMetadata !== undefined ? { sourceMetadata: options.sourceMetadata } : {}),
    policy,
  });

  const status = decideStatus(manifest, detection);
  const confirmations = buildConfirmations({
    declarationStatus,
    diffs,
    drift,
    policy,
    redLines: detection.red_lines,
  });

  if (
    status !== 'unscannable' &&
    diffs.some((diff) => diff.code === 'source_hash_mismatch') &&
    !policy.block_on_source_hash_mismatch
  ) {
    confirmations.unshift({
      code: 'source_mismatch',
      message: '来源元数据哈希与解压内容不一致：需确认你接受来源无法核验的内容。',
      ack_token: ACK_SOURCE_MISMATCH_TOKEN,
    });
  }

  const action = suggestAction(status, diffs, confirmations, policy);
  const errors = collectDecisionIssues(manifest, detection);
  const categories: CapabilityCategorySummary[] = buildCategories(
    manifest,
    declarationView,
    detection,
  );
  const matchedAnchor = drift.matched_anchor;
  const latestAnchor = latestAnchorOf(anchors);

  const continuousTrustWarning =
    detection.auto_update.detected || detection.auto_update.declared;
  const continuousTrustReason = detection.auto_update.declared
    ? '插件声明了 auto_update：运行中可能更新自身代码，安装时审查的内容不等于运行中执行的内容。'
    : detection.auto_update.detected
      ? `检出运行期远程内容获取机制（${detection.auto_update.reasons.join('；')}）：安装时审查的内容不等于运行中执行的内容。`
      : undefined;

  return {
    schema_version: TRUST_SCHEMA_VERSION,
    generated_at: isoNow(now),
    plugin: { id: manifest.plugin_id, version: manifest.version, root },
    host_code: true,
    status,
    action,
    scanner: detection.primary_source,
    source_trust: sourceTrust,
    declaration: {
      status: declarationStatus,
      ...(manifest.declaration.source_field !== undefined
        ? { source_field: manifest.declaration.source_field }
        : {}),
      errors: manifest.declaration.errors,
      declared: manifest.declaration.declared,
    },
    capabilities: {
      facts: detection.facts,
      heuristic_facts: detection.heuristic_facts,
      categories,
    },
    summary: {
      install_scripts: manifest.install_scripts,
      auto_update: detection.auto_update,
      dependency_sources: manifest.dependencies,
      continuous_trust_warning: continuousTrustWarning,
      ...(continuousTrustReason !== undefined
        ? { continuous_trust_reason: continuousTrustReason }
        : {}),
    },
    diffs,
    confirmations_required: confirmations,
    capability_keys: capabilityKeys,
    content_hash: hashResult.hash,
    anchor: {
      found: anchors.length > 0,
      ...(matchedAnchor !== undefined ? { matched: matchedAnchor } : {}),
      ...(latestAnchor !== undefined ? { latest: latestAnchor } : {}),
    },
    coverage: detection.coverage,
    errors,
    red_lines: detection.red_lines,
    policy,
  };
}

// Re-exported for renderers that show the fixed disclosure text.
export { HOST_CODE_NOTICE_ZH };
