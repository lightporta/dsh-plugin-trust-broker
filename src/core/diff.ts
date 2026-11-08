/**
 * Face two's difference layer: the declared surface vs. the detected surface
 * (type A), the current capability set vs. the last confirmed anchor (type B),
 * and the declared provenance vs. the supplied source metadata (type C).
 *
 * Only type A/B rows can carry `new_capability: true`; type C is a provenance
 * problem and never enters the mandatory confirmation queue by itself.
 */

import type {
  AutoUpdateFinding,
  CapabilityFact,
  CapabilityCategorySummary,
  CapabilityKey,
  CapabilityPath,
  DeclarationResult,
  DeclarationStatus,
  DependencySourceFact,
  DetectionResult,
  DriftResult,
  EvidenceRef,
  ManifestIssue,
  PluginManifest,
  PolicyConfig,
  SourceMetadata,
  SourceTrust,
  TrustDiff,
} from '../types.ts';
import { redactUrlCredentials } from './fs-utils.ts';
import {
  CAPABILITY_DEFINITIONS,
  capabilityPathOfKey,
  declarationPathState,
  definitionOf,
  familyLabel,
  isDeclarable,
  isHighPrivilege,
  labelForPath,
} from './catalog.ts';

/** Manifest issues that make the lifecycle/dependency/patch surface unknown (fail closed). */
export const FATAL_MANIFEST_ISSUE_CODES: ReadonlySet<string> = new Set([
  'scripts_invalid',
  'script_invalid',
  'dependencies_invalid',
  'dependency_invalid',
  'bundle_patch_invalid',
  'anchor_journal_unreadable',
  'anchor_journal_invalid',
]);

const CATALOG_ORDER: ReadonlyMap<CapabilityPath, number> = new Map(
  CAPABILITY_DEFINITIONS.map((definition, index) => [definition.path, index]),
);

const MAX_EVIDENCE_ROWS = 6;

export interface DiffInput {
  manifest: PluginManifest;
  declaration: DeclarationResult;
  detection: DetectionResult;
  drift: DriftResult;
  contentHash: string | null;
  sourceMetadata?: SourceMetadata;
  policy: PolicyConfig;
}

export interface SourceTrustInput {
  manifest: PluginManifest;
  contentHash: string | null;
  contentHashError?: string;
  sourceMetadata?: SourceMetadata;
}

/** Upgrade `declared` to `incomplete` when detection covers paths the declaration omits. */
export function upgradeDeclarationStatus(
  manifest: PluginManifest,
  declaration: DeclarationResult,
  detection: DetectionResult,
): DeclarationStatus {
  if (declaration.status !== 'declared') return declaration.status;

  const detectedPaths = new Set<CapabilityPath>();
  for (const fact of [...detection.facts, ...detection.heuristic_facts]) {
    const path = fact.path;
    if (path !== undefined && isDeclarable(path)) detectedPaths.add(path);
  }
  for (const script of manifest.install_scripts) {
    detectedPaths.add(`lifecycle.${script.name}`);
  }
  if (detection.auto_update.detected) detectedPaths.add('auto_update');

  for (const path of detectedPaths) {
    if (declarationPathState(declaration.declared, path) === 'absent') return 'incomplete';
  }
  return 'declared';
}

/** Effective capability set: declared true + detected + lifecycle scripts + auto-update. */
export function effectiveCapabilityKeys(
  manifest: PluginManifest,
  declaration: DeclarationResult,
  detection: DetectionResult,
): CapabilityKey[] {
  const keys = new Set<CapabilityKey>();
  for (const key of declaration.declared_true_keys) keys.add(key);
  for (const fact of [...detection.facts, ...detection.heuristic_facts]) {
    const path = fact.path;
    keys.add(path ?? capabilityPathOfKey(fact.capability));
  }
  for (const script of manifest.install_scripts) {
    keys.add(`lifecycle.${script.name}`);
  }
  if (detection.auto_update.detected) keys.add('auto_update');
  return sortCapabilityKeys([...keys]);
}

/** Catalog order first; unknown keys sorted lexicographically afterwards. */
export function sortCapabilityKeys(keys: readonly CapabilityKey[]): CapabilityKey[] {
  return [...new Set(keys)].sort((left, right) => {
    const leftIndex = CATALOG_ORDER.get(left) ?? Number.MAX_SAFE_INTEGER;
    const rightIndex = CATALOG_ORDER.get(right) ?? Number.MAX_SAFE_INTEGER;
    if (leftIndex !== rightIndex) return leftIndex - rightIndex;
    return left.localeCompare(right);
  });
}

function factPath(fact: CapabilityFact): CapabilityPath | undefined {
  return fact.path ?? capabilityPathOfKey(fact.capability);
}

function dedupeEvidence(rows: readonly EvidenceRef[], limit = MAX_EVIDENCE_ROWS): EvidenceRef[] {
  const seen = new Set<string>();
  const output: EvidenceRef[] = [];
  for (const row of rows) {
    const key = `${row.file ?? ''}:${row.line ?? ''}:${row.field ?? ''}:${row.snippet ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(row);
    if (output.length >= limit) break;
  }
  return output;
}

/** Coarse category list rendered as the "detected surface" summary. */
export function buildCategories(
  manifest: PluginManifest,
  declaration: DeclarationResult,
  detection: DetectionResult,
): CapabilityCategorySummary[] {
  interface Accumulator {
    family: CapabilityCategorySummary['family'];
    paths: Set<CapabilityPath>;
    verifiableEvidence: EvidenceRef[];
    heuristicEvidence: EvidenceRef[];
    hasVerifiable: boolean;
    hasHeuristic: boolean;
  }

  const families = new Map<string, Accumulator>();
  const touch = (path: CapabilityPath, fact?: CapabilityFact): Accumulator => {
    const definition = definitionOf(path);
    const family = definition?.family ?? 'host_runtime';
    let current = families.get(family);
    if (current === undefined) {
      current = {
        family,
        paths: new Set(),
        verifiableEvidence: [],
        heuristicEvidence: [],
        hasVerifiable: false,
        hasHeuristic: false,
      };
      families.set(family, current);
    }
    current.paths.add(path);
    if (fact !== undefined) {
      if (fact.heuristic) {
        current.hasHeuristic = true;
        current.heuristicEvidence.push(...fact.evidence);
      } else {
        current.hasVerifiable = true;
        current.verifiableEvidence.push(...fact.evidence);
      }
    }
    return current;
  };

  for (const fact of detection.facts) {
    const path = factPath(fact);
    if (path !== undefined) touch(path, fact);
  }
  for (const fact of detection.heuristic_facts) {
    const path = factPath(fact);
    if (path !== undefined) touch(path, fact);
  }
  for (const script of manifest.install_scripts) {
    const entry = touch(`lifecycle.${script.name}`);
    entry.hasVerifiable = true;
    entry.verifiableEvidence.push(script.evidence);
  }
  if (detection.auto_update.detected) {
    const entry = touch('auto_update');
    if (detection.auto_update.heuristic === true) entry.hasHeuristic = true;
    else entry.hasVerifiable = true;
    (detection.auto_update.heuristic === true
      ? entry.heuristicEvidence
      : entry.verifiableEvidence
    ).push(...detection.auto_update.evidence);
  }

  const categories: CapabilityCategorySummary[] = [];
  for (const accumulator of families.values()) {
    const paths = [...accumulator.paths].sort(
      (left, right) => (CATALOG_ORDER.get(left) ?? 999) - (CATALOG_ORDER.get(right) ?? 999),
    );
    const evidence = dedupeEvidence([
      ...accumulator.verifiableEvidence,
      ...accumulator.heuristicEvidence,
    ]);
    categories.push({
      family: accumulator.family,
      label: familyLabel(accumulator.family, 'zh'),
      capability_paths: paths,
      evidence,
      heuristic: !accumulator.hasVerifiable && accumulator.hasHeuristic,
    });
  }
  return categories;
}

/** Resolve source trust as a state, never as a score. */
export function assessSourceTrust(input: SourceTrustInput): SourceTrust {
  const { manifest, contentHash, sourceMetadata } = input;
  const actual = contentHash;
  const expectedRepo = sourceMetadata?.repository === undefined
    ? undefined
    : redactUrlCredentials(sourceMetadata.repository);
  const supplied = sourceMetadata?.content_sha256 ?? sourceMetadata?.tarball_sha256;
  const expected = supplied === undefined ? null : normalizeSha256(supplied);

  if (expected !== null && actual !== null && expected !== actual.toLowerCase()) {
    return {
      kind: 'hash_mismatch',
      detail: '来源元数据中的期望内容哈希与候选树的规范化哈希不一致。',
      expected_hash: expected,
      actual_hash: actual,
      ...(manifest.repository !== undefined ? { repository_declared: manifest.repository } : {}),
      ...(expectedRepo !== undefined
        ? { repository_expected: expectedRepo }
        : {}),
    };
  }
  if (sourceMetadata?.registry_signature === 'verified' && expected !== null && actual?.toLowerCase() === expected) {
    return {
      kind: 'registry_signature',
      detail: '调用方报告已验证 registry 签名，且其提供的内容哈希与候选树一致。',
      expected_hash: expected,
      actual_hash: actual,
      ...(manifest.repository !== undefined ? { repository_declared: manifest.repository } : {}),
    };
  }
  if (expected !== null && actual !== null && expected === actual.toLowerCase()) {
    return {
      kind: 'hash_match',
      detail: '来源元数据中的期望内容哈希与候选树的规范化哈希一致。',
      expected_hash: expected,
      actual_hash: actual,
    };
  }
  if (expected !== null && actual === null) {
    return {
      kind: 'unverified',
      detail: '提供了来源哈希，但内容哈希无法计算：本次无法完成来源-内容比对。',
      expected_hash: expected,
      actual_hash: null,
    };
  }
  if (sourceMetadata?.registry_signature === 'verified') {
    return { kind: 'unverified', detail: '调用方报告已验证 registry 签名，但未提供可与候选树绑定的内容哈希。' };
  }
  if (manifest.repository !== undefined) {
    return {
      kind: 'unverified',
      detail:
        '插件声明了 repository，但调用方未提供 registry 签名或 tarball 哈希，无法验证来源与解压内容一致。',
      ...(actual !== null ? { actual_hash: actual } : {}),
      repository_declared: manifest.repository,
      ...(expectedRepo !== undefined
        ? { repository_expected: expectedRepo }
        : {}),
    };
  }
  return {
    kind: 'undeclared',
    detail: '插件未声明 repository，调用方也未提供来源元数据；来源不可核验。',
    ...(actual !== null ? { actual_hash: actual } : {}),
  };
}

/** Accept `sha256:<hex>` or a bare 64-character hex digest. */
export function normalizeSha256(value: string): string | null {
  const trimmed = value.trim().toLowerCase();
  if (/^sha256:[0-9a-f]{64}$/.test(trimmed)) return trimmed;
  if (/^[0-9a-f]{64}$/.test(trimmed)) return `sha256:${trimmed}`;
  return null;
}

function normalizeRepositoryUrl(value: string): string {
  let normalized = value.trim().toLowerCase();
  normalized = normalized.replace(/^git\+/, '');
  normalized = normalized.replace(/^git@([^:]+):/, 'https://$1/');
  normalized = normalized.replace(/^ssh:\/\/git@/, 'https://');
  normalized = normalized.replace(/^https?:\/\//, 'https://');
  normalized = normalized.replace(/\.git$/, '').replace(/\/$/, '');
  return normalized;
}

/** Build the complete difference list. */
export function buildDiffs(input: DiffInput): TrustDiff[] {
  const { manifest, declaration, detection, drift, contentHash, sourceMetadata } = input;
  const diffs = new Map<CapabilityPath, TrustDiff>();
  const canDiffDeclaration =
    declaration.status !== 'unstated' && declaration.status !== 'malformed';
  const declarationField = declaration.source_field ?? 'package.json#dsh.capabilities';

  if (canDiffDeclaration) {
    const factsByPath = new Map<CapabilityPath, CapabilityFact[]>();
    for (const fact of [...detection.facts, ...detection.heuristic_facts]) {
      const path = fact.path;
      if (path === undefined || !isDeclarable(path)) continue;
      const current = factsByPath.get(path) ?? [];
      current.push(fact);
      factsByPath.set(path, current);
    }

    for (const [path, facts] of factsByPath) {
      const state = declarationPathState(declaration.declared, path);
      if (state === 'true') continue;
      const definition = definitionOf(path);
      const pointer = definition?.declaration_pointer ?? path;
      const evidence = dedupeEvidence(facts.flatMap((fact) => fact.evidence));
      const declaredFalse = state === 'false';
      diffs.set(path, {
        id: `A:${path}`,
        type: 'A_declaration_insufficient',
        code: declaredFalse ? 'detected_but_declared_false' : 'detected_but_undeclared',
        capability: path,
        declared: {
          field: declaredFalse ? `${declarationField}.${pointer}` : declarationField,
          value: declaredFalse ? false : 'absent',
        },
        ...(evidence[0] !== undefined ? { detected: evidence[0] } : {}),
        new_capability: isHighPrivilege(path),
        evidence,
        heuristic: facts.every((fact) => fact.heuristic),
        summary: declaredFalse
          ? `声明 ${pointer} = false，但检出${labelForPath(path)}。`
          : `声明未覆盖 ${path}，但检出${labelForPath(path)}。`,
      });
    }

    // Install scripts are facts independent of the capability declaration.
    for (const script of manifest.install_scripts) {
      const path = `lifecycle.${script.name}` as CapabilityPath;
      const state = declarationPathState(declaration.declared, path);
      if (state === 'true') continue;
      const evidence: EvidenceRef[] = [
        { ...script.evidence, snippet: `scripts.${script.name}: ${script.command}` },
      ];
      diffs.set(path, {
        id: `A:${path}`,
        type: 'A_declaration_insufficient',
        code: state === 'false' ? 'detected_but_declared_false' : 'detected_but_undeclared',
        capability: path,
        declared: {
          field:
            state === 'false'
              ? `${declarationField}.lifecycle.${script.name}`
              : declarationField,
          value: state === 'false' ? false : 'absent',
        },
        detected: evidence[0],
        new_capability: true,
        evidence,
        heuristic: false,
        summary:
          state === 'false'
            ? `权限声明 lifecycle.${script.name} = false，但 package.json 声明了 ${script.name} 脚本：${script.command}`
            : `权限声明未覆盖 lifecycle.${script.name}，但 package.json 声明了 ${script.name} 脚本：${script.command}`,
      });
    }

    // AUTO_UPDATE is a capability slot AND an independent finding.
    if (detection.auto_update.detected) {
      const state = declarationPathState(declaration.declared, 'auto_update');
      if (state !== 'true') {
        const evidence =
          detection.auto_update.evidence.length > 0
            ? dedupeEvidence(detection.auto_update.evidence)
            : [{ field: 'package.json#dsh.autoUpdate', snippet: 'auto-update related surface' }];
        diffs.set('auto_update', {
          id: 'A:auto_update',
          type: 'A_declaration_insufficient',
          code: state === 'false' ? 'detected_but_declared_false' : 'detected_but_undeclared',
          capability: 'auto_update',
          declared: {
            field:
              state === 'false' ? `${declarationField}.auto_update` : declarationField,
            value: state === 'false' ? false : 'absent',
          },
          detected: evidence[0],
          new_capability: true,
          evidence,
          heuristic: detection.auto_update.heuristic === true,
          summary:
            state === 'false'
              ? '权限声明 auto_update = false，但检出了运行期获取远程内容或自动更新的机制。'
              : '权限声明未覆盖 auto_update，但检出了运行期获取远程内容或自动更新的机制。',
        });
      }
    }
  }

  // Type B: new capabilities compared with the last confirmed anchor.
  if (!drift.skipped_reconfirmation && drift.new_capabilities.length > 0) {
    for (const added of drift.new_capabilities) {
      const path = capabilityPathOfKey(added.capability);
      if (diffs.has(path)) continue; // A already covers the declaration gap.
      const evidence =
        added.evidence.length > 0
          ? dedupeEvidence(added.evidence)
          : [{ field: 'anchor.capability_keys', snippet: `v${added.previous_version}` }];
      const previous = drift.compared_anchor;
      const declarationState = declarationPathState(declaration.declared, path);
      const heuristic = isHeuristicOnly(detection, path);
      diffs.set(path, {
        id: `B:${path}`,
        type: 'B_capability_drift',
        code: 'new_capability_since_anchor',
        capability: path,
        ...(declarationState === 'true'
          ? {
              declared: {
                field: `${declarationField}.${definitionOf(path)?.declaration_pointer ?? path}`,
                value: true,
              },
            }
          : {}),
        ...(evidence[0] !== undefined ? { detected: evidence[0] } : {}),
        ...(previous !== undefined
          ? {
              previous: {
                version: previous.version,
                confirmed_at: previous.confirmed_at,
                confirmed_by: previous.confirmed_by,
              },
            }
          : {}),
        new_capability: isHighPrivilege(path),
        evidence,
        heuristic,
        summary:
          previous !== undefined
            ? `与已确认版本 v${previous.version} 相比，新增能力：${labelForPath(path)}。`
            : `与已确认能力集相比，新增能力：${labelForPath(path)}。`,
      });
    }
  }

  // Non-declarable host-integrity facts: a bundle patch can override or disable
  // composition rows before the candidate's own `apply()` runs. There is no
  // declaration slot for that, so surface it as an A row. First install requires
  // an explicit confirmation; once a matching anchor records the capability the
  // row is not repeated.
  const compositionPath: CapabilityPath = 'composition.override';
  const coveredByAnchor =
    drift.compared_anchor?.capability_keys.includes(compositionPath) === true;
  if (!drift.skipped_reconfirmation && !coveredByAnchor && !diffs.has(compositionPath)) {
    const overrideFacts = [...detection.facts, ...detection.heuristic_facts].filter(
      (fact) => (fact.path ?? fact.capability) === compositionPath,
    );
    if (overrideFacts.length > 0) {
      const evidence = dedupeEvidence(overrideFacts.flatMap((fact) => fact.evidence));
      diffs.set(compositionPath, {
        id: 'A:composition.override',
        type: 'A_declaration_insufficient',
        code: 'observed_non_declarable_capability',
        capability: compositionPath,
        declared: {
          field: evidence[0]?.field ?? 'package.json#dsh.bundle.patch',
          value: 'not-declarable',
        },
        ...(evidence[0] !== undefined ? { detected: evidence[0] } : {}),
        new_capability: true,
        evidence,
        heuristic: overrideFacts.every((fact) => fact.heuristic),
        summary:
          '检出无法通过权限声明表达的组合覆盖行为（覆盖/禁用 DSH 组合行），需显式确认。',
      });
    }
  }

  const typeC: TrustDiff[] = [];

  // C1: expected extracted-tree hash vs. canonical content hash.
  const supplied = sourceMetadata?.content_sha256 ?? sourceMetadata?.tarball_sha256;
  const expected = supplied === undefined ? null : normalizeSha256(supplied);
  if (expected !== null && contentHash !== null && expected !== contentHash.toLowerCase()) {
    typeC.push({
      id: 'C:source_hash_mismatch',
      type: 'C_source_content_mismatch',
      code: 'source_hash_mismatch',
      new_capability: false,
      evidence: [
        { field: 'source_metadata.content_sha256', snippet: expected },
        { field: 'content_hash', snippet: contentHash },
      ],
      heuristic: false,
      summary: `来源元数据哈希（${expected}）与解压内容哈希（${contentHash}）不一致。`,
    });
  }

  // C2: declared repository vs. repository from source metadata.
  if (sourceMetadata?.repository !== undefined && manifest.repository !== undefined) {
    const expectedRepository = redactUrlCredentials(sourceMetadata.repository);
    const declaredRepo = normalizeRepositoryUrl(manifest.repository);
    const expectedRepo = normalizeRepositoryUrl(expectedRepository);
    if (declaredRepo !== expectedRepo) {
      typeC.push({
        id: 'C:repository_mismatch',
        type: 'C_source_content_mismatch',
        code: 'repository_mismatch',
        new_capability: false,
        evidence: [
          { field: 'package.json#repository', snippet: manifest.repository },
          { field: '--source-metadata.repository', snippet: expectedRepository },
        ],
        heuristic: false,
        summary: `package.json 声明的 repository 与来源元数据不一致：${manifest.repository} ≠ ${expectedRepository}。`,
      });
    }
  }

  // C3: dependency sources outside the registry.
  for (const dependency of manifest.dependencies) {
    if (dependency.kind === 'registry') continue;
    typeC.push({
      id: `C:dependency:${dependency.name}${dependency.evidence.file === undefined ? '' : `:${dependency.evidence.field}`}`,
      type: 'C_source_content_mismatch',
      code: 'non_registry_dependency',
      new_capability: false,
      evidence: [
        { ...dependency.evidence, snippet: `${dependency.name}: ${dependency.spec}` },
      ],
      heuristic: false,
      summary: `依赖 ${dependency.name} 来自 ${dependency.kind} 源（${dependency.spec}），不属于 registry 版本范围。`,
    });
  }
  typeC.sort(compareTypeC);

  const typeA = [...diffs.values()]
    .filter((diff) => diff.type === 'A_declaration_insufficient')
    .sort(compareCapabilityDiff);
  const typeB = [...diffs.values()]
    .filter((diff) => diff.type === 'B_capability_drift')
    .sort(compareCapabilityDiff);
  return [...typeA, ...typeB, ...typeC];
}

function compareCapabilityDiff(left: TrustDiff, right: TrustDiff): number {
  const leftPath = left.capability;
  const rightPath = right.capability;
  if (leftPath !== undefined && rightPath !== undefined) {
    return (CATALOG_ORDER.get(leftPath) ?? 999) - (CATALOG_ORDER.get(rightPath) ?? 999);
  }
  return left.id.localeCompare(right.id);
}

function compareTypeC(left: TrustDiff, right: TrustDiff): number {
  const priority = (diff: TrustDiff): number =>
    diff.code === 'source_hash_mismatch' ? 0 : diff.code === 'repository_mismatch' ? 1 : 2;
  const delta = priority(left) - priority(right);
  return delta !== 0 ? delta : left.id.localeCompare(right.id);
}

function isHeuristicOnly(detection: DetectionResult, path: CapabilityPath): boolean {
  const verifiable = detection.facts.some((fact) => factPath(fact) === path);
  if (verifiable) return false;
  return detection.heuristic_facts.some((fact) => factPath(fact) === path);
}

/** Merge manifest/detection issues into the decision's error list. */
export function collectDecisionIssues(
  manifest: PluginManifest,
  detection: DetectionResult,
  contentHashError?: string,
): ManifestIssue[] {
  const issues: ManifestIssue[] = [
    ...manifest.errors,
    ...manifest.declaration.errors.map((issue) => ({ ...issue, field: issue.field ?? issue.code })),
    ...detection.errors.map((error) => ({
      code: error.code,
      message: error.message,
      ...(error.file !== undefined ? { field: error.file } : {}),
    })),
  ];
  if (contentHashError !== undefined) {
    issues.push({ code: 'content_hash_unavailable', message: contentHashError });
  }
  return issues;
}

export type { AutoUpdateFinding, DependencySourceFact };
