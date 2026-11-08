/**
 * Composite static detector (face two): built-in heuristic walk with optional
 * externally sourced evidence.
 *
 * The result is the broker's "detected facts" half: verifiable scanner facts
 * stay in `facts`, the built-in fallback stays in `heuristic_facts`, and
 * `auto_update` reasoning is derived from the manifest plus the heuristic
 * walk. Failures never disappear: a broken external scanner is reported in
 * `errors` so the decision layer can fail closed, while a scanner that
 * was not explicitly configured is only a note (and selects the heuristic source).
 */

import type {
  AutoUpdateFinding,
  CapabilityFact,
  DetectionError,
  DetectionResult,
  DetectionSource,
  EvidenceRef,
  PluginManifest,
  ScanCoverage,
} from '../types.ts';
import { HEURISTIC_SOURCE, detectHeuristically } from './heuristic.ts';
import type { HeuristicLimits, RemoteContentIndicator } from './heuristic.ts';
import { loadExternalScan } from './external-scan.ts';
import type { ExternalScanInput, ExternalScanOutcome, ExternalScanSuccess } from './external-scan.ts';

/** Limits forwarded to the heuristic walk. */
export interface DetectionLimits extends HeuristicLimits {}

/** Input bag for {@link detectCapabilities}. */
export interface DetectInput {
  root: string;
  /** Original plugin root when root refers to a private snapshot. */
  candidateRoot?: string;
  /** Already-read manifest; supplies the `auto_update` declaration. */
  manifest?: PluginManifest;
  /** Pre-fetched `dsh-trust-check --dir --json` payload (schema 2). */
  scannerReport?: unknown;
  /** Path to a schema 2 payload. Used when `scannerReport` is absent. */
  scannerReportPath?: string;
  /** Disable the external scanner entirely and use the heuristic fallback. */
  noExternalScanner?: boolean;
  /** Limits forwarded to the heuristic walk. */
  limits?: DetectionLimits;
  /** Operator-selected absolute path to a trusted scanner executable. */
  bin?: string;
  /** Extension: scanner spawn timeout in milliseconds. */
  timeoutMs?: number;
  signal?: AbortSignal;
}

/**
 * Detect the plugin's capability surface.
 *
 * Source precedence:
 * - external scanner success -> scanner facts and additional local heuristic evidence;
 * - external scanner failure -> heuristic evidence with incomplete coverage;
 * - no explicit scanner / `noExternalScanner` -> heuristic source only.
 */
export async function detectCapabilities(input: DetectInput): Promise<DetectionResult> {
  const signal = input.signal ?? input.limits?.signal;
  signal?.throwIfAborted();
  const heuristic = await detectHeuristically(input.root, {
    ...input.limits,
    signal,
    ...(input.manifest !== undefined
      ? { patchFiles: input.manifest.dsh_bundle_patches, patchMode: 'manifest' as const }
      : {}),
  });
  const externalNotes: string[] = [];
  const external = await resolveExternalScan(input, externalNotes, heuristic.coverage.complete, signal);

  const autoUpdate = buildAutoUpdateFinding(input.manifest, heuristic.remote_content_indicators);
  const autoUpdateFact = deriveAutoUpdateFact(heuristic.remote_content_indicators);

  const notes: string[] = [...externalNotes];
  const errors: DetectionError[] = [];
  let primarySource: DetectionSource;
  let facts: CapabilityFact[] = [];
  const verifiedPaths = new Set(external?.ok ? external.facts.map((fact) => fact.path ?? fact.capability) : []);
  const heuristicFacts = heuristic.facts.filter((fact) => !verifiedPaths.has(fact.path ?? fact.capability));
  if (autoUpdateFact !== undefined) heuristicFacts.push(autoUpdateFact);
  let redLines: string[] = [];
  let coverage: ScanCoverage;

  if (external !== null && external.ok) {
    primarySource = scannerDetectionSource(external);
    facts = external.facts;
    redLines = external.red_lines;
    notes.push(...external.notes);
    notes.push(
      `外部扫描器 ${external.scanner.name} 提供了扫描事实；补充的本地启发式事实独立保留。`,
    );
    coverage = scannerCoverage(heuristic.coverage, external);
  } else {
    primarySource = { ...HEURISTIC_SOURCE };
    coverage = heuristic.coverage;
    if (external !== null) {
      errors.push(...external.errors);
      notes.push(...external.notes);
      notes.push('指定的外部扫描失败。本地启发式结果供复核，扫描覆盖标记为不完整。');
      coverage = { ...coverage, complete: false };
    }
  }

  errors.push(...heuristic.errors);
  notes.push(...heuristic.notes);
  if (autoUpdateFact !== undefined) {
    notes.push('已根据 heuristic 远程内容指示器生成 auto_update 启发式事实。');
  }

  return {
    primary_source: primarySource,
    facts,
    heuristic_facts: heuristicFacts,
    auto_update: autoUpdate,
    coverage,
    errors,
    red_lines: redLines,
    notes,
  };
}

/**
 * Build the `auto_update` finding from the manifest declaration plus heuristic
 * remote-content indicators. The finding exists independently of capability
 * declarations: presence is what the decision layer consumes.
 */
export function buildAutoUpdateFinding(
  manifest: PluginManifest | undefined,
  indicators: readonly RemoteContentIndicator[],
): AutoUpdateFinding {
  const reasons: string[] = [];
  const evidence: EvidenceRef[] = [];
  const evidenceSeen = new Set<string>();
  const reasonSeen = new Set<string>();

  const addEvidence = (ref: EvidenceRef): void => {
    const key = evidenceKey(ref);
    if (evidenceSeen.has(key)) return;
    evidenceSeen.add(key);
    evidence.push({ ...ref });
  };
  const addReason = (reason: string): void => {
    if (reasonSeen.has(reason)) return;
    reasonSeen.add(reason);
    reasons.push(reason);
  };

  const declared = manifest?.auto_update_declared === true;
  const declaredField = manifest?.auto_update_field;
  if (declared) {
    addReason(
      declaredField === undefined
        ? '插件声明了自动更新（autoUpdate: true）。'
        : `插件在 ${declaredField} 声明了自动更新（autoUpdate: true）。`,
    );
    if (declaredField !== undefined) addEvidence({ field: declaredField });
  }

  for (const indicator of indicators) {
    addReason(indicator.reason);
    addEvidence(indicator.evidence);
  }

  return {
    detected: declared || indicators.length > 0,
    declared,
    ...(declared && declaredField !== undefined ? { field: declaredField } : {}),
    ...(indicators.length > 0 ? { heuristic: true } : {}),
    reasons,
    evidence,
  };
}

/** Resolve the external scanner according to the caller's options. */
async function resolveExternalScan(
  input: DetectInput,
  notes: string[],
  localCoverageComplete: boolean,
  signal?: AbortSignal,
): Promise<ExternalScanOutcome> {
  if (input.noExternalScanner === true) {
    if (input.scannerReport !== undefined || input.scannerReportPath !== undefined) {
      notes.push('已按参数禁用外部扫描器，传入的扫描器报告被忽略。');
    } else {
      notes.push('已按参数禁用外部扫描器（noExternalScanner），仅使用内置启发式扫描。');
    }
    return null;
  }

  if (input.scannerReport !== undefined) {
    return loadExternalScan({ root: input.root, report: input.scannerReport, signal });
  }
  if (input.scannerReportPath !== undefined) {
    return loadExternalScan({ root: input.root, reportPath: input.scannerReportPath, signal });
  }

  if (!localCoverageComplete && input.bin !== undefined) {
    notes.push('本地扫描覆盖不完整，跳过运行外部扫描器。');
    return null;
  }

  const scannerInput: ExternalScanInput = { root: input.root, candidateRoot: input.candidateRoot, signal };
  if (input.bin !== undefined) scannerInput.bin = input.bin;
  if (input.timeoutMs !== undefined) scannerInput.timeoutMs = input.timeoutMs;
  const outcome = await loadExternalScan(scannerInput);
  if (outcome === null) {
    notes.push('未指定外部扫描器或报告：使用内置启发式扫描（heuristic:true）。');
  }
  return outcome;
}

/** Translate a successful external scan into the broker's primary source. */
function scannerDetectionSource(success: ExternalScanSuccess): DetectionSource {
  return {
    kind: 'dsh-trust-check',
    name: success.scanner.name,
    ...(success.scanner.version !== undefined ? { version: success.scanner.version } : {}),
    schema_version: success.scanner.schema_version,
    heuristic: false,
  };
}

/**
 * Coverage shown for a successful external scan.
 *
 * The scanner does not report walk coverage, but the heuristic walk still runs
 * for `auto_update`; its completeness is authoritative here. An incomplete
 * walk therefore keeps `complete: false` (fail closed) even when the scanner
 * itself succeeded.
 */
function scannerCoverage(walk: ScanCoverage, success: ExternalScanSuccess): ScanCoverage {
  return {
    ...walk,
    notes: [
      ...walk.notes,
      `外部扫描器 ${success.scanner.name} 已提供可验证事实；coverage 来自内置遍历（auto_update 与回退判定）。`,
    ],
  };
}

/**
 * Derive the heuristic `auto_update` fact from remote-content indicators.
 *
 * Only emitted when concrete indicators exist: a bare `autoUpdate: true`
 * declaration is already represented by the declaration and the finding, so it
 * is not turned into a "detected" fact.
 */
function deriveAutoUpdateFact(
  indicators: readonly RemoteContentIndicator[],
): CapabilityFact | undefined {
  if (indicators.length === 0) return undefined;

  const evidence: EvidenceRef[] = [];
  const seen = new Set<string>();
  for (const indicator of indicators) {
    const key = evidenceKey(indicator.evidence);
    if (seen.has(key)) continue;
    seen.add(key);
    evidence.push({ ...indicator.evidence });
  }
  if (evidence.length === 0) return undefined;

  const details = [...new Set(indicators.map((indicator) => indicator.reason))];
  return {
    capability: 'auto_update',
    path: 'auto_update',
    evidence,
    source: { ...HEURISTIC_SOURCE },
    heuristic: true,
    detail: `remote-content-indicators: ${details.join('; ')}`.slice(0, 500),
  };
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
