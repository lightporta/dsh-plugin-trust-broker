/**
 * Public library surface of dsh-plugin-trust-broker.
 *
 * A loader integration imports `evaluatePluginTrust` + `admitDecision`, or asks
 * the Host for the `trustBroker` service provided by the bundle entry.
 */

export {
  buildConfirmations,
  buildEvidenceMap,
  decideStatus,
  evaluatePluginTrust,
  latestAnchorOf,
  suggestAction,
} from './core/decision.ts';
export {
  ManifestReadError,
  classifyDependencySpec,
  parseDeclaredCapabilities,
  readPluginManifest,
} from './core/manifest.ts';
export { detectCapabilities } from './core/detector.ts';
export type { DetectInput, DetectionLimits } from './core/detector.ts';
export { loadExternalScan } from './core/external-scan.ts';
export type {
  ExternalScanFailure,
  ExternalScanInput,
  ExternalScanOutcome,
  ExternalScanSuccess,
} from './core/external-scan.ts';
export { computeContentHash, sha256File } from './core/hash.ts';
export type { ContentHashOptions, ContentHashResult } from './core/hash.ts';
export { AnchorStore, anchorStorePath, buildTrustAnchor } from './core/anchor-store.ts';
export type { AnchorStoreOptions, BuildAnchorInput } from './core/anchor-store.ts';
export { detectCapabilityDrift } from './core/drift.ts';
export type { DriftInput } from './core/drift.ts';
export {
  admitDecision,
  computeDecisionDigest,
  contentHashUnchanged,
  missingAcknowledgements,
} from './admission/gate.ts';
export type { AdmitOptions } from './admission/gate.ts';
export { createRuntimeAudit } from './runtime/audit.ts';
export { AuditLog } from './runtime/audit-log.ts';
export type { AuditLogOptions } from './runtime/audit-log.ts';
export { checkToolScope, classifyToolCall, resolveToolOwner } from './runtime/scope.ts';
export type { ClassifiedToolCall, ScopeCheckInput, ToolScopeVerdict } from './runtime/scope.ts';
export {
  defaultPolicy,
  defaultStoreDir,
  loadPolicyFile,
  resolvePolicy,
} from './core/policy.ts';
export {
  assessSourceTrust,
  buildCategories,
  buildDiffs,
  collectDecisionIssues,
  effectiveCapabilityKeys,
  normalizeSha256,
  sortCapabilityKeys,
  upgradeDeclarationStatus,
} from './core/diff.ts';
export {
  CAPABILITY_DEFINITIONS,
  DEFAULT_TOOL_CAPABILITIES,
  capabilityPathOfKey,
  declaredFalsePaths,
  declaredTrueKeys,
  declarationPathState,
  declarationSlotValue,
  declarationSlots,
  definitionOf,
  isDeclarable,
  isHighPrivilege,
  labelForPath,
} from './core/catalog.ts';
export { TRUST_BROKER_NAME, TRUST_BROKER_VERSION } from './version.ts';
export type * from './types.ts';
