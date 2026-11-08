/**
 * Shared, serializable data model of the Plugin Trust Broker.
 *
 * Every structure in this file is JSON-safe on purpose: the same decision object
 * is rendered by the CLI, emitted with `--json`, persisted next to a trust
 * anchor, and consumed by a future loader admission hook. The broker produces
 * facts, differences, a binary `new_capability` flag and a suggested action; it
 * never decides "safe" or "malicious" on the user's behalf.
 */

/** Version of several stable JSON contracts (decision, anchor, audit). */
export const TRUST_SCHEMA_VERSION = 1 as const;

/** Schema version of the append-only runtime audit log. */
export const AUDIT_SCHEMA_VERSION = 1 as const;

/** Who confirmed an anchor. Only these two values are ever written. */
export type ConfirmedBy = 'user' | 'policy';

/** Coarse capability families known to the broker. Superset of the required set. */
export type CapabilityFamily =
  | 'network'
  | 'process'
  | 'filesystem'
  | 'env'
  | 'tool_registry'
  | 'context'
  | 'lifecycle'
  | 'auto_update'
  | 'credentials'
  | 'subagent'
  | 'llm'
  | 'dynamic_code'
  | 'host_runtime'
  | 'composition';

/**
 * Canonical capability path: one boolean slot in `DeclaredCapabilities` (or an
 * always-observable fact such as an install script). This is the unit that the
 * diff engine compares between a declaration, detected facts, and an anchor.
 */
export type CapabilityPath =
  | 'network.fetch'
  | 'network.socket'
  | 'process.child_process'
  | 'process.exec'
  | 'filesystem.read'
  | 'filesystem.write'
  | 'env.read'
  | 'tool_registry.add'
  | 'tool_registry.override'
  | 'tool_registry.intercept'
  | 'context.prompt_inject'
  | 'context.tool_output_rewrite'
  | 'context.history_compress'
  | 'lifecycle.preinstall'
  | 'lifecycle.install'
  | 'lifecycle.postinstall'
  | 'lifecycle.prepare'
  | 'auto_update'
  | 'credentials.read'
  | 'subagent.spawn'
  | 'llm.call'
  | 'dynamic_code.eval'
  /** Facts without a declaration slot: depends on a DSH host runtime package. */
  | 'host_runtime.dependency'
  /** Facts without a declaration slot: overrides or disables a core bundle row. */
  | 'composition.override';

/**
 * A capability in the effective capability set. Today it equals a capability
 * path; the alias keeps the door open for scoped keys without breaking anchors.
 */
export type CapabilityKey = CapabilityPath;

/**
 * The permission block a plugin MAY declare.
 *
 * The first eight fields are the required taxonomy from the trust-broker brief.
 * The remaining fields mirror capability ids that the reference static scanner
 * (`dsh-trust-check`, schema 2) already reports, so a declaration can cover the
 * whole observed surface instead of forcing those facts into a wrong bucket.
 *
 * `undefined` means "no statement" and is fundamentally different from `false`.
 * This is why every field is optional and why presence is tracked separately in
 * `DeclarationResult.slots`.
 */
export interface DeclaredCapabilities {
  network?: { fetch?: boolean; socket?: boolean; outbound_domains?: string[] };
  process?: { child_process?: boolean; exec?: boolean };
  filesystem?: { read?: boolean; write?: boolean; roots?: string[] };
  env?: { read?: string[] };
  tool_registry?: { add?: boolean; override?: boolean; intercept?: boolean };
  context?: {
    prompt_inject?: boolean;
    tool_output_rewrite?: boolean;
    history_compress?: boolean;
  };
  lifecycle?: {
    preinstall?: boolean;
    install?: boolean;
    postinstall?: boolean;
    prepare?: boolean;
  };
  auto_update?: boolean;
  /** Extension: reads the DSH credential service or a secret store. */
  credentials?: { read?: boolean };
  /** Extension: starts sub-agents. */
  subagent?: { spawn?: boolean };
  /** Extension: calls a model. */
  llm?: { call?: boolean };
  /** Extension: evaluates code at runtime (`eval`, `new Function`, `vm`). */
  dynamic_code?: { eval?: boolean };
}

/** Where a piece of evidence lives: a file:line, or a metadata field pointer. */
export interface EvidenceRef {
  /** Path relative to the plugin root. */
  file?: string;
  /** 1-based line number. */
  line?: number;
  /** Metadata pointer such as `package.json#dsh.capabilities.process`. */
  field?: string;
  /** Trimmed source line (never the whole file). */
  snippet?: string;
}

/** Fact source descriptor. `heuristic: true` facts never share a field with verifiable ones. */
export interface DetectionSource {
  kind: 'dsh-trust-check' | 'heuristic';
  name: string;
  version?: string;
  /** Scanner JSON schema version when the source is an external scanner. */
  schema_version?: number;
  heuristic: boolean;
}

/** One detected capability occurrence with locally re-checkable evidence. */
export interface CapabilityFact {
  capability: CapabilityKey;
  /** Declaration slot this fact belongs to, when the taxonomy has one. */
  path?: CapabilityPath;
  evidence: EvidenceRef[];
  source: DetectionSource;
  /** True only for the broker's own fallback regex detector. */
  heuristic: boolean;
  /** Human-readable explanation, usually the scanner rule id or matched text. */
  detail?: string;
}

/** One install-time lifecycle script read from package.json. */
export interface InstallScriptFact {
  name: 'preinstall' | 'install' | 'postinstall' | 'prepare';
  command: string;
  evidence: EvidenceRef;
}

/** A dependency whose value is not a plain registry semver range. */
export interface DependencySourceFact {
  name: string;
  spec: string;
  kind: 'registry' | 'git' | 'file' | 'url' | 'workspace' | 'other';
  evidence: EvidenceRef;
}

/** AUTO_UPDATE / remote-content analysis. Presence is independent of declarations. */
export interface AutoUpdateFinding {
  detected: boolean;
  /** Declared in the manifest (e.g. `dsh.autoUpdate: true`). */
  declared: boolean;
  /** Declaration field when declared. */
  field?: string;
  /** Why the broker believes the plugin may fetch and run unreviewed content. */
  reasons: string[];
  evidence: EvidenceRef[];
  /** True when at least one reason comes from the heuristic pass. */
  heuristic?: boolean;
}

/** How completely the detector was able to look at the plugin tree. */
export interface ScanCoverage {
  complete: boolean;
  files_total: number;
  files_scanned: number;
  files_skipped: Array<{ path: string; reason: string }>;
  bytes_scanned: number;
  notes: string[];
}

/** A detection-level failure. Any error that reduces coverage must surface. */
export interface DetectionError {
  code: string;
  message: string;
  file?: string;
}

/** Result of static capability detection (face two facts). */
export interface DetectionResult {
  primary_source: DetectionSource;
  /** Verifiable facts: scanner-derived, manifest-derived. `heuristic === false`. */
  facts: CapabilityFact[];
  /** Broker fallback facts. Always segregated from `facts` and marked heuristic. */
  heuristic_facts: CapabilityFact[];
  auto_update: AutoUpdateFinding;
  coverage: ScanCoverage;
  errors: DetectionError[];
  /** External scanner high-confidence lines. Displayed as facts, never re-judged. */
  red_lines: string[];
  notes: string[];
}

/** Parser errors from a manifest or a capability declaration. */
export interface ManifestIssue {
  code: string;
  message: string;
  field?: string;
}

/** Three-state declaration status. `incomplete` is assigned after detection. */
export type DeclarationStatus = 'declared' | 'unstated' | 'incomplete' | 'malformed';

/** One explicit declaration slot; presence is tracked so `undefined !== false`. */
export interface DeclarationSlotState {
  path: CapabilityPath;
  present: boolean;
  /** false for explicit denial; string[] for `env.read`; true otherwise. */
  value: boolean | readonly string[];
}

/** Result of parsing the permission declaration. */
export interface DeclarationResult {
  status: DeclarationStatus;
  /** Metadata pointer where the declaration was found, e.g. `package.json#dsh.capabilities`. */
  source_field?: string;
  declared: DeclaredCapabilities;
  /** Explicitly present slots only (absent slots are reported by their absence). */
  slots: DeclarationSlotState[];
  /** Capability keys implied by explicit `true`/non-empty values. */
  declared_true_keys: CapabilityKey[];
  errors: ManifestIssue[];
  notes: string[];
}

/** Identity, provenance and declaration facts read from package.json. */
export interface PluginManifest {
  plugin_id: string;
  version: string;
  root: string;
  package_json_path: string;
  description?: string;
  repository?: string;
  homepage?: string;
  main_entry?: string;
  /** Relative path of the DSH bundle patch when declared. */
  dsh_bundle_patch?: string;
  install_scripts: InstallScriptFact[];
  dependencies: DependencySourceFact[];
  auto_update_declared: boolean;
  auto_update_field?: string;
  declaration: DeclarationResult;
  errors: ManifestIssue[];
}

/** Expected provenance supplied by the caller from registry / source metadata. */
export interface SourceMetadata {
  /** e.g. `npm:dsh-foo@1.2.3` or `git+https://...`. */
  spec?: string;
  repository?: string;
  /** Canonical SHA-256 of the extracted tree, obtained from a trusted source. */
  content_sha256?: string;
  /** Legacy alias for content_sha256. A raw tarball digest cannot verify a tree. */
  tarball_sha256?: string;
  /** `verified` when the caller validated the registry signature/provenance. */
  registry_signature?: 'verified' | 'unverified' | 'absent';
  /** Display-only publication facts. */
  published_at?: string;
  deprecated?: boolean;
}

/** Source trustworthiness, as a state (never a score). */
export type SourceTrustKind =
  | 'registry_signature'
  | 'hash_match'
  | 'hash_mismatch'
  | 'unverified'
  | 'undeclared';

export interface SourceTrust {
  kind: SourceTrustKind;
  detail: string;
  expected_hash?: string;
  actual_hash?: string | null;
  repository_declared?: string;
  repository_expected?: string;
}

/** Stable difference taxonomy from the brief. */
export type DiffType =
  | 'A_declaration_insufficient'
  | 'B_capability_drift'
  | 'C_source_content_mismatch';

export type DiffCode =
  | 'detected_but_declared_false'
  | 'detected_but_undeclared'
  | 'new_capability_since_anchor'
  | 'source_hash_mismatch'
  | 'repository_mismatch'
  | 'non_registry_dependency'
  | 'install_script_newer_than_declaration';

/** One diff row. Callers force confirmation ONLY for `new_capability === true`. */
export interface TrustDiff {
  /** Stable within one decision, e.g. `A:process.child_process` or `B:network.fetch`. */
  id: string;
  type: DiffType;
  code: DiffCode;
  capability?: CapabilityKey;
  declared?: { field: string; value: unknown };
  detected?: EvidenceRef;
  previous?: {
    version: string;
    confirmed_at: string;
    confirmed_by: ConfirmedBy;
  };
  /** Binary severity marker defined by the brief: new high-privilege capability? */
  new_capability: boolean;
  /** At least one evidence pointer, or a metadata field pointer. */
  evidence: EvidenceRef[];
  heuristic: boolean;
  /** Fixed, localizable sentence assembled by the broker (Chinese by default). */
  summary: string;
}

/** A persisted trust anchor. Required fields match the brief; extras are `ext_`. */
export interface TrustAnchor {
  plugin_id: string;
  version: string;
  /** Canonical content hash, e.g. `sha256:...`; anchors are refused when null. */
  content_hash: string;
  declared_capabilities: DeclaredCapabilities;
  confirmed_at: string;
  confirmed_by: ConfirmedBy;
  /** Extension: schema version of this anchor record. */
  schema_version: 1;
  /** Extension: effective capability set confirmed by the user/policy. */
  capability_keys: CapabilityKey[];
  /** Extension: declaration status at confirmation time. */
  declaration_status: DeclarationStatus;
  /** Extension: scanner identity that produced the facts behind the decision. */
  scanner: { name: string; version?: string; heuristic: boolean };
  /** Extension: sha256 over the canonical decision facts (anchor binding). */
  decision_digest: string;
  /** Extension: free-form notes recorded at confirmation time. */
  notes?: string;
}

/** Result of the version-drift comparison against previously confirmed anchors. */
export interface DriftCapability {
  capability: CapabilityKey;
  previous_version: string;
  evidence: EvidenceRef[];
}

export interface DriftResult {
  compared_anchor?: TrustAnchor;
  /** Capability keys present now and absent from the latest confirmed anchor. */
  new_capabilities: DriftCapability[];
  /** Capability keys removed since the latest confirmed anchor (no re-confirmation). */
  reduced_capabilities: CapabilityKey[];
  /** True when the content hash equals an already anchored version. */
  skipped_reconfirmation: boolean;
  matched_anchor?: TrustAnchor;
  note?: string;
}

/** A required explicit confirmation before admission. */
export interface ConfirmationRequirement {
  code:
    | 'unstated_capabilities'
    | 'new_capability'
    | 'supply_chain_dependency'
    | 'red_line'
    | 'scan_incomplete'
    | 'source_mismatch';
  /** Localized fixed sentence. */
  message: string;
  diff_ids?: string[];
  capability_keys?: CapabilityKey[];
  /** Exact phrase the interactive CLI requires; also the token for flags. */
  ack_token: string;
}

/** Suggested action. Never a safety verdict; the caller/user decides. */
export type DecisionAction = 'proceed' | 'confirm' | 'block_for_review';

/** Evaluation status. `unscannable` and `malformed_manifest` are fail-closed states. */
export type DecisionStatus = 'scanned' | 'unscannable' | 'malformed_manifest';

/** Coarse human-facing category row in the decision summary. */
export interface CapabilityCategorySummary {
  family: CapabilityFamily;
  label: string;
  capability_paths: CapabilityPath[];
  evidence: EvidenceRef[];
  heuristic: boolean;
}

/** Result of the persistent anchor lookup for one plugin. */
export interface AnchorLookup {
  found: boolean;
  matched?: TrustAnchor;
  latest?: TrustAnchor;
}

/** The broker's full, reviewable output. */
export interface TrustDecision {
  schema_version: 1;
  generated_at: string;
  plugin: { id: string; version: string; root: string };
  /** Fixed fact: DSH loads third-party plugins as Host code, in-process. */
  host_code: true;
  status: DecisionStatus;
  action: DecisionAction;
  /** Identity of the fact source that backed this decision. */
  scanner: DetectionSource;
  source_trust: SourceTrust;
  declaration: {
    status: DeclarationStatus;
    source_field?: string;
    errors: ManifestIssue[];
    /** Normalized declaration; always present, empty for unstated plugins. */
    declared: DeclaredCapabilities;
  };
  capabilities: {
    facts: CapabilityFact[];
    heuristic_facts: CapabilityFact[];
    categories: CapabilityCategorySummary[];
  };
  summary: {
    install_scripts: InstallScriptFact[];
    auto_update: AutoUpdateFinding;
    dependency_sources: DependencySourceFact[];
    /** The plugin may fetch and execute content that was not reviewed at install time. */
    continuous_trust_warning: boolean;
    continuous_trust_reason?: string;
  };
  diffs: TrustDiff[];
  confirmations_required: ConfirmationRequirement[];
  /** Effective capability set (declared true + detected + lifecycle + auto-update). */
  capability_keys: CapabilityKey[];
  /** Copyable canonical content hash; null when it could not be computed. */
  content_hash: string | null;
  content_hash_error?: string;
  anchor: AnchorLookup;
  coverage: ScanCoverage;
  errors: ManifestIssue[];
  red_lines: string[];
  policy: PolicyConfig;
}

/** Profile-level policy. Defaults keep the brief's fail-closed rules intact. */
export interface PolicyConfig {
  schema_version: 1;
  /** Unstated declarations must be acknowledged explicitly. Default true. */
  require_ack_for_unstated: boolean;
  /** New high-privilege capabilities must be confirmed. Default true. */
  confirm_on_new_capability: boolean;
  /** Block when the tree cannot be fully inspected. Default true. */
  block_on_unscannable: boolean;
  /** Block when expected registry/source hash differs from the actual content. Default true. */
  block_on_source_hash_mismatch: boolean;
  /** Non-registry dependency sources (git:/file:/URL) require confirmation. Default true. */
  confirm_on_non_registry_dependency: boolean;
  /** What to suggest for external scanner red lines. Default `display` (facts only). */
  external_red_lines: 'display' | 'confirm';
  /** Legacy policy field. Admission always hashes the entire tree. */
  hash_excludes: string[];
  /** Default store directory (anchors + audit logs). */
  store_dir: string;
  /** Optional custom `dsh-trust-check` executable. */
  trust_check_bin?: string;
}

/** Result of a pre-install admission gate. */
export interface AdmissionAccepted {
  accepted: true;
  decision: TrustDecision;
  acknowledged: ConfirmationRequirement['code'][];
  anchor: TrustAnchor;
}

export interface AdmissionRejected {
  accepted: false;
  decision: TrustDecision;
  reason:
    | 'confirmation_required'
    | 'blocked_for_review'
    | 'content_changed'
    | 'acknowledgement_missing';
  message: string;
  required: ConfirmationRequirement[];
}

export type AdmissionOutcome = AdmissionAccepted | AdmissionRejected;

/** Option bag for `evaluatePluginTrust`. */
export interface EvaluateOptions {
  root: string;
  /** Cancel inspection, including an explicitly configured external scanner. */
  signal?: AbortSignal;
  /** Pre-fetched external scanner report (`dsh-trust-check --dir --json` payload). */
  scannerReport?: unknown;
  /** Where to load `scannerReport` from when the caller passes a path. */
  scannerReportPath?: string;
  /** Disable the external scanner and use the heuristic fallback only. */
  noExternalScanner?: boolean;
  /** Expected provenance from the caller. */
  sourceMetadata?: SourceMetadata;
  /** Policy overrides merged over defaults. */
  policy?: Partial<PolicyConfig>;
  /** Anchor store file. Defaults to `<store_dir>/anchors.jsonl`. */
  anchorsFile?: string;
  /** Store dir override. */
  storeDir?: string;
  /** Clock override for deterministic tests. */
  now?: () => Date;
}

/* ------------------------------------------------------------------------- */
/* Runtime audit channel (face four).                                         */
/* ------------------------------------------------------------------------- */

export type AuditEventType =
  | 'tool_call'
  | 'tool_result'
  | 'scope_exceeded'
  | 'context_write'
  | 'anchor_created'
  | 'decision_recorded'
  | 'audit_error';

export interface AuditEventBase {
  schema_version: 1;
  event: AuditEventType;
  /** Monotonic within one writer process. */
  seq: number;
  id: string;
  ts: string;
  plugin_id?: string;
  plugin_version?: string;
  session_id?: string;
  agent_id?: string;
}

/** Pre-dispatch tool call record. */
export interface ToolCallAuditEvent extends AuditEventBase {
  event: 'tool_call';
  tool: string;
  call_id?: string;
  /** sha256 of the canonical, redacted arguments. */
  arguments_digest: string;
  argument_keys: string[];
  /** Capability categories this call can exercise, inferred from tool+args. */
  categories: CapabilityKey[];
  /** Scope verdict against the owning plugin's confirmed surface. */
  scope: 'declared' | 'undeclared_scope' | 'unattributed';
  owner_plugin_id?: string;
}

/** Post-dispatch record; captures tool-output rewriting. */
export interface ToolResultAuditEvent extends AuditEventBase {
  event: 'tool_result';
  tool: string;
  call_id?: string;
  ok: boolean;
  /** Digest of the result content before the post-execute waterfall returned. */
  result_digest: string;
  /** Digest after the waterfall settled; differs when a plugin rewrote output. */
  settled_digest: string;
  rewritten: boolean;
}

/** A tool call that exercised categories outside the owning plugin's anchored surface. */
export interface ScopeExceededAuditEvent extends AuditEventBase {
  event: 'scope_exceeded';
  tool: string;
  call_id?: string;
  owner_plugin_id: string;
  exceeded: CapabilityKey[];
  declared: CapabilityKey[];
  evidence: string;
}

/** Context mutation events: prompt injection, output rewrite, history compression. */
export interface ContextWriteAuditEvent extends AuditEventBase {
  event: 'context_write';
  channel:
    | 'prompt_inject'
    | 'tool_output_rewrite'
    | 'history_compress'
    | 'prompt_assembly'
    | 'inbox_insert';
  before_digest?: string;
  after_digest?: string;
  chars_before?: number;
  chars_after?: number;
  detail?: string;
}

export type AuditEvent =
  | ToolCallAuditEvent
  | ToolResultAuditEvent
  | ScopeExceededAuditEvent
  | ContextWriteAuditEvent
  | (AuditEventBase & { event: 'anchor_created'; anchor: TrustAnchor })
  | (AuditEventBase & { event: 'decision_recorded'; decision_digest: string; action: DecisionAction })
  | (AuditEventBase & {
      event: 'audit_error';
      operation: string;
      message: string;
    });

/** Envelope fields the audit writer fills; drafts omit exactly these. */
export type AuditDraftBase = Omit<AuditEventBase, 'event'>;

/** Draft accepted by the audit log; envelope fields are filled by the writer. */
export type AuditEventDraft =
  | Omit<ToolCallAuditEvent, keyof AuditDraftBase>
  | Omit<ToolResultAuditEvent, keyof AuditDraftBase>
  | Omit<ScopeExceededAuditEvent, keyof AuditDraftBase>
  | Omit<ContextWriteAuditEvent, keyof AuditDraftBase>
  | { event: 'anchor_created'; anchor: TrustAnchor }
  | { event: 'decision_recorded'; decision_digest: string; action: DecisionAction }
  | { event: 'audit_error'; operation: string; message: string };

/** Resolved runtime-audit configuration (plugin config + environment defaults). */
export interface RuntimeAuditConfig {
  store_dir?: string;
  anchors_file?: string;
  audit_file?: string;
  decisions_file?: string;
  /** tool name -> owning plugin id, for scope checks. */
  tool_owners?: Record<string, string>;
  /** Extra/overriding tool name -> capability keys. */
  tool_capabilities?: Record<string, CapabilityKey[]>;
  /** Argument keys whose values are replaced with `[redacted]` before digesting. */
  redact_argument_keys?: string[];
  /** Record context writes (prompt assembly, inbox inserts, compaction). Default true. */
  context_audit?: boolean;
}

/** Runtime audit API returned by `createRuntimeAudit`. */
export interface RuntimeAuditService {
  readonly store_dir: string;
  readonly audit_log_path: string;
  readonly anchors_log_path: string;
  readonly version: string;
  listAnchors(pluginId?: string): Promise<TrustAnchor[]>;
  /** Append one audit event (complete or draft-shaped) to the append-only channel. */
  record(event: AuditEvent | AuditEventDraft): void;
  reloadAnchors(): Promise<void>;
  setToolOwner(tool: string, pluginId: string): void;
}

/** Full service exposed by the bundle entry: runtime audit + admission evaluation. */
export interface TrustBrokerService extends RuntimeAuditService {
  /** Inspect a plugin tree selected by a trusted Host caller. */
  evaluate(options: Pick<EvaluateOptions, 'root' | 'signal'>): Promise<TrustDecision>;
}

/** What `createRuntimeAudit` returns to the bundle entry. */
export interface RuntimeAuditHandle {
  service: RuntimeAuditService;
  /** Resolved absolute audit log path. */
  audit_log_path: string;
  /** Resolved absolute anchor journal path. */
  anchors_log_path: string;
  /** Re-read anchors after an external confirmation (CLI) or install change. */
  reloadAnchors(): Promise<void>;
  /** Register a tool owner discovered from another host plugin. */
  setToolOwner(tool: string, pluginId: string): void;
  dispose(): void;
}

/** Minimal structural Host context used by the runtime audit factory (testable). */
export interface RuntimeHostContext {
  on(
    name: string,
    listener: (...args: any[]) => unknown,
    options?: { prepend?: boolean } | boolean,
  ): unknown;
  provide?(name: string, service: unknown): unknown;
  logger?: {
    info(message: string, ...args: unknown[]): void;
    warn(message: string, ...args: unknown[]): void;
    error(message: string, ...args: unknown[]): void;
  };
  get?(name: string): unknown;
  /** Optional Cordis effect scope; used only to dispose the audit writer. */
  effect?(execute: () => () => void | Promise<void>): unknown;
}
