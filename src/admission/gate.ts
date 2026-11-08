/**
 * The admission gate: the only place a `TrustDecision` becomes an accepted
 * install. It enforces the brief's fail-closed defaults:
 * - an action of `block_for_review` is never admitted;
 * - every required confirmation must be acknowledged explicitly;
 * - the accepted content hash must match both the review and the current tree;
 * - success always persists a `TrustAnchor`.
 */

import { AnchorStore, buildTrustAnchor, anchorStorePath } from '../core/anchor-store.ts';
import { computeContentHash } from '../core/hash.ts';
import { digestJson, isoNow } from '../core/fs-utils.ts';
import type {
  AdmissionOutcome,
  AdmissionRejected,
  ConfirmationRequirement,
  ConfirmedBy,
  TrustDecision,
} from '../types.ts';

export interface AdmitOptions {
  /** Confirmation codes the caller obtained from the user (or policy). */
  acknowledgements?: readonly ConfirmationRequirement['code'][];
  /** Hash the user actually saw and confirmed; guards content changes. */
  acceptedContentHash?: string;
  /** Anchor journal path; defaults to `<policy.store_dir>/anchors.jsonl`. */
  anchorsFile?: string;
  confirmedBy?: ConfirmedBy;
  now?: () => Date;
  notes?: string;
}

/** Canonical digest binding an anchor to the exact decision facts the user saw. */
export function computeDecisionDigest(decision: TrustDecision): string {
  return digestJson({
    schema_version: decision.schema_version,
    plugin: { id: decision.plugin.id, version: decision.plugin.version },
    content_hash: decision.content_hash,
    declaration: decision.declaration,
    source_trust: decision.source_trust,
    capability_keys: decision.capability_keys,
    scanner: decision.scanner,
    status: decision.status,
    action: decision.action,
    red_lines: decision.red_lines,
    diffs: decision.diffs,
    confirmations: decision.confirmations_required.map((requirement) => requirement.code),
  });
}

/** Confirmations still missing from a caller-supplied acknowledgement list. */
export function missingAcknowledgements(
  decision: TrustDecision,
  acknowledgements: readonly ConfirmationRequirement['code'][] = [],
): ConfirmationRequirement[] {
  const given = new Set(acknowledgements);
  return decision.confirmations_required.filter((requirement) => !given.has(requirement.code));
}

/** Re-hash the tree to detect a change between review and anchoring (TOCTOU). */
export async function contentHashUnchanged(decision: TrustDecision): Promise<boolean> {
  if (decision.content_hash === null) return false;
  const result = await computeContentHash(decision.plugin.root, { strict: true });
  return result.hash === decision.content_hash;
}

function rejected(
  decision: TrustDecision,
  reason: AdmissionRejected['reason'],
  message: string,
  required: ConfirmationRequirement[],
): AdmissionRejected {
  return { accepted: false, decision, reason, message, required };
}

/**
 * Gate a decision and (when admitted) persist exactly one `TrustAnchor`.
 *
 * Throws only when the anchor journal cannot be written: a failed anchor write
 * must not look like a successful admission.
 */
export async function admitDecision(
  decision: TrustDecision,
  options: AdmitOptions = {},
): Promise<AdmissionOutcome> {
  if (
    decision.action === 'block_for_review' || decision.status === 'unscannable' ||
    !decision.coverage.complete || decision.content_hash === null
  ) {
    return rejected(
      decision,
      'blocked_for_review',
      '决策要求人工复核（block_for_review）：未写入信任锚点，不得进入加载。',
      decision.confirmations_required,
    );
  }

  const missing = missingAcknowledgements(decision, options.acknowledgements ?? []);
  if (missing.length > 0) {
    return rejected(
      decision,
      'acknowledgement_missing',
      `缺少 ${missing.length} 项强制确认：${missing.map((item) => item.code).join(', ')}。`,
      missing,
    );
  }

  if (options.acceptedContentHash === undefined) {
    return rejected(decision, 'confirmation_required', '必须明确接受完整的内容哈希后才能锚定。', []);
  }
  if (options.acceptedContentHash.trim() !== decision.content_hash || !(await contentHashUnchanged(decision))) {
    return rejected(decision, 'content_changed', '内容哈希不匹配或内容在审查后发生变化。', []);
  }

  const acknowledged = [...new Set(options.acknowledgements ?? [])];
  const anchorsFile = options.anchorsFile ?? anchorStorePath(decision.policy.store_dir);
  const store = new AnchorStore({ file: anchorsFile });
  const now = options.now ?? (() => new Date());
  const anchor = buildTrustAnchor({
    plugin_id: decision.plugin.id,
    version: decision.plugin.version,
    content_hash: decision.content_hash,
    declared_capabilities: decision.declaration.declared,
    capability_keys: decision.capability_keys,
    declaration_status: decision.declaration.status,
    scanner: decision.scanner,
    decision_digest: computeDecisionDigest(decision),
    confirmed_by: options.confirmedBy ?? 'user',
    confirmed_at: isoNow(now),
    ...(options.notes !== undefined ? { notes: options.notes } : {}),
  });
  await store.record(anchor);

  return { accepted: true, decision, acknowledged, anchor };
}
