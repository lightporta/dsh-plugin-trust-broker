/**
 * Capability drift against the last confirmed trust anchor (diff type
 * `B_capability_drift` input).
 *
 * Two questions are answered here:
 * 1. Have these exact bytes already been confirmed? Then re-confirmation is
 *    skipped only if the earlier anchor covers all currently reported capabilities.
 * 2. Otherwise, which capability keys are new relative to the latest confirmed
 *    anchor of the same plugin, and which disappeared? New keys are reported
 *    unfiltered; the diff engine decides the binary `new_capability` flag from
 *    the catalog (`high_privilege`). Removals are informational only and never
 *    require re-confirmation.
 *
 * The function is pure: inputs are never mutated, and output order is
 * deterministic (catalog `DECLARABLE_PATHS` order first, observable-only
 * extension paths after, unknown keys last in lexical order) so two identical
 * decisions serialize identically.
 */

import type {
  CapabilityKey,
  DriftCapability,
  DriftResult,
  EvidenceRef,
  TrustAnchor,
} from '../types.ts';
import { CAPABILITY_DEFINITIONS, DECLARABLE_PATHS } from './catalog.ts';

/** Declarable capability paths, in catalog order. */
const DECLARABLE_RANK: ReadonlyMap<string, number> = new Map(
  DECLARABLE_PATHS.map((path, index) => [path, index]),
);

/** Observable-only capability paths (no declaration slot), in catalog order. */
const EXTENSION_RANK: ReadonlyMap<string, number> = new Map(
  CAPABILITY_DEFINITIONS.filter((definition) => !definition.declarable).map(
    (definition, index) => [definition.path, index],
  ),
);

/** Input of {@link detectCapabilityDrift}. */
export interface DriftInput {
  plugin_id: string;
  current_version: string;
  /** Canonical hash of the current tree; null when it could not be computed. */
  current_content_hash: string | null;
  current_capability_keys: CapabilityKey[];
  /** Evidence per capability for the current tree; used for new capabilities. */
  evidence?: Partial<Record<CapabilityKey, EvidenceRef[]>>;
  /** Candidate anchors (the caller may pass the whole store); ours are filtered. */
  anchors: TrustAnchor[];
}

/**
 * Compare the current capability set with the latest confirmed anchor.
 *
 * Rules:
 * - Only anchors with the same `plugin_id` are considered.
 * - If any such anchor has the same `content_hash` as the current tree, the
 *   result is `skipped_reconfirmation: true` with `matched_anchor` and no new
 *   capabilities (identical content needs no re-confirmation).
 * - Otherwise the latest anchor (greatest `confirmed_at`, later input wins on a
 *   tie) is the comparison baseline: `new_capabilities = current - previous`,
 *   `reduced_capabilities = previous - current`.
 * - With no anchor for this plugin, `new_capabilities` is empty and `note` is
 *   `'no previous anchor'`; the caller treats the whole surface as new.
 *
 * New capability entries carry `previous_version` = baseline anchor version and
 * the caller-supplied evidence, falling back to the meta pointer
 * `{ field: 'anchor.capability_keys', snippet: previousAnchor.version }`.
 *
 * @param input Current plugin facts plus candidate anchors.
 * @returns Deterministic drift facts; never mutates the input.
 */
export function detectCapabilityDrift(input: DriftInput): DriftResult {
  const anchors = input.anchors.filter((anchor) => anchor.plugin_id === input.plugin_id);
  const currentKeys = [...input.current_capability_keys];
  const currentSet = new Set<CapabilityKey>(currentKeys);

  const matched = input.current_content_hash === null
    ? undefined
    : pickLatestAnchor(anchors.filter((anchor) => anchor.content_hash === input.current_content_hash));
  if (matched !== undefined) {
    const covered = new Set(matched.capability_keys);
    if (currentKeys.every((key) => covered.has(key))) {
      return {
        new_capabilities: [],
        reduced_capabilities: [],
        skipped_reconfirmation: true,
        matched_anchor: matched,
      };
    }
  }

  const compared = matched ?? pickLatestAnchor(anchors);
  if (compared === undefined) {
    return {
      new_capabilities: [],
      reduced_capabilities: [],
      skipped_reconfirmation: false,
      note: 'no previous anchor',
    };
  }

  const previousKeys = [...compared.capability_keys];
  const previousSet = new Set<CapabilityKey>(previousKeys);
  const added = sortedUniqueKeys(currentKeys.filter((key) => !previousSet.has(key)));
  const removed = sortedUniqueKeys(previousKeys.filter((key) => !currentSet.has(key)));

  const evidenceByCapability = input.evidence;
  const newCapabilities: DriftCapability[] = added.map((capability) => {
    const provided = evidenceByCapability?.[capability];
    return {
      capability,
      previous_version: compared.version,
      evidence:
        provided === undefined
          ? [{ field: 'anchor.capability_keys', snippet: compared.version }]
          : cloneEvidence(provided),
    };
  });

  return {
    compared_anchor: compared,
    new_capabilities: newCapabilities,
    reduced_capabilities: removed,
    skipped_reconfirmation: false,
  };
}

/** Latest anchor by confirmed_at; ties resolved by later input order. */
function pickLatestAnchor(anchors: readonly TrustAnchor[]): TrustAnchor | undefined {
  let best: TrustAnchor | undefined;
  let bestTime = Number.NEGATIVE_INFINITY;
  let bestIndex = -1;
  anchors.forEach((anchor, index) => {
    const time = Date.parse(anchor.confirmed_at);
    if (time > bestTime || (time === bestTime && index > bestIndex)) {
      best = anchor;
      bestTime = time;
      bestIndex = index;
    }
  });
  return best;
}

/** Deduplicate and order keys deterministically for stable output. */
function sortedUniqueKeys(keys: readonly CapabilityKey[]): CapabilityKey[] {
  return [...new Set<CapabilityKey>(keys)].sort(compareCapabilityKeys);
}

/**
 * Deterministic capability order: declarable catalog order, then observable-only
 * extension paths in catalog order, then unknown keys lexicographically.
 */
function compareCapabilityKeys(left: CapabilityKey, right: CapabilityKey): number {
  const declarableLeft = DECLARABLE_RANK.get(left);
  const declarableRight = DECLARABLE_RANK.get(right);
  if (declarableLeft !== undefined || declarableRight !== undefined) {
    if (declarableLeft !== undefined && declarableRight !== undefined) {
      return declarableLeft - declarableRight;
    }
    return declarableLeft !== undefined ? -1 : 1;
  }
  const extensionLeft = EXTENSION_RANK.get(left);
  const extensionRight = EXTENSION_RANK.get(right);
  if (extensionLeft !== undefined || extensionRight !== undefined) {
    if (extensionLeft !== undefined && extensionRight !== undefined) {
      return extensionLeft - extensionRight;
    }
    return extensionLeft !== undefined ? -1 : 1;
  }
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Copy evidence pointers so the result never aliases caller objects. */
function cloneEvidence(evidence: readonly EvidenceRef[]): EvidenceRef[] {
  return evidence.map((reference) => ({ ...reference }));
}
