/**
 * Wire protocol between the Host review service and the Web client tab.
 *
 * The client only ever receives this compact projection; the full
 * `TrustDecision` stays on the Host and is used to write the anchor.
 */

import type {
  DecisionAction,
  DecisionStatus,
  DeclarationStatus,
  EvidenceRef,
} from '../types.ts';

export type CandidateKind = 'local' | 'npm' | 'git' | 'tarball';

/** How the reviewed candidate was obtained. */
export interface UiResolvedCandidate {
  kind: CandidateKind;
  /** Exact install spec the client should hand to the native install flow. */
  install_spec: string;
  name?: string;
  version?: string;
  registry?: string;
  /** Transport integrity of a registry tarball, when the registry supplied one. */
  tarball_sha256?: string;
  integrity?: 'verified' | 'unavailable';
  /** Free-form notes (for example a range resolved to latest). */
  note?: string;
}

export interface UiCapabilityCategory {
  family: string;
  label: string;
  capability_paths: string[];
  heuristic: boolean;
}

export interface UiDiff {
  id: string;
  type: string;
  code: string;
  capability?: string;
  new_capability: boolean;
  heuristic: boolean;
  summary: string;
  evidence: EvidenceRef[];
}

export interface UiConfirmation {
  code: string;
  message: string;
  ack_token: string;
  diff_ids?: string[];
  capability_keys?: string[];
}

/** Compact decision shown in the Web UI. */
export interface UiDecision {
  status: DecisionStatus;
  action: DecisionAction;
  host_code: true;
  plugin: { id: string; version: string };
  source_trust: { kind: string; detail: string };
  declaration: { status: DeclarationStatus; source_field?: string };
  categories: UiCapabilityCategory[];
  facts_count: number;
  heuristic_count: number;
  install_scripts: Array<{ name: string; command: string }>;
  auto_update: { detected: boolean; declared: boolean; reasons: string[] };
  continuous_trust_warning: boolean;
  content_hash: string | null;
  diffs: UiDiff[];
  confirmations_required: UiConfirmation[];
  errors: Array<{ code: string; message: string }>;
  red_lines: string[];
  coverage_complete: boolean;
}

export interface UiReview {
  review_id: string;
  spec: string;
  resolved: UiResolvedCandidate;
  decision: UiDecision;
  created_at: string;
  /** Reviews expire; the client must run a fresh review instead of confirming. */
  expires_at: string;
}

export interface ReviewSuccess {
  ok: true;
  review: UiReview;
}

export interface ReviewFailure {
  ok: false;
  error: { code: string; message: string };
}

export type ReviewResponse = ReviewSuccess | ReviewFailure;

export interface ConfirmRequest {
  review_id: string;
  acknowledgements: string[];
}

export interface ConfirmSuccess {
  ok: true;
  anchor: {
    plugin_id: string;
    version: string;
    content_hash: string;
    confirmed_at: string;
  };
}

export type ConfirmResponse = ConfirmSuccess | ReviewFailure;

export interface HealthResponse {
  ok: true;
  version: string;
  store_dir: string;
}

/** Native approval payload for a model-initiated `plugin_manager install_bundle`. */
export interface AgentGateReview {
  kind: 'ask' | 'allow';
  reason?: string;
  displayReason?: { en: string; zh?: string };
}
