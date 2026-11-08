/**
 * Anchor fixtures for the runtime audit / scope tests.
 *
 * Anchors are plain JSON records; the runtime half only consumes `plugin_id`,
 * `confirmed_at` and `capability_keys`, but the fixture is a complete
 * `TrustAnchor` so it can also be written to a real `anchors.jsonl` journal.
 */

import type { TrustAnchor } from '../../../src/types.ts';

/** Build one complete anchor record; pass overrides to change identity/surface. */
export function anchorFixture(overrides: Partial<TrustAnchor> = {}): TrustAnchor {
  const base: TrustAnchor = {
    plugin_id: 'plugin-a',
    version: '1.0.0',
    content_hash: `sha256:${'a'.repeat(64)}`,
    declared_capabilities: {},
    confirmed_at: '2026-01-01T00:00:00.000Z',
    confirmed_by: 'user',
    schema_version: 1,
    capability_keys: [],
    declaration_status: 'declared',
    scanner: { name: 'dsh-trust-check', heuristic: false },
    decision_digest: `sha256:${'b'.repeat(64)}`,
  };
  return { ...base, ...overrides };
}
