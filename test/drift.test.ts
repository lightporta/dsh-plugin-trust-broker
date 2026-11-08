/**
 * Tests for capability drift detection against confirmed trust anchors.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildTrustAnchor } from '../src/core/anchor-store.ts';
import type { BuildAnchorInput } from '../src/core/anchor-store.ts';
import { detectCapabilityDrift } from '../src/core/drift.ts';
import type { DriftInput } from '../src/core/drift.ts';
import { sha256Hex } from '../src/core/fs-utils.ts';
import type { CapabilityKey, EvidenceRef, TrustAnchor } from '../src/types.ts';

/** Deterministic content hash for a seed. */
function contentHash(seed: string): string {
  return `sha256:${sha256Hex(seed)}`;
}

/** Build a confirmed anchor for the drift tests. */
function anchorOf(
  version: string,
  capabilityKeys: CapabilityKey[],
  options: {
    content_hash?: string;
    confirmed_at?: string;
    plugin_id?: string;
    confirmed_by?: 'user' | 'policy';
  } = {},
): TrustAnchor {
  const input: BuildAnchorInput = {
    plugin_id: options.plugin_id ?? 'plugin-a',
    version,
    content_hash: options.content_hash ?? contentHash(`plugin-a@${version}`),
    declared_capabilities: {},
    capability_keys: [...capabilityKeys],
    declaration_status: 'declared',
    scanner: { name: 'dsh-trust-check', heuristic: false },
    decision_digest: contentHash(`decision:${version}`),
    confirmed_by: options.confirmed_by ?? 'user',
    confirmed_at: options.confirmed_at ?? '2026-01-01T00:00:00.000Z',
  };
  return buildTrustAnchor(input);
}

/** Assemble a drift input with test-friendly defaults. */
function driftInput(overrides: Partial<DriftInput> = {}): DriftInput {
  return {
    plugin_id: 'plugin-a',
    current_version: '1.1.0',
    current_content_hash: contentHash('current'),
    current_capability_keys: [],
    anchors: [],
    ...overrides,
  };
}

test('a new capability is flagged with the previous anchor version', () => {
  const previous = anchorOf('1.0.0', ['network.fetch', 'filesystem.read']);
  const result = detectCapabilityDrift(
    driftInput({
      current_capability_keys: ['network.fetch', 'filesystem.read', 'process.exec'],
      anchors: [previous],
    }),
  );

  assert.equal(result.skipped_reconfirmation, false);
  assert.equal(result.new_capabilities.length, 1);
  assert.equal(result.new_capabilities[0]?.capability, 'process.exec');
  assert.equal(result.new_capabilities[0]?.previous_version, '1.0.0');
  assert.deepEqual(result.new_capabilities[0]?.evidence, [
    { field: 'anchor.capability_keys', snippet: '1.0.0' },
  ]);
  assert.deepEqual(result.reduced_capabilities, []);
  assert.equal(result.matched_anchor, undefined);
  assert.equal(result.compared_anchor?.version, '1.0.0');
});

test('a removed capability is only informational', () => {
  const previous = anchorOf('1.0.0', [
    'network.fetch',
    'filesystem.read',
    'process.exec',
  ]);
  const result = detectCapabilityDrift(
    driftInput({
      current_capability_keys: ['network.fetch'],
      anchors: [previous],
    }),
  );

  assert.equal(result.skipped_reconfirmation, false);
  assert.deepEqual(result.new_capabilities, []);
  // Deterministic catalog order: process.exec precedes filesystem.read.
  assert.deepEqual(result.reduced_capabilities, ['process.exec', 'filesystem.read']);
  assert.equal(result.compared_anchor?.version, '1.0.0');
});

test('identical content hash does not waive newly discovered capabilities', () => {
  const shared = contentHash('shared-bytes');
  const previous = anchorOf('1.0.0', ['network.fetch'], { content_hash: shared });
  const result = detectCapabilityDrift(
    driftInput({
      current_content_hash: shared,
      current_capability_keys: ['network.fetch', 'process.exec'],
      anchors: [previous],
    }),
  );

  assert.equal(result.skipped_reconfirmation, false);
  assert.equal(result.matched_anchor, undefined);
  assert.deepEqual(result.new_capabilities.map((item) => item.capability), ['process.exec']);
  assert.deepEqual(result.reduced_capabilities, []);
  assert.equal(result.compared_anchor?.version, '1.0.0');
  assert.equal(result.note, undefined);
});

test('the skip match may be an older anchor than the latest one', () => {
  const shared = contentHash('confirmed-bytes');
  const newer = anchorOf('2.0.0', ['network.fetch', 'process.exec'], {
    content_hash: contentHash('changed-bytes'),
    confirmed_at: '2026-05-01T00:00:00.000Z',
  });
  const olderMatching = anchorOf('1.0.0', ['network.fetch'], {
    content_hash: shared,
    confirmed_at: '2026-01-01T00:00:00.000Z',
  });
  const result = detectCapabilityDrift(
    driftInput({
      current_content_hash: shared,
      current_capability_keys: ['network.fetch'],
      anchors: [newer, olderMatching],
    }),
  );

  assert.equal(result.skipped_reconfirmation, true);
  assert.equal(result.matched_anchor?.version, '1.0.0');
  assert.equal(result.new_capabilities.length, 0);
});

test('without an anchor the result is empty and noted', () => {
  const empty = detectCapabilityDrift(
    driftInput({ current_capability_keys: ['network.fetch', 'process.exec'] }),
  );
  assert.deepEqual(empty.new_capabilities, []);
  assert.deepEqual(empty.reduced_capabilities, []);
  assert.equal(empty.note, 'no previous anchor');
  assert.equal(empty.skipped_reconfirmation, false);
  assert.equal(empty.matched_anchor, undefined);
  assert.equal(empty.compared_anchor, undefined);

  // Anchors of other plugins do not count either.
  const foreign = anchorOf('9.0.0', ['network.fetch'], { plugin_id: 'plugin-b' });
  const onlyForeign = detectCapabilityDrift(
    driftInput({ current_capability_keys: ['network.fetch'], anchors: [foreign] }),
  );
  assert.equal(onlyForeign.note, 'no previous anchor');
  assert.deepEqual(onlyForeign.new_capabilities, []);
});

test('only the latest anchor of the same plugin is the baseline', () => {
  const v1 = anchorOf('1.0.0', ['network.fetch'], {
    confirmed_at: '2026-01-01T00:00:00.000Z',
  });
  const v2 = anchorOf('2.0.0', ['network.fetch', 'filesystem.write'], {
    confirmed_at: '2026-02-01T00:00:00.000Z',
  });
  const result = detectCapabilityDrift(
    driftInput({
      current_capability_keys: ['network.fetch', 'process.exec'],
      anchors: [v2, v1],
    }),
  );

  assert.equal(result.compared_anchor?.version, '2.0.0');
  assert.deepEqual(result.new_capabilities.map((entry) => entry.capability), ['process.exec']);
  assert.deepEqual(result.reduced_capabilities, ['filesystem.write']);
  assert.equal(result.skipped_reconfirmation, false);
});

test('a confirmed_at tie is broken by later input order', () => {
  const timestamp = '2026-03-01T00:00:00.000Z';
  const firstInArray = anchorOf('9.0.0', ['network.fetch'], { confirmed_at: timestamp });
  const laterInArray = anchorOf('1.0.0', ['network.fetch'], { confirmed_at: timestamp });
  const result = detectCapabilityDrift(
    driftInput({
      current_capability_keys: ['network.fetch', 'process.exec'],
      anchors: [firstInArray, laterInArray],
    }),
  );

  assert.equal(result.compared_anchor?.version, '1.0.0');
  assert.equal(result.new_capabilities[0]?.previous_version, '1.0.0');
});

test('new capability order is catalog order, then extensions, then unknown keys', () => {
  const previous = anchorOf('1.0.0', []);
  const currentKeys = [
    'llm.call',
    'network.fetch',
    'host_runtime.dependency',
    'composition.override',
    'zzz.unknown',
    'aaa.unknown',
    'filesystem.read',
    'network.fetch',
  ] as CapabilityKey[];
  const result = detectCapabilityDrift(
    driftInput({ current_capability_keys: currentKeys, anchors: [previous] }),
  );

  assert.deepEqual(
    result.new_capabilities.map((entry) => entry.capability),
    [
      'network.fetch',
      'filesystem.read',
      'llm.call',
      'host_runtime.dependency',
      'composition.override',
      'aaa.unknown',
      'zzz.unknown',
    ],
  );
});

test('caller evidence is used for new capabilities and inputs are not mutated', () => {
  const previous = anchorOf('1.0.0', ['network.fetch']);
  const provided: EvidenceRef[] = [{ file: 'src/run.ts', line: 12, snippet: 'spawn(...)' }];
  const result = detectCapabilityDrift(
    driftInput({
      current_capability_keys: ['network.fetch', 'process.exec', 'filesystem.write'],
      evidence: { 'process.exec': provided },
      anchors: [previous],
    }),
  );

  const processExec = result.new_capabilities.find((entry) => entry.capability === 'process.exec');
  const filesystemWrite = result.new_capabilities.find(
    (entry) => entry.capability === 'filesystem.write',
  );
  assert.deepEqual(processExec?.evidence, provided);
  assert.notEqual(processExec?.evidence, provided); // copied, not aliased
  assert.deepEqual(filesystemWrite?.evidence, [
    { field: 'anchor.capability_keys', snippet: '1.0.0' },
  ]);

  // Frozen inputs must not be mutated (or written through).
  const frozenAnchor = anchorOf('2.0.0', ['network.fetch']);
  const frozenAnchors = Object.freeze([frozenAnchor]) as readonly TrustAnchor[];
  const frozenKeys = Object.freeze(['network.fetch', 'process.exec']) as readonly CapabilityKey[];
  const frozenEvidence = Object.freeze({
    'process.exec': Object.freeze([{ file: 'src/run.ts', line: 12 }]),
  });
  const before = JSON.stringify({ frozenAnchor, frozenKeys, frozenEvidence });
  const frozenResult = detectCapabilityDrift({
    plugin_id: 'plugin-a',
    current_version: '2.1.0',
    current_content_hash: contentHash('next'),
    current_capability_keys: [...frozenKeys],
    evidence: frozenEvidence as unknown as Partial<Record<CapabilityKey, EvidenceRef[]>>,
    anchors: [...frozenAnchors],
  });
  assert.equal(JSON.stringify({ frozenAnchor, frozenKeys, frozenEvidence }), before);
  assert.deepEqual(frozenResult.new_capabilities.map((entry) => entry.capability), ['process.exec']);
});

test('content identical to an anchor and null current hash behave correctly', () => {
  const previous = anchorOf('1.0.0', ['network.fetch']);
  const nullHash = detectCapabilityDrift(
    driftInput({
      current_content_hash: null,
      current_capability_keys: ['network.fetch', 'process.exec'],
      anchors: [previous],
    }),
  );
  assert.equal(nullHash.skipped_reconfirmation, false);
  assert.deepEqual(nullHash.new_capabilities.map((entry) => entry.capability), ['process.exec']);
  assert.equal(nullHash.compared_anchor?.version, '1.0.0');

  const noKeysCurrent = detectCapabilityDrift(
    driftInput({ current_capability_keys: [], anchors: [previous] }),
  );
  assert.deepEqual(noKeysCurrent.new_capabilities, []);
  assert.deepEqual(noKeysCurrent.reduced_capabilities, ['network.fetch']);
});

test('removed key ordering matches the new-key ordering rules', () => {
  const previous = anchorOf('1.0.0', [
    'network.fetch',
    'zzz.unknown',
    'host_runtime.dependency',
    'filesystem.read',
  ] as CapabilityKey[]);
  const result = detectCapabilityDrift(
    driftInput({ current_capability_keys: [], anchors: [previous] }),
  );
  assert.deepEqual(result.reduced_capabilities, [
    'network.fetch',
    'filesystem.read',
    'host_runtime.dependency',
    'zzz.unknown',
  ]);
  assert.deepEqual(result.new_capabilities, []);
});

test('low-privilege and high-privilege new keys are reported alike', () => {
  const previous = anchorOf('1.0.0', []);
  const result = detectCapabilityDrift(
    driftInput({
      current_capability_keys: ['filesystem.read', 'network.socket'],
      anchors: [previous],
    }),
  );
  assert.deepEqual(
    result.new_capabilities.map((entry) => entry.capability),
    ['network.socket', 'filesystem.read'],
  );
  assert.equal(result.new_capabilities.length, 2);
  assert.equal(result.new_capabilities.every((entry) => entry.previous_version === '1.0.0'), true);
});
