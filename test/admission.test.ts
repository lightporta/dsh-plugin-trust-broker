import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

import { cleanup, fixturePath, makeTempDir, writeTree } from './helpers.ts';
import {
  admitDecision,
  computeDecisionDigest,
  contentHashUnchanged,
  missingAcknowledgements,
} from '../src/admission/gate.ts';
import { evaluatePluginTrust } from '../src/core/decision.ts';
import { anchorStorePath } from '../src/core/anchor-store.ts';
import { readJsonLines } from './helpers.ts';
import type { TrustDecision } from '../src/types.ts';

const CONSISTENT = fixturePath('decision', 'consistent');
const UNSTATED = fixturePath('decision', 'unstated');

test('gate refuses a block_for_review decision and writes no anchor', async () => {
  const storeDir = await makeTempDir('tb-gate-store-');
  try {
    const decision = await evaluatePluginTrust({
      root: fixturePath('manifest', 'no-package'),
      noExternalScanner: true,
      storeDir,
    });
    const outcome = await admitDecision(decision, {});
    assert.equal(outcome.accepted, false);
    if (outcome.accepted === false) {
      assert.equal(outcome.reason, 'blocked_for_review');
    }
    const anchorsFile = anchorStorePath(storeDir);
    assert.throws(() => readJsonLines(anchorsFile));
  } finally {
    await cleanup(storeDir);
  }
});

test('gate requires explicit acknowledgements before accepting', async () => {
  const storeDir = await makeTempDir('tb-gate-store-');
  try {
    const decision = await evaluatePluginTrust({
      root: UNSTATED,
      noExternalScanner: true,
      storeDir,
    });
    const missing = missingAcknowledgements(decision);
    assert.deepEqual(
      missing.map((requirement) => requirement.code),
      ['unstated_capabilities'],
    );

    const rejected = await admitDecision(decision, {});
    assert.equal(rejected.accepted, false);
    if (rejected.accepted === false) {
      assert.equal(rejected.reason, 'acknowledgement_missing');
      assert.ok(rejected.required.some((item) => item.code === 'unstated_capabilities'));
    }

    const accepted = await admitDecision(decision, {
      acknowledgements: ['unstated_capabilities'],
      acceptedContentHash: decision.content_hash ?? undefined,
      anchorsFile: join(storeDir, 'anchors.jsonl'),
      now: () => new Date('2026-02-02T00:00:00.000Z'),
    });
    assert.equal(accepted.accepted, true);
    if (accepted.accepted) {
      assert.ok(accepted.anchor !== undefined);
      assert.equal(accepted.anchor?.confirmed_by, 'user');
      assert.equal(accepted.anchor?.confirmed_at, '2026-02-02T00:00:00.000Z');
      assert.equal(accepted.anchor?.content_hash, decision.content_hash);
      assert.equal(accepted.anchor?.decision_digest, computeDecisionDigest(decision));
      assert.deepEqual(accepted.anchor?.capability_keys, decision.capability_keys);
    }

    const lines = readJsonLines(join(storeDir, 'anchors.jsonl'));
    assert.equal(lines.length, 1);
  } finally {
    await cleanup(storeDir);
  }
});

test('gate rejects an accepted hash that no longer matches the decision', async () => {
  const storeDir = await makeTempDir('tb-gate-store-');
  try {
    const decision = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
    });
    const outcome = await admitDecision(decision, {
      acceptedContentHash: `sha256:${'1'.repeat(64)}`,
    });
    assert.equal(outcome.accepted, false);
    if (outcome.accepted === false) {
      assert.equal(outcome.reason, 'content_changed');
    }
  } finally {
    await cleanup(storeDir);
  }
});

test('gate blocks when the content hash is unavailable', async () => {
  const storeDir = await makeTempDir('tb-gate-store-');
  try {
    const decision = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
    });
    const unhashed: TrustDecision = {
      ...decision,
      content_hash: null,
      content_hash_error: 'simulated unreadable file',
      action: 'confirm',
      confirmations_required: [],
    };
    const outcome = await admitDecision(unhashed, {});
    assert.equal(outcome.accepted, false);
    if (!outcome.accepted) assert.equal(outcome.reason, 'blocked_for_review');
    await assert.rejects(async () => readJsonLines(anchorStorePath(storeDir)));
  } finally {
    await cleanup(storeDir);
  }
});

test('contentHashUnchanged detects a post-review modification (TOCTOU guard)', async () => {
  const root = await makeTempDir('tb-gate-root-');
  const storeDir = await makeTempDir('tb-gate-store-');
  try {
    await mkdir(root, { recursive: true });
    await copyFile(join(CONSISTENT, 'package.json'), join(root, 'package.json'));
    await writeTree(root, {
      'lib/index.js': "export const apply = () => fetch('https://example.com/health');\n",
    });
    const decision = await evaluatePluginTrust({ root, noExternalScanner: true, storeDir });
    assert.equal(await contentHashUnchanged(decision), true);
    const unconfirmed = await admitDecision(decision);
    assert.equal(unconfirmed.accepted, false);
    if (!unconfirmed.accepted) assert.equal(unconfirmed.reason, 'confirmation_required');

    await writeTree(root, {
      'lib/index.js': "export const apply = () => fetch('https://example.com/health');\n// changed\n",
    });
    assert.equal(await contentHashUnchanged(decision), false);
    const stale = await admitDecision(decision, { acceptedContentHash: decision.content_hash ?? undefined });
    assert.equal(stale.accepted, false);
    if (!stale.accepted) assert.equal(stale.reason, 'content_changed');
    assert.throws(() => readJsonLines(anchorStorePath(storeDir)));
  } finally {
    await cleanup(root);
    await cleanup(storeDir);
  }
});

test('decision digest is stable for the same facts and changes with the content hash', async () => {
  const storeDir = await makeTempDir('tb-gate-store-');
  try {
    const decision = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
    });
    const digestA = computeDecisionDigest(decision);
    const digestB = computeDecisionDigest(decision);
    assert.equal(digestA, digestB);
    assert.match(digestA, /^sha256:[0-9a-f]{64}$/);

    const changed: TrustDecision = {
      ...decision,
      content_hash: `sha256:${'2'.repeat(64)}`,
    };
    assert.notEqual(computeDecisionDigest(changed), digestA);
  } finally {
    await cleanup(storeDir);
  }
});
