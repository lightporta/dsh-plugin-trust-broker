import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmod } from 'node:fs/promises';
import { join } from 'node:path';

import { cleanup, fixturePath, fixedClock, makeTempDir, writeTree } from './helpers.ts';
import { evaluatePluginTrust } from '../src/core/decision.ts';
import { buildTrustAnchor, anchorStorePath } from '../src/core/anchor-store.ts';
import { appendJsonLine } from '../src/core/jsonl.ts';

const CONSISTENT = fixturePath('decision', 'consistent');
const UNDERSTATED = fixturePath('decision', 'understated');
const UNSTATED = fixturePath('decision', 'unstated');
const INSTALL_SCRIPT = fixturePath('decision', 'install-script');
const AUTO_UPDATE = fixturePath('decision', 'auto-update');

async function withStore(fn: (storeDir: string) => Promise<void>): Promise<void> {
  const storeDir = await makeTempDir('tb-decision-store-');
  try {
    await fn(storeDir);
  } finally {
    await cleanup(storeDir);
  }
}

test('consistent declaration: proceed, no diffs, copyable hash, complete coverage', async () => {
  await withStore(async (storeDir) => {
    const decision = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
      now: fixedClock(),
    });

    assert.equal(decision.schema_version, 1);
    assert.equal(decision.host_code, true);
    assert.equal(decision.generated_at, '2026-01-01T00:00:00.000Z');
    assert.equal(decision.status, 'scanned');
    assert.equal(decision.action, 'proceed');
    assert.equal(decision.declaration.status, 'declared');
    assert.equal(decision.source_trust.kind, 'undeclared');
    assert.equal(decision.scanner.kind, 'heuristic');
    assert.match(decision.content_hash ?? '', /^sha256:[0-9a-f]{64}$/);
    assert.equal(decision.coverage.complete, true);
    assert.deepEqual(decision.diffs, []);
    assert.deepEqual(decision.confirmations_required, []);
    assert.equal(decision.anchor.found, false);
    assert.equal(decision.anchor.matched, undefined);

    // Heuristic facts never mix with verifiable facts.
    assert.equal(decision.capabilities.facts.length, 0);
    const heuristicCapabilities = decision.capabilities.heuristic_facts
      .map((fact) => fact.capability)
      .sort();
    assert.deepEqual(heuristicCapabilities, ['filesystem.read', 'network.fetch']);
    assert.ok(decision.capabilities.heuristic_facts.every((fact) => fact.heuristic));
    const evidence = decision.capabilities.heuristic_facts.flatMap((fact) => fact.evidence);
    assert.ok(evidence.some((row) => row.file?.endsWith('lib/index.js') && typeof row.line === 'number'));
  });
});

test('understated declaration: three A diffs, binary new_capability marker distinguishes fs-read', async () => {
  await withStore(async (storeDir) => {
    const decision = await evaluatePluginTrust({
      root: UNDERSTATED,
      noExternalScanner: true,
      storeDir,
    });

    assert.equal(decision.declaration.status, 'declared');
    assert.equal(decision.action, 'confirm');
    assert.equal(decision.status, 'scanned');

    const byCapability = new Map(decision.diffs.map((diff) => [diff.capability, diff]));
    assert.equal(byCapability.size, 3);
    assert.equal(byCapability.get('process.child_process')?.new_capability, true);
    assert.equal(byCapability.get('network.fetch')?.new_capability, true);
    // filesystem.read is the low-privilege catalog entry: still a diff, no forced confirm.
    assert.equal(byCapability.get('filesystem.read')?.new_capability, false);

    for (const diff of decision.diffs) {
      assert.equal(diff.type, 'A_declaration_insufficient');
      assert.equal(diff.code, 'detected_but_declared_false');
      assert.equal(diff.declared?.value, false);
      assert.ok(diff.evidence.length >= 1);
      assert.ok(diff.evidence.some((row) => typeof row.line === 'number'));
      assert.match(diff.summary, /声明 .* = false/);
    }

    assert.deepEqual(
      decision.confirmations_required.map((requirement) => requirement.code),
      ['new_capability'],
    );
    assert.ok(decision.confirmations_required[0]?.capability_keys?.includes('process.child_process'));
    assert.ok(decision.capability_keys.includes('filesystem.read'));
  });
});

test('unstated plugin: no A diffs (nothing to contradict) and a mandatory unstated acknowledgement', async () => {
  await withStore(async (storeDir) => {
    const decision = await evaluatePluginTrust({
      root: UNSTATED,
      noExternalScanner: true,
      storeDir,
    });

    assert.equal(decision.declaration.status, 'unstated');
    assert.equal(decision.action, 'confirm');
    assert.deepEqual(decision.diffs, []);
    assert.deepEqual(
      decision.confirmations_required.map((requirement) => requirement.code),
      ['unstated_capabilities'],
    );
    assert.equal(decision.confirmations_required[0]?.ack_token, '我已知悉');
    assert.match(decision.confirmations_required[0]?.message ?? '', /unstated/);
    assert.deepEqual(decision.capability_keys, ['network.fetch', 'process.child_process']);
  });
});

test('install scripts are reported independently of declarations and always surfaced', async () => {
  await withStore(async (storeDir) => {
    const decision = await evaluatePluginTrust({
      root: INSTALL_SCRIPT,
      noExternalScanner: true,
      storeDir,
    });

    assert.equal(decision.summary.install_scripts.length, 1);
    assert.equal(decision.summary.install_scripts[0]?.name, 'postinstall');
    assert.equal(decision.summary.install_scripts[0]?.command, 'node scripts/setup.js');
    assert.match(
      decision.summary.install_scripts[0]?.evidence.field ?? '',
      /package\.json#scripts\.postinstall/,
    );

    const lifecycleDiff = decision.diffs.find(
      (diff) => diff.capability === 'lifecycle.postinstall',
    );
    assert.ok(lifecycleDiff !== undefined);
    assert.equal(lifecycleDiff.type, 'A_declaration_insufficient');
    assert.equal(lifecycleDiff.new_capability, true);
    assert.equal(lifecycleDiff.heuristic, false);
    assert.match(lifecycleDiff.summary, /postinstall 脚本/);
    assert.equal(decision.action, 'confirm');
  });
});

test('auto_update: separate finding, continuous-trust warning, A diff and confirmation', async () => {
  await withStore(async (storeDir) => {
    const decision = await evaluatePluginTrust({
      root: AUTO_UPDATE,
      noExternalScanner: true,
      storeDir,
    });

    assert.equal(decision.summary.auto_update.declared, true);
    assert.equal(decision.summary.auto_update.detected, true);
    assert.ok(decision.summary.auto_update.reasons.length > 0);
    assert.equal(decision.summary.continuous_trust_warning, true);
    assert.match(decision.summary.continuous_trust_reason ?? '', /安装时审查的内容不等于运行中执行的内容/);

    const autoUpdateDiff = decision.diffs.find((diff) => diff.capability === 'auto_update');
    assert.ok(autoUpdateDiff !== undefined);
    assert.equal(autoUpdateDiff.new_capability, true);
    assert.equal(decision.action, 'confirm');
  });
});

test('malformed declaration: decision status malformed_manifest, treated as unstated, parse error kept', async () => {
  await withStore(async (storeDir) => {
    const decision = await evaluatePluginTrust({
      root: fixturePath('manifest', 'malformed'),
      noExternalScanner: true,
      storeDir,
    });

    assert.equal(decision.status, 'malformed_manifest');
    assert.equal(decision.action, 'confirm');
    assert.equal(decision.declaration.status, 'malformed');
    assert.ok(decision.declaration.errors.some((issue) => issue.code === 'declaration_type'));
    assert.deepEqual(
      decision.confirmations_required.map((requirement) => requirement.code),
      ['unstated_capabilities'],
    );
    assert.match(decision.confirmations_required[0]?.message ?? '', /无法解析/);
  });
});

test('unscannable tree: fail closed with block_for_review and no hash/anchor', async () => {
  await withStore(async (storeDir) => {
    const decision = await evaluatePluginTrust({
      root: fixturePath('manifest', 'no-package'),
      noExternalScanner: true,
      storeDir,
    });

    assert.equal(decision.status, 'unscannable');
    assert.equal(decision.action, 'block_for_review');
    assert.deepEqual(decision.confirmations_required, []);
    assert.equal(decision.content_hash, null);
    assert.equal(decision.coverage.complete, false);
    assert.ok(decision.errors.some((issue) => issue.code === 'package_json_missing'));
    assert.equal(decision.anchor.found, false);
  });
});

test('source metadata: hash mismatch blocks, hash match is reported as a state', async () => {
  await withStore(async (storeDir) => {
    const baseline = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
    });
    const actualHash = baseline.content_hash;
    assert.ok(actualHash !== null);

    const mismatch = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
      sourceMetadata: { tarball_sha256: '0'.repeat(64) },
    });
    assert.equal(mismatch.source_trust.kind, 'hash_mismatch');
    assert.equal(mismatch.action, 'block_for_review');
    const hashDiff = mismatch.diffs.find((diff) => diff.code === 'source_hash_mismatch');
    assert.ok(hashDiff !== undefined);
    assert.equal(hashDiff.new_capability, false);
    assert.equal(mismatch.confirmations_required.length, 0);

    const match = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
      sourceMetadata: { tarball_sha256: actualHash },
    });
    assert.equal(match.source_trust.kind, 'hash_match');
    assert.equal(match.action, 'proceed');
    assert.deepEqual(match.diffs, []);
  });
});

test('an invalid expected hash blocks and a caller-reported signature alone stays unverified', async () => {
  await withStore(async (storeDir) => {
    const options = { root: CONSISTENT, noExternalScanner: true, storeDir };
    const invalid = await evaluatePluginTrust({
      ...options, sourceMetadata: { content_sha256: 'not-a-hash' },
    });
    assert.equal(invalid.action, 'block_for_review');
    assert.equal(invalid.errors[0]?.code, 'expected_hash_invalid');
    const signatureOnly = await evaluatePluginTrust({
      ...options, sourceMetadata: { registry_signature: 'verified' },
    });
    assert.equal(signatureOnly.source_trust.kind, 'unverified');
  });
});

test('an invalid explicit scanner report blocks even with the legacy downgrade flag', async () => {
  await withStore(async (storeDir) => {
    const decision = await evaluatePluginTrust({
      root: CONSISTENT, storeDir, scannerReport: { schemaVersion: 999 },
      policy: { block_on_unscannable: false },
    });
    assert.equal(decision.coverage.complete, false);
    assert.equal(decision.action, 'block_for_review');
  });
});

test('changing the live candidate during snapshot scanning blocks the decision', {
  skip: process.platform === 'win32',
}, async () => {
  const root = await makeTempDir('tb-live-candidate-');
  await withStore(async (storeDir) => {
    try {
      await writeTree(root, {
        'package.json': JSON.stringify({ name: 'snapshot-test', version: '1.0.0' }),
        'index.js': 'export const apply = () => 0;\n',
      });
      const scanner = join(storeDir, 'scanner.mjs');
      await writeTree(storeDir, { 'scanner.mjs': `#!${process.execPath}
import { writeFileSync } from 'node:fs';
writeFileSync(${JSON.stringify(join(root, 'index.js'))}, 'export const apply = () => 1;');
console.log(JSON.stringify({ schemaVersion: 2, plugins: [{ capabilities: [] }] }));
` });
      await chmod(scanner, 0o700);
      const decision = await evaluatePluginTrust({ root, storeDir, policy: { trust_check_bin: scanner } });
      assert.equal(decision.action, 'block_for_review');
      assert.equal(decision.errors[0]?.code, 'content_changed_during_review');
    } finally {
      await cleanup(root);
    }
  });
});

test('repository mismatch is a type-C diff; non-registry dependencies are reported', async () => {
  const root = await makeTempDir('tb-repo-fixture-');
  await withStore(async (storeDir) => {
    try {
      await writeTree(root, {
        'package.json': JSON.stringify({
          name: 'repo-plugin',
          version: '1.0.0',
          type: 'module',
          repository: 'git+https://github.com/example/real-repo.git',
          dependencies: {
            'pinned-dep': 'git+https://github.com/example/dep.git',
            zod: '^4.0.0',
          },
          dsh: { capabilities: { network: { fetch: false }, auto_update: false } },
        }),
        'lib/index.js': 'export const apply = () => 1;\n',
      });

      const baseline = await evaluatePluginTrust({ root, noExternalScanner: true, storeDir });
      assert.ok(baseline.content_hash !== null);

      const decision = await evaluatePluginTrust({
        root,
        noExternalScanner: true,
        storeDir,
        sourceMetadata: {
          tarball_sha256: baseline.content_hash as string,
          repository: 'git+https://github.com/example/other-repo.git',
        },
      });

      const codes = decision.diffs.map((diff) => diff.code).sort();
      assert.deepEqual(codes, ['non_registry_dependency', 'repository_mismatch']);
      assert.ok(decision.diffs.every((diff) => diff.new_capability === false));
      // Type-C provenance diffs are displayed and never enter the mandatory
      // new_capability confirmation queue under default policy.
      assert.equal(decision.action, 'proceed');
      assert.ok(
        decision.confirmations_required.every(
          (requirement) => requirement.code !== 'new_capability',
        ),
      );
    } finally {
      await cleanup(root);
    }
  });
});

test('drift: identical content hash skips re-confirmation; a new capability produces a B diff', async () => {
  const root = await makeTempDir('tb-drift-plugin-');
  await withStore(async (storeDir) => {
    try {
      const v1Files = {
        'package.json': JSON.stringify({
          name: 'drift-plugin',
          version: '2.0.0',
          type: 'module',
        }),
        'lib/index.js': "export const apply = () => fetch('https://example.com/health');\n",
      };
      await writeTree(root, v1Files);
      const first = await evaluatePluginTrust({ root, noExternalScanner: true, storeDir });
      assert.ok(first.content_hash !== null);
      assert.equal(first.declaration.status, 'unstated');

      // Seed the anchor exactly as an earlier user confirmation would have.
      appendJsonLine(
        anchorStorePath(storeDir),
        buildTrustAnchor({
          plugin_id: 'drift-plugin',
          version: '1.0.0',
          content_hash: first.content_hash as string,
          declared_capabilities: {},
          capability_keys: first.capability_keys,
          declaration_status: 'unstated',
          scanner: { name: 'heuristic', heuristic: true },
          decision_digest: `sha256:${'a'.repeat(64)}`,
          confirmed_by: 'user',
          confirmed_at: '2025-12-01T00:00:00.000Z',
        }),
      );

      // Same tree again: identical content hash => skip duplicate confirmation.
      const same = await evaluatePluginTrust({ root, noExternalScanner: true, storeDir });
      assert.equal(same.anchor.matched?.version, '1.0.0');
      assert.deepEqual(same.confirmations_required, []);
      assert.equal(same.action, 'proceed');
      assert.ok(!same.diffs.some((diff) => diff.type === 'B_capability_drift'));

      // New version adds a child_process capability.
      await writeTree(root, {
        'lib/index.js':
          "import { exec } from 'node:child_process';\nexport const apply = () => { exec('echo drift'); fetch('https://example.com/health'); };\n",
      });
      const drifted = await evaluatePluginTrust({ root, noExternalScanner: true, storeDir });
      assert.equal(drifted.anchor.latest?.version, '1.0.0');
      const driftDiff = drifted.diffs.find((diff) => diff.type === 'B_capability_drift');
      assert.ok(driftDiff !== undefined);
      assert.equal(driftDiff.capability, 'process.child_process');
      assert.equal(driftDiff.new_capability, true);
      assert.equal(driftDiff.previous?.version, '1.0.0');
      assert.equal(driftDiff.previous?.confirmed_by, 'user');
      assert.match(driftDiff.summary, /已确认版本 v1\.0\.0/);
      assert.ok(
        drifted.confirmations_required.some(
          (requirement) => requirement.code === 'new_capability',
        ),
      );
      // network.fetch existed in the anchor, so only one B diff appears.
      assert.equal(
        drifted.diffs.filter((diff) => diff.type === 'B_capability_drift').length,
        1,
      );
    } finally {
      await cleanup(root);
    }
  });
});

test('policy relaxations are recorded in the decision and can waive forced confirmations', async () => {
  await withStore(async (storeDir) => {
    const decision = await evaluatePluginTrust({
      root: UNDERSTATED,
      noExternalScanner: true,
      storeDir,
      policy: {
        confirm_on_new_capability: false,
        require_ack_for_unstated: false,
      },
    });

    assert.equal(decision.policy.confirm_on_new_capability, false);
    assert.deepEqual(decision.confirmations_required, []);
    assert.equal(decision.action, 'proceed');
    // The facts and binary markers stay visible even when the gate is relaxed.
    assert.ok(decision.diffs.some((diff) => diff.new_capability));
  });
});


test('an invalid anchor journal blocks evaluation without discarding scanned evidence', async () => {
  await withStore(async (storeDir) => {
    const baseline = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
    });
    assert.ok(baseline.content_hash !== null);
    const valid = buildTrustAnchor({
      plugin_id: baseline.plugin.id,
      version: baseline.plugin.version,
      content_hash: baseline.content_hash as string,
      declared_capabilities: baseline.declaration.declared,
      capability_keys: baseline.capability_keys,
      declaration_status: baseline.declaration.status,
      scanner: baseline.scanner,
      decision_digest: `sha256:${'a'.repeat(64)}`,
      confirmed_by: 'user',
      confirmed_at: '2026-01-01T00:00:00.000Z',
    });
    appendJsonLine(anchorStorePath(storeDir), { ...valid, content_hash: 'sha256:short' });

    const decision = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
    });
    assert.equal(decision.status, 'unscannable');
    assert.equal(decision.action, 'block_for_review');
    assert.ok(decision.content_hash !== null);
    assert.ok(decision.capabilities.heuristic_facts.length > 0);
    assert.ok(decision.errors.some((issue) => issue.code === 'anchor_journal_invalid'));
  });
});

test('an unreadable anchor journal blocks evaluation', {
  skip: process.platform === 'win32',
}, async (t) => {
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    t.skip('running as root: chmod 000 does not block reads');
    return;
  }
  await withStore(async (storeDir) => {
    const baseline = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
    });
    assert.ok(baseline.content_hash !== null);
    appendJsonLine(anchorStorePath(storeDir), buildTrustAnchor({
      plugin_id: baseline.plugin.id,
      version: baseline.plugin.version,
      content_hash: baseline.content_hash as string,
      declared_capabilities: baseline.declaration.declared,
      capability_keys: baseline.capability_keys,
      declaration_status: baseline.declaration.status,
      scanner: baseline.scanner,
      decision_digest: `sha256:${'a'.repeat(64)}`,
      confirmed_by: 'user',
      confirmed_at: '2026-01-01T00:00:00.000Z',
    }));
    const anchorsFile = anchorStorePath(storeDir);
    await chmod(anchorsFile, 0o000);
    try {
      const decision = await evaluatePluginTrust({
        root: CONSISTENT,
        noExternalScanner: true,
        storeDir,
      });
      assert.equal(decision.status, 'unscannable');
      assert.equal(decision.action, 'block_for_review');
      assert.ok(decision.errors.some((issue) => issue.code === 'anchor_journal_unreadable'));
    } finally {
      await chmod(anchorsFile, 0o600);
    }
  });
});

test('latest anchor display compares timezone-offset timestamps chronologically', async () => {
  await withStore(async (storeDir) => {
    const baseline = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
    });
    assert.ok(baseline.content_hash !== null);
    const anchor = (version: string, confirmedAt: string) => buildTrustAnchor({
      plugin_id: baseline.plugin.id,
      version,
      content_hash: baseline.content_hash as string,
      declared_capabilities: baseline.declaration.declared,
      capability_keys: baseline.capability_keys,
      declaration_status: baseline.declaration.status,
      scanner: baseline.scanner,
      decision_digest: `sha256:${'a'.repeat(64)}`,
      confirmed_by: 'user',
      confirmed_at: confirmedAt,
    });
    appendJsonLine(anchorStorePath(storeDir), anchor('1.0.0', '2026-01-01T00:30:00.000+08:00'));
    appendJsonLine(anchorStorePath(storeDir), anchor('1.1.0', '2025-12-31T17:00:00.000Z'));

    const decision = await evaluatePluginTrust({
      root: CONSISTENT,
      noExternalScanner: true,
      storeDir,
    });
    assert.equal(decision.anchor.latest?.version, '1.1.0');
  });
});
