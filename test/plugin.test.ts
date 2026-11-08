import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import {
  cleanup,
  createFakeContext,
  fixturePath,
  makeTempDir,
  readJsonLines,
} from './helpers.ts';
import { apply, name as pluginName } from '../src/plugin/index.ts';
import type { TrustBrokerService } from '../src/types.ts';

const CONSISTENT = fixturePath('decision', 'consistent');

test('bundle entry: registers the audit channel, provides trustBroker, evaluates and records', async () => {
  const storeDir = await makeTempDir('tb-plugin-store-');
  try {
    const fake = createFakeContext();
    let dispose: (() => void | Promise<void>) | undefined;
    fake.ctx.effect = (execute) => {
      dispose = execute();
    };

    assert.equal(pluginName, 'dsh-plugin-trust-broker');
    apply(fake.ctx, { store_dir: storeDir });

    const service = fake.services.get('trustBroker') as TrustBrokerService | undefined;
    assert.ok(service !== undefined);
    assert.equal(typeof service?.evaluate, 'function');
    assert.equal(service?.store_dir, storeDir);
    assert.match(service?.version ?? '', /^0\.1\.0$/);

    for (const event of [
      'tools/pre-execute',
      'tools/post-execute',
      'system-prompt/assemble',
      'agent/inbox/inserted',
      'session/event',
    ]) {
      assert.ok(fake.listeners.has(event), `missing listener for ${event}`);
    }

    const decision = await service.evaluate({ root: CONSISTENT });
    assert.equal(decision?.action, 'proceed');
    assert.equal(decision?.plugin.id, 'consistent-plugin');
    assert.deepEqual(await service?.listAnchors(), []);

    // Runtime audit service accepts draft events and writes stable JSONL.
    service?.record({ event: 'context_write', channel: 'inbox_insert', after_digest: 'sha256:abcd' });
    const auditLines = readJsonLines(join(storeDir, 'audit.jsonl'));
    assert.equal(auditLines.length, 1);
    const recorded = auditLines[0] as Record<string, unknown>;
    assert.equal(recorded['schema_version'], 1);
    assert.equal(recorded['event'], 'context_write');
    assert.equal(typeof recorded['seq'], 'number');
    assert.equal(typeof recorded['id'], 'string');
    assert.equal(typeof recorded['ts'], 'string');

    // The pre-execute listener must call next() and return its decision, while
    // appending a tool_call audit record afterwards.
    const listener = fake.listener('tools/pre-execute');
    assert.ok(listener !== undefined);
    const next = async (): Promise<{ kind: 'allow' }> => ({ kind: 'allow' });
    const result = await listener?.(
      { name: 'bash', callId: 'call-1', arguments: { command: 'ls' }, agent: { id: 'session-1' } },
      next,
    );
    assert.deepEqual(result, { kind: 'allow' });

    const after = readJsonLines(join(storeDir, 'audit.jsonl'));
    const toolCall = after.find(
      (record) => (record as Record<string, unknown>)['event'] === 'tool_call',
    ) as Record<string, unknown> | undefined;
    assert.ok(toolCall !== undefined);
    assert.equal(toolCall?.['tool'], 'bash');
    assert.equal(toolCall?.['scope'], 'unattributed');
    assert.match(toolCall?.['arguments_digest'] as string, /^sha256:[0-9a-f]{64}$/);

    assert.equal(typeof dispose, 'function');
    await dispose?.();
  } finally {
    await cleanup(storeDir);
  }
});

test('Host evaluation ignores scanner and journal overrides, then stops when unloaded', async () => {
  const storeDir = await makeTempDir('tb-plugin-store-');
  try {
    const fake = createFakeContext();
    let dispose: (() => void | Promise<void>) | undefined;
    fake.ctx.effect = (execute) => {
      dispose = execute();
    };
    apply(fake.ctx, { store_dir: storeDir });
    const service = fake.services.get('trustBroker') as TrustBrokerService;

    const supplied = {
      root: CONSISTENT,
      scannerReport: { schemaVersion: -1 },
      anchorsFile: '/untrusted-anchor-journal',
      policy: { trust_check_bin: '/untrusted-scanner', require_ack_for_unstated: false },
    };
    const decision = await service.evaluate(supplied);
    assert.equal(decision.scanner.kind, 'heuristic');
    assert.equal(decision.policy.require_ack_for_unstated, true);
    assert.deepEqual(decision.errors, []);

    const pending = assert.rejects(service.evaluate({ root: CONSISTENT }), /is disposed/);
    await dispose?.();
    await pending;
    await assert.rejects(service.evaluate({ root: CONSISTENT }), /is disposed/);

    service.record({ event: 'context_write', channel: 'inbox_insert' });
    assert.equal(existsSync(service.audit_log_path), false);
  } finally {
    await cleanup(storeDir);
  }
});
