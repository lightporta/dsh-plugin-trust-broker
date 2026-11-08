/**
 * Tests for the runtime audit channel: the tolerant append-only {@link AuditLog}
 * and the Host-side {@link createRuntimeAudit} factory driving structural
 * listeners registered on a fake Host context (`test/helpers.ts`).
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { appendFile, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { DEFAULT_REDACT_KEYS, digestJson, redactDeep } from '../src/core/fs-utils.ts';
import { JsonlWriter } from '../src/core/jsonl.ts';
import { AuditLog } from '../src/runtime/audit-log.ts';
import { createRuntimeAudit } from '../src/runtime/audit.ts';
import { TRUST_BROKER_VERSION } from '../src/version.ts';
import { cleanup, createFakeContext, fixedClock, makeTempDir, readJsonLines } from './helpers.ts';
import type { FakeContext } from './helpers.ts';
import { anchorFixture } from './fixtures/runtime/anchors.ts';
import type {
  AuditEvent,
  ContextWriteAuditEvent,
  RuntimeAuditConfig,
  RuntimeAuditHandle,
  RuntimeAuditService,
  ScopeExceededAuditEvent,
  ToolCallAuditEvent,
  ToolResultAuditEvent,
  TrustAnchor,
} from '../src/types.ts';

/** Anchor declaring a network-only surface for plugin-a. */
const NETWORK_ANCHOR = anchorFixture({
  plugin_id: 'plugin-a',
  capability_keys: ['network.fetch'],
  confirmed_at: '2026-01-01T00:00:00.000Z',
});

/** All anchors with a broader confirmed surface, used after a reload. */
function expandedAnchor(): TrustAnchor {
  return anchorFixture({
    plugin_id: 'plugin-a',
    capability_keys: [
      'process.child_process',
      'process.exec',
      'filesystem.read',
      'filesystem.write',
      'network.fetch',
    ],
    confirmed_at: '2026-02-01T00:00:00.000Z',
  });
}

/* ------------------------------------------------------------------------- */
/* Shared helpers.                                                           */
/* ------------------------------------------------------------------------- */

/** Parse the audit journal, tolerating a not-yet-created file. */
function readEvents(file: string): AuditEvent[] {
  if (!existsSync(file)) return [];
  return readJsonLines(file) as AuditEvent[];
}

function toolCalls(file: string): ToolCallAuditEvent[] {
  return readEvents(file).filter((event): event is ToolCallAuditEvent => event.event === 'tool_call');
}

function toolResults(file: string): ToolResultAuditEvent[] {
  return readEvents(file).filter(
    (event): event is ToolResultAuditEvent => event.event === 'tool_result',
  );
}

function scopeExceeded(file: string): ScopeExceededAuditEvent[] {
  return readEvents(file).filter(
    (event): event is ScopeExceededAuditEvent => event.event === 'scope_exceeded',
  );
}

function contextWrites(file: string): ContextWriteAuditEvent[] {
  return readEvents(file).filter(
    (event): event is ContextWriteAuditEvent => event.event === 'context_write',
  );
}

/** Write an anchor journal into `storeDir`. */
async function seedAnchors(storeDir: string, anchors: readonly TrustAnchor[]): Promise<void> {
  const lines = anchors.map((anchor) => JSON.stringify(anchor)).join('\n');
  await writeFile(join(storeDir, 'anchors.jsonl'), lines === '' ? '' : `${lines}\n`, 'utf8');
}

interface Harness {
  root: string;
  fake: FakeContext;
  handle: RuntimeAuditHandle;
  auditFile: string;
}

/** Create a temp store with seeded anchors and a runtime audit mounted on a fake context. */
async function openHarness(
  anchors: readonly TrustAnchor[],
  config: RuntimeAuditConfig = {},
): Promise<Harness> {
  const root = await makeTempDir();
  await seedAnchors(root, anchors);
  const fake = createFakeContext();
  const handle = createRuntimeAudit(fake.ctx, { store_dir: root, ...config });
  return { root, fake, handle, auditFile: handle.audit_log_path };
}

async function closeHarness(harness: Harness): Promise<void> {
  harness.handle.dispose();
  await cleanup(harness.root);
}

/* ------------------------------------------------------------------------- */
/* AuditLog: envelope, sequencing, tolerance.                                */
/* ------------------------------------------------------------------------- */

describe('AuditLog', () => {
  it('keeps a closed JSONL writer terminal and creates private journal files', async () => {
    const root = await makeTempDir();
    try {
      const file = join(root, 'private', 'audit.jsonl');
      const writer = new JsonlWriter({ file });
      writer.append({ record: 'before close' });
      writer.close();
      assert.equal(writer.tryAppend({ record: 'after close' }), false);
      assert.deepEqual(readJsonLines(file), [{ record: 'before close' }]);
      if (process.platform !== 'win32') {
        assert.equal(statSync(file).mode & 0o077, 0);
        assert.equal(statSync(join(root, 'private')).mode & 0o077, 0);
      }
    } finally {
      await cleanup(root);
    }
  });

  it('fills the envelope with a stable field order and injectable id/clock', async () => {
    const root = await makeTempDir();
    try {
      const file = join(root, 'audit.jsonl');
      const log = new AuditLog({
        file,
        now: fixedClock('2026-01-01T00:00:00.000Z'),
        idFactory: () => 'id-1',
      });
      try {
        const event = log.record({
          event: 'context_write',
          channel: 'inbox_insert',
          after_digest: digestJson('hello'),
        });
        assert.ok(event !== null);
        assert.equal(event.schema_version, 1);
        assert.equal(event.event, 'context_write');
        assert.equal(event.seq, 1);
        assert.equal(event.id, 'id-1');
        assert.equal(event.ts, '2026-01-01T00:00:00.000Z');

        const lines = readJsonLines(file) as Array<Record<string, unknown>>;
        assert.equal(lines.length, 1);
        assert.deepEqual(Object.keys(lines[0] ?? {}).slice(0, 5), [
          'schema_version',
          'event',
          'seq',
          'id',
          'ts',
        ]);
      } finally {
        log.close();
      }
    } finally {
      await cleanup(root);
    }
  });

  it('assigns a monotonic seq and unique ids, and stamps attribution fields', async () => {
    const root = await makeTempDir();
    try {
      const file = join(root, 'audit.jsonl');
      const log = new AuditLog({ file });
      try {
        const first = log.record(
          { event: 'context_write', channel: 'inbox_insert', after_digest: 'sha256:one' },
          { plugin_id: 'plugin-a', plugin_version: '1.2.3', session_id: 'session-1', agent_id: 'agent-1' },
        );
        const second = log.record({
          event: 'context_write',
          channel: 'inbox_insert',
          after_digest: 'sha256:two',
        });
        assert.ok(first !== null && second !== null);
        assert.deepEqual([first.seq, second.seq], [1, 2]);
        assert.equal(typeof first.id, 'string');
        assert.notEqual(first.id, second.id);
        assert.equal(first.plugin_id, 'plugin-a');
        assert.equal(first.plugin_version, '1.2.3');
        assert.equal(first.session_id, 'session-1');
        assert.equal(first.agent_id, 'agent-1');
        assert.equal(second.plugin_id, undefined);
        assert.equal(readJsonLines(file).length, 2);
      } finally {
        log.close();
      }
    } finally {
      await cleanup(root);
    }
  });

  it('falls back to a counter id when the id factory throws', async () => {
    const root = await makeTempDir();
    try {
      const log = new AuditLog({
        file: join(root, 'audit.jsonl'),
        idFactory: () => {
          throw new Error('id factory unavailable');
        },
      });
      try {
        const first = log.record({ event: 'context_write', channel: 'prompt_assembly' });
        const second = log.record({ event: 'context_write', channel: 'prompt_assembly' });
        assert.ok(first !== null && second !== null);
        assert.match(first.id, /^audit-/);
        assert.notEqual(first.id, second.id);
      } finally {
        log.close();
      }
    } finally {
      await cleanup(root);
    }
  });

  it('returns null and records lastError when the target path is a directory', async () => {
    const root = await makeTempDir();
    try {
      const target = join(root, 'audit-target');
      await mkdir(target);
      const log = new AuditLog({ file: target });
      try {
        let event: AuditEvent | null = null;
        assert.doesNotThrow(() => {
          event = log.record({ event: 'context_write', channel: 'inbox_insert' });
        });
        assert.equal(event, null);
        assert.ok(log.lastError !== undefined);
        assert.ok((log.lastError ?? '').length > 0);
      } finally {
        log.close();
      }
    } finally {
      await cleanup(root);
    }
  });

  it('reports clock failures as lastError instead of throwing', async () => {
    const root = await makeTempDir();
    try {
      const log = new AuditLog({
        file: join(root, 'audit.jsonl'),
        now: () => {
          throw new Error('clock unavailable');
        },
      });
      try {
        let event: AuditEvent | null = null;
        assert.doesNotThrow(() => {
          event = log.record({ event: 'context_write', channel: 'prompt_assembly' });
        });
        assert.equal(event, null);
        assert.match(log.lastError ?? '', /clock unavailable/);
      } finally {
        log.close();
      }
    } finally {
      await cleanup(root);
    }
  });

  it('appends pre-enveloped events verbatim and continues the seq after them', async () => {
    const root = await makeTempDir();
    try {
      const file = join(root, 'audit.jsonl');
      const log = new AuditLog({ file });
      try {
        const external: AuditEvent = {
          schema_version: 1,
          event: 'decision_recorded',
          seq: 7,
          id: 'external-7',
          ts: '2026-03-01T00:00:00.000Z',
          decision_digest: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
          action: 'confirm',
        };
        assert.doesNotThrow(() => log.append(external));
        const next = log.record({ event: 'context_write', channel: 'inbox_insert' });
        assert.ok(next !== null);
        assert.equal(next.seq, 8);
        assert.deepEqual(readEvents(file)[0], external);
      } finally {
        log.close();
      }
    } finally {
      await cleanup(root);
    }
  });
});

/* ------------------------------------------------------------------------- */
/* Runtime audit factory: metadata and scope records.                        */
/* ------------------------------------------------------------------------- */

describe('createRuntimeAudit metadata', () => {
  it('resolves store paths and exposes the anchor list', async () => {
    const harness = await openHarness([NETWORK_ANCHOR]);
    try {
      const service: RuntimeAuditService = harness.handle.service;
      assert.equal(service.store_dir, harness.root);
      assert.equal(harness.auditFile, join(harness.root, 'audit.jsonl'));
      assert.equal(harness.handle.audit_log_path, join(harness.root, 'audit.jsonl'));
      assert.equal(harness.handle.anchors_log_path, join(harness.root, 'anchors.jsonl'));
      assert.equal(service.audit_log_path, harness.auditFile);
      assert.equal(service.version, TRUST_BROKER_VERSION);
      const withPaths = service as RuntimeAuditService & { decisions_log_path: string };
      assert.equal(withPaths.decisions_log_path, join(harness.root, 'decisions.jsonl'));

      assert.equal((await service.listAnchors('plugin-a')).length, 1);
      assert.equal((await service.listAnchors()).length, 1);
      assert.equal((await service.listAnchors('plugin-ghost')).length, 0);
    } finally {
      await closeHarness(harness);
    }
  });

  it('uses the DSH_TRUST_BROKER_STORE environment default when no config is given', async () => {
    const root = await makeTempDir();
    const previous = process.env.DSH_TRUST_BROKER_STORE;
    process.env.DSH_TRUST_BROKER_STORE = root;
    try {
      const fake = createFakeContext();
      const handle = createRuntimeAudit(fake.ctx);
      try {
        assert.equal(handle.service.store_dir, root);
        assert.equal(handle.audit_log_path, join(root, 'audit.jsonl'));
      } finally {
        handle.dispose();
      }
    } finally {
      if (previous === undefined) delete process.env.DSH_TRUST_BROKER_STORE;
      else process.env.DSH_TRUST_BROKER_STORE = previous;
      await cleanup(root);
    }
  });
});

describe('tools/pre-execute audit', () => {
  it('records tool_call + scope_exceeded for a call outside the anchored surface', async () => {
    const harness = await openHarness([NETWORK_ANCHOR], {
      tool_owners: { bash: 'plugin-a', web_fetch: 'plugin-a' },
    });
    try {
      const args = { command: 'echo hi', api_key: 'super-secret-value' };
      const decision = { action: 'proceed' };
      let nextCalls = 0;
      const returned = await harness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'bash', callId: 'call-1', arguments: args, agent: { id: 'agent-7' } },
        () => {
          nextCalls += 1;
          return decision;
        },
      );
      assert.equal(nextCalls, 1);
      assert.equal(returned, decision);

      const calls = toolCalls(harness.auditFile);
      assert.equal(calls.length, 1);
      const call = calls[0];
      assert.ok(call !== undefined);
      assert.equal(call.tool, 'bash');
      assert.equal(call.call_id, 'call-1');
      // Default bash surface plus the secret-like `api_key` argument heuristic.
      assert.deepEqual(call.categories, [
        'process.child_process',
        'process.exec',
        'filesystem.read',
        'filesystem.write',
        'credentials.read',
      ]);
      assert.equal(call.scope, 'undeclared_scope');
      assert.equal(call.owner_plugin_id, 'plugin-a');
      assert.equal(call.agent_id, 'agent-7');
      assert.equal(call.session_id, undefined);
      assert.deepEqual(call.argument_keys, ['command', 'api_key']);
      assert.equal(call.arguments_digest, digestJson(redactDeep(args, DEFAULT_REDACT_KEYS)));
      assert.ok(!readFileSync(harness.auditFile, 'utf8').includes('super-secret-value'));

      const exceeded = scopeExceeded(harness.auditFile);
      assert.equal(exceeded.length, 1);
      const record = exceeded[0];
      assert.ok(record !== undefined);
      assert.equal(record.owner_plugin_id, 'plugin-a');
      assert.equal(record.call_id, 'call-1');
      assert.deepEqual(record.exceeded, [
        'process.child_process',
        'process.exec',
        'filesystem.read',
        'filesystem.write',
        'credentials.read',
      ]);
      assert.deepEqual(record.declared, ['network.fetch']);
      assert.equal(record.evidence, 'tool-call-outside-anchored-surface');
    } finally {
      await closeHarness(harness);
    }
  });

  it('records only tool_call for a call inside the anchored surface', async () => {
    const harness = await openHarness([NETWORK_ANCHOR], {
      tool_owners: { web_fetch: 'plugin-a' },
    });
    try {
      const returned = await harness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'web_fetch', callId: 'call-2', arguments: { url: 'https://example.com' } },
        () => ({ action: 'proceed' }),
      );
      assert.deepEqual(returned, { action: 'proceed' });
      const calls = toolCalls(harness.auditFile);
      assert.equal(calls.length, 1);
      assert.equal(calls[0]?.scope, 'declared');
      assert.deepEqual(calls[0]?.categories, ['network.fetch']);
      assert.equal(calls[0]?.owner_plugin_id, 'plugin-a');
      assert.equal(scopeExceeded(harness.auditFile).length, 0);
      assert.equal(readEvents(harness.auditFile).length, 1);
    } finally {
      await closeHarness(harness);
    }
  });

  it('marks calls of unowned tools as unattributed', async () => {
    const harness = await openHarness([NETWORK_ANCHOR]);
    try {
      await harness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'grep', callId: 'call-3', arguments: { pattern: 'needle' } },
        () => ({ action: 'proceed' }),
      );
      const calls = toolCalls(harness.auditFile);
      assert.equal(calls.length, 1);
      assert.equal(calls[0]?.scope, 'unattributed');
      assert.equal(calls[0]?.owner_plugin_id, undefined);
      assert.equal(scopeExceeded(harness.auditFile).length, 0);
    } finally {
      await closeHarness(harness);
    }
  });

  it('honours redact_argument_keys and classifies nested argument hints', async () => {
    const args = { command: 'run it', api_key: 'secret-value', nested: { token: 'abc' } };
    const defaultHarness = await openHarness([]);
    const customHarness = await openHarness([], { redact_argument_keys: ['command'] });
    try {
      await defaultHarness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'mystery_tool', callId: 9, arguments: args },
        () => ({ action: 'proceed' }),
      );
      await customHarness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'mystery_tool', callId: 9, arguments: args },
        () => ({ action: 'proceed' }),
      );
      const defaultCall = toolCalls(defaultHarness.auditFile)[0];
      const customCall = toolCalls(customHarness.auditFile)[0];
      assert.ok(defaultCall !== undefined && customCall !== undefined);
      assert.deepEqual(defaultCall.argument_keys, ['command', 'api_key', 'nested']);
      assert.deepEqual(defaultCall.categories, ['credentials.read']);
      assert.ok(defaultCall.arguments_digest !== customCall.arguments_digest);
      assert.equal(customCall.arguments_digest, digestJson(redactDeep(args, [...DEFAULT_REDACT_KEYS, 'command'])));
    } finally {
      await closeHarness(defaultHarness);
      await closeHarness(customHarness);
    }
  });
});

/* ------------------------------------------------------------------------- */
/* Runtime audit factory: post-execute and context writes.                   */
/* ------------------------------------------------------------------------- */

describe('tools/post-execute audit', () => {
  it('flags rewritten tool output and records the rewrite channel', async () => {
    const harness = await openHarness([NETWORK_ANCHOR]);
    try {
      const result = { isError: false, content: 'original output' };
      const rewritten = { isError: false, content: 'redacted output' };
      const replacement = { kind: 'accept', content: rewritten.content };
      let nextCalls = 0;
      const returned = await harness.fake.invokeFirst(
        'tools/post-execute',
        { name: 'bash', callId: 'call-4', agent: { id: 'agent-7' } },
        result,
        () => {
          nextCalls += 1;
          return replacement;
        },
      );
      assert.equal(nextCalls, 1);
      assert.equal(returned, replacement);

      const results = toolResults(harness.auditFile);
      assert.equal(results.length, 1);
      assert.equal(results[0]?.ok, true);
      assert.equal(results[0]?.rewritten, true);
      assert.equal(results[0]?.agent_id, 'agent-7');
      assert.equal(results[0]?.result_digest, digestJson(result));
      assert.equal(results[0]?.settled_digest, digestJson(rewritten));

      const writes = contextWrites(harness.auditFile);
      assert.equal(writes.length, 1);
      assert.equal(writes[0]?.channel, 'tool_output_rewrite');
      assert.equal(writes[0]?.agent_id, 'agent-7');
      assert.equal(writes[0]?.before_digest, digestJson(result));
      assert.equal(writes[0]?.after_digest, digestJson(rewritten));
    } finally {
      await closeHarness(harness);
    }
  });

  it('does not record a context write when the waterfall leaves the result unchanged', async () => {
    const harness = await openHarness([]);
    try {
      const result = { isError: false, content: 'unchanged output' };
      const decision = { kind: 'accept' };
      const returned = await harness.fake.invokeFirst(
        'tools/post-execute',
        { name: 'read', callId: 'call-5' },
        result,
        () => decision,
      );
      assert.equal(returned, decision);
      const results = toolResults(harness.auditFile);
      assert.equal(results.length, 1);
      assert.equal(results[0]?.rewritten, false);
      assert.equal(results[0]?.result_digest, results[0]?.settled_digest);
      assert.equal(contextWrites(harness.auditFile).length, 0);
    } finally {
      await closeHarness(harness);
    }
  });

  it('audits context attached by a post-execute decision even when content is unchanged', async () => {
    const harness = await openHarness([]);
    try {
      const decision = { kind: 'accept', additionalContexts: [{ role: 'user', content: 'injected' }] };
      const returned = await harness.fake.invokeFirst(
        'tools/post-execute',
        { name: 'read' },
        { isError: false, content: 'original' },
        () => decision,
      );
      assert.equal(returned, decision);
      assert.equal(toolResults(harness.auditFile)[0]?.rewritten, true);
      assert.equal(contextWrites(harness.auditFile)[0]?.channel, 'tool_output_rewrite');
      assert.doesNotMatch(readFileSync(harness.auditFile, 'utf8'), /injected/);
    } finally {
      await closeHarness(harness);
    }
  });

  it('marks error results with ok=false', async () => {
    const harness = await openHarness([]);
    try {
      const result = { isError: true, content: 'tool failed' };
      await harness.fake.invokeFirst(
        'tools/post-execute',
        { name: 'bash', callId: 'call-6' },
        result,
        () => result,
      );
      const results = toolResults(harness.auditFile);
      assert.equal(results.length, 1);
      assert.equal(results[0]?.ok, false);
    } finally {
      await closeHarness(harness);
    }
  });

  it('propagates dispatch errors from next() instead of swallowing them', async () => {
    const harness = await openHarness([]);
    try {
      await assert.rejects(
        harness.fake.invokeFirst(
          'tools/post-execute',
          { name: 'bash', callId: 'call-7' },
          { isError: false, content: 'x' },
          () => {
            throw new Error('dispatch failed');
          },
        ),
        /dispatch failed/,
      );
      assert.equal(readEvents(harness.auditFile).length, 0);
    } finally {
      await closeHarness(harness);
    }
  });
});

describe('context-write audit listeners', () => {
  it('records a changed system-prompt assembly and returns the new assembly', async () => {
    const harness = await openHarness([]);
    try {
      const assembly = { system: ['base prompt'], tools: [] };
      const nextAssembly = { system: ['base prompt', 'injected prompt'], tools: [] };
      const returned = await harness.fake.invokeFirst(
        'system-prompt/assemble',
        assembly,
        { session: { id: 'session-1' } },
        () => nextAssembly,
      );
      assert.equal(returned, nextAssembly);
      const writes = contextWrites(harness.auditFile);
      assert.equal(writes.length, 1);
      assert.equal(writes[0]?.channel, 'prompt_assembly');
      assert.equal(writes[0]?.before_digest, digestJson(assembly));
      assert.equal(writes[0]?.after_digest, digestJson(nextAssembly));
    } finally {
      await closeHarness(harness);
    }
  });

  it('records nothing when the system-prompt assembly is unchanged', async () => {
    const harness = await openHarness([]);
    try {
      const assembly = { system: ['base prompt'] };
      await harness.fake.invokeFirst(
        'system-prompt/assemble',
        assembly,
        {},
        () => assembly,
      );
      assert.equal(readEvents(harness.auditFile).length, 0);
    } finally {
      await closeHarness(harness);
    }
  });

  it('records inbox insertions with their source kind', async () => {
    const harness = await openHarness([]);
    try {
      await harness.fake.invokeFirst('agent/inbox/inserted', {
        agent: { id: 'agent-1' },
        message: { content: 'hello from plugin', source: { kind: 'plugin' } },
      });
      const writes = contextWrites(harness.auditFile);
      assert.equal(writes.length, 1);
      assert.equal(writes[0]?.channel, 'inbox_insert');
      assert.equal(writes[0]?.after_digest, digestJson('hello from plugin'));
      assert.equal(writes[0]?.detail, 'plugin');
      assert.equal(writes[0]?.agent_id, 'agent-1');

      await harness.fake.invokeFirst('agent/inbox/inserted', { agent: { id: 'agent-1' } });
      assert.equal(contextWrites(harness.auditFile).length, 1);
    } finally {
      await closeHarness(harness);
    }
  });

  it('records history compaction session events but not ordinary events', async () => {
    const harness = await openHarness([]);
    try {
      await harness.fake.invokeFirst(
        'session/event',
        { id: 'session-1' },
        { type: 'compaction/summary', data: { compacted_messages: 3 } },
      );
      const writes = contextWrites(harness.auditFile);
      assert.equal(writes.length, 1);
      assert.equal(writes[0]?.channel, 'history_compress');
      assert.equal(writes[0]?.detail, 'compaction/summary');
      assert.equal(writes[0]?.before_digest, digestJson({ compacted_messages: 3 }));
      assert.equal(writes[0]?.session_id, 'session-1');

      await harness.fake.invokeFirst('session/event', { id: 'session-1' }, { type: 'message', data: {} });
      assert.equal(contextWrites(harness.auditFile).length, 1);
    } finally {
      await closeHarness(harness);
    }
  });

  it('context_audit:false suppresses inbox and compaction writes but keeps dispatch records', async () => {
    const harness = await openHarness([NETWORK_ANCHOR], { context_audit: false });
    try {
      const result = { isError: false, content: 'original' };
      await harness.fake.invokeFirst(
        'tools/post-execute',
        { name: 'bash', callId: 'call-8' },
        result,
        () => ({ isError: false, content: 'rewritten' }),
      );
      await harness.fake.invokeFirst(
        'system-prompt/assemble',
        { system: ['a'] },
        {},
        () => ({ system: ['a', 'b'] }),
      );
      await harness.fake.invokeFirst('agent/inbox/inserted', {
        agent: { id: 'agent-1' },
        message: { content: 'suppressed' },
      });
      await harness.fake.invokeFirst('session/event', { id: 's' }, { type: 'compaction/full', data: {} });

      assert.equal(toolResults(harness.auditFile).length, 1);
      const channels = contextWrites(harness.auditFile).map((write) => write.channel);
      assert.deepEqual(channels, ['tool_output_rewrite', 'prompt_assembly']);
    } finally {
      await closeHarness(harness);
    }
  });
});

/* ------------------------------------------------------------------------- */
/* Runtime audit factory: resilience and mutable state.                      */
/* ------------------------------------------------------------------------- */

describe('createRuntimeAudit resilience', () => {
  it('omits thrown payload text from warnings and keeps the downstream decision', async () => {
    const harness = await openHarness([]);
    try {
      const result = {
        isError: false,
        get content(): never {
          throw new Error('SYNTHETIC_AUDIT_TOKEN');
        },
      };
      const verdict = { kind: 'accept' };
      const returned = await harness.fake.invokeFirst(
        'tools/post-execute', { name: 'read' }, result, () => verdict,
      );
      assert.equal(returned, verdict);
      assert.ok(harness.fake.logs.some((entry) => entry.level === 'warn'));
      assert.doesNotMatch(JSON.stringify(harness.fake.logs), /SYNTHETIC_AUDIT_TOKEN/);
    } finally {
      await closeHarness(harness);
    }
  });

  it('passes through waterfalls without opening the journal after disposal', async () => {
    const harness = await openHarness([]);
    try {
      const result = { isError: false, content: 'original' };
      const settled = { kind: 'accept', content: 'updated' };
      const nextAssembly = { system: 'new' };
      let release!: () => void;
      const ready = new Promise<void>((resolve) => { release = resolve; });
      const post = harness.fake.invokeFirst(
        'tools/post-execute', { name: 'read' }, result, () => ready.then(() => settled),
      );
      const assembly = harness.fake.invokeFirst(
        'system-prompt/assemble', { system: 'old' }, {}, () => ready.then(() => nextAssembly),
      );

      harness.handle.dispose();
      release();
      assert.equal(await post, settled);
      assert.equal(await assembly, nextAssembly);
      assert.equal(existsSync(harness.auditFile), false);
    } finally {
      await closeHarness(harness);
    }
  });

  it('skips malformed anchor lines, keeps valid ones, and logs warnings', async () => {
    const root = await makeTempDir();
    try {
      const valid = JSON.stringify(NETWORK_ANCHOR);
      const missingPluginId = JSON.stringify({
        schema_version: 1,
        version: '1.0.0',
        confirmed_at: '2026-01-01T00:00:00.000Z',
        capability_keys: [],
      });
      await writeFile(
        join(root, 'anchors.jsonl'),
        `${[valid, '{not-json', missingPluginId].join('\n')}\n`,
        'utf8',
      );
      const fake = createFakeContext();
      const handle = createRuntimeAudit(fake.ctx, {
        store_dir: root,
        tool_owners: { web_fetch: 'plugin-a' },
      });
      try {
        assert.ok(fake.logs.filter((entry) => entry.level === 'warn').length >= 2);
        assert.equal((await handle.service.listAnchors('plugin-a')).length, 1);
        await fake.invokeFirst(
          'tools/pre-execute',
          { name: 'web_fetch', callId: 10, arguments: { url: 'https://example.com' } },
          () => ({ action: 'proceed' }),
        );
        const calls = toolCalls(handle.audit_log_path);
        assert.equal(calls.length, 1);
        assert.equal(calls[0]?.scope, 'declared');
      } finally {
        handle.dispose();
      }
    } finally {
      await cleanup(root);
    }
  });

  it('does not throw into dispatch when the store directory is a regular file', async () => {
    const root = await makeTempDir();
    try {
      const storeTarget = join(root, 'store-is-a-file');
      await writeFile(storeTarget, 'not a directory', 'utf8');
      const fake = createFakeContext();
      let handle: RuntimeAuditHandle | undefined;
      assert.doesNotThrow(() => {
        handle = createRuntimeAudit(fake.ctx, {
          store_dir: storeTarget,
          tool_owners: { bash: 'plugin-a' },
        });
      });
      assert.ok(handle !== undefined);
      const audit = handle as RuntimeAuditHandle;
      try {
        assert.equal(audit.audit_log_path, join(storeTarget, 'audit.jsonl'));
        const decision = { action: 'proceed' };
        let nextCalls = 0;
        const returned = await fake.invokeFirst(
          'tools/pre-execute',
          { name: 'bash', callId: 11, arguments: { command: 'echo hi' } },
          () => {
            nextCalls += 1;
            return decision;
          },
        );
        assert.equal(nextCalls, 1);
        assert.equal(returned, decision);
        assert.ok(fake.logs.some((entry) => entry.level === 'warn'));
        assert.equal(toolCalls(audit.audit_log_path).length, 0);
      } finally {
        audit.dispose();
      }
    } finally {
      await cleanup(root);
    }
  });

  it('reloadAnchors re-reads the journal so later scope checks see new anchors', async () => {
    const harness = await openHarness([NETWORK_ANCHOR], { tool_owners: { bash: 'plugin-a' } });
    try {
      await harness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'bash', callId: 'call-12', arguments: { command: 'echo hi' } },
        () => ({ action: 'proceed' }),
      );
      assert.equal(scopeExceeded(harness.auditFile).length, 1);

      await appendFile(
        join(harness.root, 'anchors.jsonl'),
        `${JSON.stringify(expandedAnchor())}\n`,
        'utf8',
      );
      await harness.handle.reloadAnchors();
      assert.equal((await harness.handle.service.listAnchors('plugin-a')).length, 2);

      await harness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'bash', callId: 'call-13', arguments: { command: 'echo hi' } },
        () => ({ action: 'proceed' }),
      );
      const calls = toolCalls(harness.auditFile);
      assert.equal(calls.length, 2);
      assert.equal(calls[0]?.scope, 'undeclared_scope');
      assert.equal(calls[1]?.scope, 'declared');
      assert.equal(scopeExceeded(harness.auditFile).length, 1);
    } finally {
      await closeHarness(harness);
    }
  });

  it('setToolOwner updates scope checks through subsequent tool calls', async () => {
    const harness = await openHarness([NETWORK_ANCHOR]);
    try {
      await harness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'bash', callId: 'call-14', arguments: { command: 'echo hi' } },
        () => ({ action: 'proceed' }),
      );
      assert.equal(toolCalls(harness.auditFile)[0]?.scope, 'unattributed');

      harness.handle.setToolOwner('bash', 'plugin-a');
      await harness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'bash', callId: 'call-15', arguments: { command: 'echo hi' } },
        () => ({ action: 'proceed' }),
      );
      assert.equal(toolCalls(harness.auditFile)[1]?.scope, 'undeclared_scope');
      assert.equal(scopeExceeded(harness.auditFile).length, 1);

      harness.handle.service.setToolOwner('web_fetch', 'plugin-a');
      await harness.fake.invokeFirst(
        'tools/pre-execute',
        { name: 'web_fetch', callId: 'call-16', arguments: { url: 'https://example.com' } },
        () => ({ action: 'proceed' }),
      );
      assert.equal(toolCalls(harness.auditFile)[2]?.scope, 'declared');
    } finally {
      await closeHarness(harness);
    }
  });

  it('service.record appends envelope-complete events and envelops draft-shaped ones', async () => {
    const harness = await openHarness([]);
    try {
      const external: AuditEvent = {
        schema_version: 1,
        event: 'decision_recorded',
        seq: 5,
        id: 'external-5',
        ts: '2026-04-01T00:00:00.000Z',
        decision_digest: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        action: 'proceed',
      };
      harness.handle.service.record(external);
      harness.handle.service.record({
        event: 'anchor_created',
        anchor: NETWORK_ANCHOR,
      } as unknown as AuditEvent);

      const events = readEvents(harness.auditFile);
      assert.equal(events.length, 2);
      assert.deepEqual(events[0], external);
      const normalized = events[1];
      assert.equal(normalized?.event, 'anchor_created');
      assert.equal(normalized?.schema_version, 1);
      assert.equal(typeof normalized?.seq, 'number');
      assert.equal(typeof normalized?.id, 'string');
      assert.equal(typeof normalized?.ts, 'string');
    } finally {
      await closeHarness(harness);
    }
  });

  it('keeps raw service error text, unknown fields and anchor notes out of the audit journal', async () => {
    const harness = await openHarness([]);
    const marker = 'SYNTHETIC_AUDIT_TOKEN';
    try {
      const draft = { event: 'audit_error' as const, operation: 'loader', message: marker, token: marker };
      harness.handle.service.record(draft);
      harness.handle.service.record({
        event: 'anchor_created',
        anchor: { ...NETWORK_ANCHOR, notes: marker },
      });
      assert.doesNotMatch(readFileSync(harness.auditFile, 'utf8'), /SYNTHETIC_AUDIT_TOKEN/);
      const [error, anchored] = readEvents(harness.auditFile);
      assert.equal(error?.event === 'audit_error' ? error.message : undefined, digestJson(marker));
      assert.equal(anchored?.event, 'anchor_created');
    } finally {
      await closeHarness(harness);
    }
  });
});
