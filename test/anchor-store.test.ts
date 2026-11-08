/**
 * Tests for the append-only trust-anchor store: anchor construction, append-only
 * journal growth, lookups, and fail-visible handling of malformed lines.
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { chmod, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  ANCHOR_STORE_FILENAME,
  AnchorStore,
  anchorStorePath,
  buildTrustAnchor,
  isTrustAnchor,
} from '../src/core/anchor-store.ts';
import type { BuildAnchorInput } from '../src/core/anchor-store.ts';
import { sha256Hex } from '../src/core/fs-utils.ts';
import type { CapabilityKey, DeclaredCapabilities, TrustAnchor } from '../src/types.ts';
import { cleanup, makeTempDir, readJsonLines } from './helpers.ts';

/** Deterministic anchor hash for a seed string. */
function contentHash(seed: string): string {
  return `sha256:${sha256Hex(seed)}`;
}

/** Build one valid anchor input; override any field. */
function buildInput(overrides: Partial<BuildAnchorInput> = {}): BuildAnchorInput {
  return {
    plugin_id: 'plugin-a',
    version: '1.0.0',
    content_hash: contentHash('plugin-a@1.0.0'),
    declared_capabilities: { network: { fetch: true } },
    capability_keys: ['network.fetch'],
    declaration_status: 'declared',
    scanner: { name: 'dsh-trust-check', version: '2.1.0', heuristic: false },
    decision_digest: contentHash('decision:plugin-a@1.0.0'),
    confirmed_by: 'user',
    confirmed_at: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

/** Build a valid anchor with convenient defaults. */
function makeAnchor(version = '1.0.0', overrides: Partial<BuildAnchorInput> = {}): TrustAnchor {
  return buildTrustAnchor(
    buildInput({
      version,
      content_hash: contentHash(`plugin-a@${version}`),
      ...overrides,
    }),
  );
}

test('anchorStorePath points at anchors.jsonl inside the store directory', () => {
  assert.equal(ANCHOR_STORE_FILENAME, 'anchors.jsonl');
  assert.equal(anchorStorePath('/tmp/store'), join('/tmp/store', 'anchors.jsonl'));
  assert.equal(anchorStorePath('/tmp/store').endsWith('anchors.jsonl'), true);
});

test('buildTrustAnchor copies inputs and defaults the timestamp', () => {
  const capabilityKeys: CapabilityKey[] = ['network.fetch'];
  const declared: DeclaredCapabilities = { network: { fetch: true } };
  const anchor = buildTrustAnchor(
    buildInput({ capability_keys: capabilityKeys, declared_capabilities: declared }),
  );

  assert.equal(anchor.schema_version, 1);
  assert.equal(anchor.confirmed_at, '2026-01-01T00:00:00.000Z');
  assert.equal(anchor.confirmed_by, 'user');
  assert.deepEqual(anchor.capability_keys, ['network.fetch']);
  assert.equal(isTrustAnchor(anchor), true);

  // The anchor must not alias caller-owned mutable state.
  capabilityKeys.push('process.exec');
  if (declared.network !== undefined) declared.network.fetch = false;
  assert.deepEqual(anchor.capability_keys, ['network.fetch']);
  assert.equal(anchor.declared_capabilities.network?.fetch, true);

  const withoutNotes = makeAnchor('1.0.1', { notes: undefined });
  assert.equal('notes' in withoutNotes, false);
  const withNotes = makeAnchor('1.0.2', { notes: 'approved by user' });
  assert.equal(withNotes.notes, 'approved by user');

  const before = Date.now();
  const defaulted = buildTrustAnchor(buildInput({ confirmed_at: undefined }));
  const parsed = Date.parse(defaulted.confirmed_at);
  assert.equal(Number.isNaN(parsed), false);
  assert.ok(Math.abs(parsed - before) < 60_000);

  const policyAnchor = makeAnchor('1.0.3', { confirmed_by: 'policy' });
  assert.equal(policyAnchor.confirmed_by, 'policy');
});

test('buildTrustAnchor rejects invalid anchors instead of persisting them', () => {
  assert.throws(
    () => buildTrustAnchor(buildInput({ content_hash: 'md5:deadbeef' })),
    TypeError,
  );
  assert.throws(() => buildTrustAnchor(buildInput({ content_hash: 'sha256:short' })), TypeError);
  assert.throws(() => buildTrustAnchor(buildInput({ decision_digest: 'sha256:short' })), TypeError);
  assert.throws(() => buildTrustAnchor(buildInput({ plugin_id: '' })), TypeError);
  assert.throws(() => buildTrustAnchor(buildInput({ confirmed_at: 'not-a-date' })), TypeError);
  assert.throws(
    () => buildTrustAnchor(buildInput({ confirmed_by: 'admin' as unknown as 'user' })),
    TypeError,
  );

  const valid = makeAnchor();
  assert.equal(isTrustAnchor(JSON.parse(JSON.stringify(valid))), true);
  assert.equal(isTrustAnchor(null), false);
  assert.equal(isTrustAnchor({}), false);
  assert.equal(isTrustAnchor({ ...valid, confirmed_by: 'admin' }), false);
  assert.equal(isTrustAnchor({ ...valid, content_hash: 'sha256:short' }), false);
  assert.equal(isTrustAnchor({ ...valid, decision_digest: 'sha256:short' }), false);
  assert.equal(
    isTrustAnchor({ ...valid, content_hash: `sha256:${'A'.repeat(64)}` }),
    false,
  );
});

test('record appends, list grows in file order, and plugin filtering works', async () => {
  const dir = await makeTempDir('trust-anchor-list-');
  const store = new AnchorStore({ file: anchorStorePath(dir) });
  try {
    assert.equal(store.file, join(dir, 'anchors.jsonl'));
    await store.record(makeAnchor('1.0.0'));
    await store.record(makeAnchor('1.1.0', { plugin_id: 'plugin-b' }));
    await store.record(makeAnchor('1.2.0'));

    const all = await store.list();
    assert.equal(all.length, 3);
    assert.deepEqual(all.map((anchor) => anchor.version), ['1.0.0', '1.1.0', '1.2.0']);
    const onlyA = await store.list('plugin-a');
    assert.equal(onlyA.length, 2);
    assert.deepEqual(onlyA.map((anchor) => anchor.version), ['1.0.0', '1.2.0']);
    assert.deepEqual(await store.list('plugin-missing'), []);
    assert.equal(readJsonLines(store.file).length, 3);
  } finally {
    await cleanup(dir);
  }
});

test('record is append-only: the previous bytes are a byte-identical prefix', async () => {
  const dir = await makeTempDir('trust-anchor-append-');
  const store = new AnchorStore({ file: anchorStorePath(dir), fsync: true });
  try {
    const first = makeAnchor('1.0.0');
    await store.record(first);
    const before = readFileSync(store.file);
    assert.equal(readJsonLines(store.file).length, 1);
    assert.ok(before.length > 0);

    const second = makeAnchor('1.1.0');
    await store.record(second);
    const after = readFileSync(store.file);
    assert.equal(readJsonLines(store.file).length, 2);
    assert.ok(after.length > before.length);
    assert.deepEqual(after.subarray(0, before.length), before);
    assert.equal(after.subarray(before.length).toString('utf8').endsWith('\n'), true);
    // The appended tail parses back to exactly the new anchor.
    assert.deepEqual(
      JSON.parse(after.subarray(before.length).toString('utf8').trimEnd()),
      second,
    );
  } finally {
    await cleanup(dir);
  }
});

test('latest picks the newest confirmed_at and breaks ties by later line', async () => {
  const dir = await makeTempDir('trust-anchor-latest-');
  const store = new AnchorStore({ file: anchorStorePath(dir) });
  try {
    await store.record(makeAnchor('2.0.0', { confirmed_at: '2026-03-01T00:00:00.000Z' }));
    await store.record(makeAnchor('1.0.0', { confirmed_at: '2026-01-01T00:00:00.000Z' }));
    await store.record(makeAnchor('3.0.0', { confirmed_at: '2026-05-01T00:00:00.000Z' }));
    assert.equal((await store.latest('plugin-a'))?.version, '3.0.0');
    assert.equal(await store.latest('plugin-missing'), undefined);

    // Equal timestamps: the later JSONL line wins.
    await store.record(makeAnchor('9.0.0', { confirmed_at: '2026-06-01T00:00:00.000Z' }));
    await store.record(makeAnchor('10.0.0', { confirmed_at: '2026-06-01T00:00:00.000Z' }));
    assert.equal((await store.latest('plugin-a'))?.version, '10.0.0');
  } finally {
    await cleanup(dir);
  }
});

test('findMatch returns the anchor for a content hash and isolates plugins', async () => {
  const dir = await makeTempDir('trust-anchor-match-');
  const store = new AnchorStore({ file: anchorStorePath(dir) });
  const hashOne = contentHash('one');
  const hashTwo = contentHash('two');
  try {
    await store.record(makeAnchor('1.0.0', { content_hash: hashOne }));
    await store.record(makeAnchor('2.0.0', { content_hash: hashTwo }));
    assert.equal((await store.findMatch('plugin-a', hashOne))?.version, '1.0.0');
    assert.equal((await store.findMatch('plugin-a', hashTwo))?.version, '2.0.0');
    assert.equal(await store.findMatch('plugin-a', contentHash('unknown')), undefined);
    assert.equal(await store.findMatch('plugin-b', hashOne), undefined);

    // Duplicate hash: the latest matching anchor is returned.
    await store.record(
      makeAnchor('3.0.0', {
        content_hash: hashOne,
        confirmed_at: '2027-01-01T00:00:00.000Z',
      }),
    );
    assert.equal((await store.findMatch('plugin-a', hashOne))?.version, '3.0.0');
  } finally {
    await cleanup(dir);
  }
});

test('snapshot reports malformed and invalid lines but keeps other anchors usable', async () => {
  const dir = await makeTempDir('trust-anchor-snapshot-');
  const file = anchorStorePath(dir);
  const store = new AnchorStore({ file });
  try {
    // Line 1 valid, line 2 torn JSON, line 3 valid, line 4 JSON that is not an anchor.
    const validOne = makeAnchor('1.0.0');
    const validTwo = makeAnchor('1.1.0');
    await writeFile(
      file,
      [
        JSON.stringify(validOne),
        '{"plugin_id": "torn"',
        JSON.stringify(validTwo),
        JSON.stringify({ plugin_id: 'plugin-a', version: '9.9.9' }),
        '{"plugin_id": "plugin-a", "version": "9.9.10", "content_hash": "md5:bad"}',
      ].join('\n') + '\n',
    );

    const snapshot = await store.snapshot();
    assert.equal(snapshot.file, file);
    assert.equal(snapshot.anchors.length, 2);
    assert.deepEqual(snapshot.anchors.map((anchor) => anchor.version), ['1.0.0', '1.1.0']);
    assert.equal(snapshot.errors.length, 3);
    assert.equal(snapshot.errors[0]?.line, 2);
    assert.equal(snapshot.errors[1]?.line, 4);
    assert.equal(snapshot.errors[2]?.line, 5);
    assert.equal(
      snapshot.errors.some((error) => error.message.includes('invalid anchor record')),
      true,
    );

    // Lookup helpers skip bad lines instead of hiding the valid ones.
    const listed = await store.list('plugin-a');
    assert.equal(listed.length, 2);
    assert.equal((await store.latest('plugin-a'))?.version, '1.1.0');
    assert.equal((await store.findMatch('plugin-a', contentHash('plugin-a@1.0.0')))?.version, '1.0.0');
  } finally {
    await cleanup(dir);
  }
});

test('a missing journal is an empty store and an invalid record is refused', async () => {
  const dir = await makeTempDir('trust-anchor-empty-');
  const file = anchorStorePath(dir);
  const store = new AnchorStore({ file, fsync: false });
  try {
    assert.deepEqual(await store.list(), []);
    assert.equal(await store.latest('plugin-a'), undefined);
    assert.equal(await store.findMatch('plugin-a', contentHash('x')), undefined);
    assert.deepEqual(await store.snapshot(), { anchors: [], errors: [], file });

    const invalid = { ...makeAnchor(), content_hash: 'md5:oops' } as unknown as TrustAnchor;
    await assert.rejects(store.record(invalid), TypeError);
    assert.equal(existsSync(file), false);
  } finally {
    await cleanup(dir);
  }
});

test('an unreadable journal is reported by snapshot rather than crashing', async (t) => {
  if (process.platform === 'win32') {
    t.skip('chmod semantics differ on Windows');
    return;
  }
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    t.skip('running as root: chmod 000 does not block reads');
    return;
  }
  const dir = await makeTempDir('trust-anchor-unreadable-');
  const file = anchorStorePath(dir);
  const store = new AnchorStore({ file });
  try {
    await store.record(makeAnchor('1.0.0'));
    await chmod(file, 0o000);
    const snapshot = await store.snapshot();
    assert.deepEqual(snapshot.anchors, []);
    assert.equal(snapshot.errors.length >= 1, true);
    assert.equal(snapshot.errors[0]?.line, 0);
    assert.deepEqual(await store.list(), []);
  } finally {
    await chmod(file, 0o600).catch(() => undefined);
    await cleanup(dir);
  }
});

test('snapshot line numbers survive blank lines and a torn final line', async () => {
  const dir = await makeTempDir('trust-anchor-torn-');
  const file = anchorStorePath(dir);
  const store = new AnchorStore({ file });
  try {
    const anchor = makeAnchor('1.0.0');
    await writeFile(file, `${JSON.stringify(anchor)}\n\n{"torn": tr`);
    const snapshot = await store.snapshot();
    assert.equal(snapshot.anchors.length, 1);
    assert.equal(snapshot.errors.length, 1);
    assert.equal(snapshot.errors[0]?.line, 3);
    assert.equal((await store.latest('plugin-a'))?.version, '1.0.0');
  } finally {
    await cleanup(dir);
  }
});
