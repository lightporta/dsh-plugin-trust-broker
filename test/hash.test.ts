/**
 * Tests for the canonical content hash. The checks pin the security properties:
 * determinism, path binding, symlink non-following, exclusion handling and
 * fail-closed behaviour under read errors and resource limits.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, link, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  CONTENT_HASH_DOMAIN,
  DEFAULT_HASH_EXCLUDES,
  DEFAULT_HASH_MAX_FILES,
  DEFAULT_HASH_MAX_TOTAL_BYTES,
  SYMLINK_HASH_DOMAIN,
  computeContentHash,
  sha256File,
} from '../src/core/hash.ts';
import { sha256Hex } from '../src/core/fs-utils.ts';
import { cleanup, makeTempDir, writeTree } from './helpers.ts';

/** Build the expected aggregate for a list of entries, independent of the implementation. */
function expectedAggregate(entries: Array<{ path: string; sha256: string }>): string {
  const sorted = [...entries].sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
  const manifest = sorted.map((entry) => `${JSON.stringify(['file', entry.sha256, entry.path])}\n`).join('');
  return `sha256:${sha256Hex(`${CONTENT_HASH_DOMAIN}\n${manifest}`)}`;
}

/** Sorted relative paths of a hash result. */
function pathsOf(result: Awaited<ReturnType<typeof computeContentHash>>): string[] {
  return result.files.map((file) => file.path);
}

test('empty root hashes the canonical empty manifest', async () => {
  const root = await makeTempDir('trust-hash-empty-');
  try {
    const result = await computeContentHash(root);
    assert.equal(result.algorithm, 'sha256');
    assert.equal(result.complete, true);
    assert.equal(result.hash, `sha256:${sha256Hex(`${CONTENT_HASH_DOMAIN}\n`)}`);
    assert.equal(result.hash, expectedAggregate([]));
    assert.equal(result.file_count, 0);
    assert.equal(result.byte_count, 0);
    assert.deepEqual(result.files, []);
    assert.deepEqual(result.errors, []);
    assert.deepEqual(result.excluded, []);
  } finally {
    await cleanup(root);
  }
});

test('the same tree always hashes identically regardless of write order', async () => {
  const firstRoot = await makeTempDir('trust-hash-order-a-');
  const secondRoot = await makeTempDir('trust-hash-order-b-');
  const files: Record<string, string> = {
    'package.json': '{"name":"fixture","version":"1.0.0"}\n',
    'src/index.ts': 'export const answer = 42;\n',
    'src/lib/util.ts': 'export const util = true;\n',
  };
  try {
    await writeTree(firstRoot, files);
    // Same content, opposite object/write order.
    await writeTree(secondRoot, {
      'src/lib/util.ts': files['src/lib/util.ts'] ?? '',
      'src/index.ts': files['src/index.ts'] ?? '',
      'package.json': files['package.json'] ?? '',
    });
    const first = await computeContentHash(firstRoot);
    const again = await computeContentHash(firstRoot);
    const second = await computeContentHash(secondRoot);

    assert.equal(first.complete, true);
    assert.equal(second.complete, true);
    assert.equal(first.hash, again.hash);
    assert.equal(first.hash, second.hash);
    assert.deepEqual(first.files, second.files);
    assert.equal(first.file_count, 3);
    assert.deepEqual(pathsOf(first), ['package.json', 'src/index.ts', 'src/lib/util.ts']);
    assert.equal(
      first.files.find((file) => file.path === 'src/index.ts')?.sha256,
      sha256Hex('export const answer = 42;\n'),
    );
    assert.equal(first.byte_count, Buffer.byteLength(Object.values(files).join('')));
  } finally {
    await cleanup(firstRoot);
    await cleanup(secondRoot);
  }
});

test('adding, modifying or renaming a file changes the hash', async () => {
  const root = await makeTempDir('trust-hash-mutations-');
  try {
    await writeTree(root, { 'a.txt': 'alpha', 'b.txt': 'bravo' });
    const baseline = await computeContentHash(root);

    await writeTree(root, { 'c.txt': 'charlie' });
    const added = await computeContentHash(root);
    assert.equal(added.hash !== baseline.hash, true);

    await rm(join(root, 'c.txt'));
    const restored = await computeContentHash(root);
    assert.equal(restored.hash, baseline.hash);

    await writeTree(root, { 'a.txt': 'alpha-2' });
    const modified = await computeContentHash(root);
    assert.equal(modified.hash !== baseline.hash, true);

    await writeTree(root, { 'a.txt': 'alpha' });
    await rm(join(root, 'b.txt'));
    await writeTree(root, { 'renamed.txt': 'bravo' });
    const renamed = await computeContentHash(root);
    assert.equal(renamed.hash !== baseline.hash, true);
    assert.deepEqual(pathsOf(renamed), ['a.txt', 'renamed.txt']);
    assert.equal(
      renamed.files.find((file) => file.path === 'renamed.txt')?.sha256,
      sha256Hex('bravo'),
    );
  } finally {
    await cleanup(root);
  }
});

test('a newline in a filename cannot manufacture an identical artifact hash', {
  skip: process.platform === 'win32',
}, async () => {
  const first = await makeTempDir('trust-hash-framed-a-');
  const second = await makeTempDir('trust-hash-framed-b-');
  try {
    const payload = 'fetch("https://example.invalid");';
    await writeTree(first, { [`x.txt\n${sha256Hex(payload)}  z.js`]: 'safe' });
    await writeTree(second, { 'x.txt': 'safe', 'z.js': payload });
    const left = await computeContentHash(first, { strict: true });
    const right = await computeContentHash(second, { strict: true });
    assert.ok(left.complete && right.complete);
    assert.notEqual(left.hash, right.hash);
  } finally {
    await cleanup(first);
    await cleanup(second);
  }
});

test('an admission snapshot contains the exact hashed bytes, including normally excluded code', async () => {
  const root = await makeTempDir('trust-hash-snapshot-source-');
  const snapshot = await makeTempDir('trust-hash-snapshot-dest-');
  try {
    const bytes = Buffer.alloc(150_000, 0x61);
    bytes.fill(0x62, 64_000, 130_000);
    await writeTree(root, { 'node_modules/fake/index.js': bytes });
    const result = await computeContentHash(root, { strict: true, snapshotDir: snapshot });
    assert.equal(result.complete, true);
    assert.deepEqual(result.excluded, []);
    assert.deepEqual(await readFile(join(snapshot, 'node_modules/fake/index.js')), bytes);
    assert.equal((await computeContentHash(snapshot, { strict: true })).hash, result.hash);
  } finally {
    await cleanup(root);
    await cleanup(snapshot);
  }
});

test('admission hashes refuse hardlinks, symbolic links, and FIFOs', {
  skip: process.platform === 'win32',
}, async () => {
  const root = await makeTempDir('trust-hash-links-root-');
  const outside = await makeTempDir('trust-hash-links-outside-');
  const entry = join(root, 'entry.js');
  try {
    const target = join(outside, 'target.js');
    await writeFile(target, 'const external = true;');
    await link(target, entry);
    assert.equal((await computeContentHash(root, { strict: true })).hash, null);
    await rm(entry);
    await symlink(target, entry);
    assert.equal((await computeContentHash(root, { strict: true })).errors[0]?.code, 'unsafe_link');
    await rm(entry);
    execFileSync('mkfifo', [entry]);
    assert.equal((await computeContentHash(root, { strict: true })).errors[0]?.code, 'unsupported_entry');
  } finally {
    await cleanup(root);
    await cleanup(outside);
  }
});

test('default excludes are skipped and reported, custom excludes replace them', async () => {
  const base = await makeTempDir('trust-hash-excludes-');
  const defaultRoot = join(base, 'defaults');
  const customRoot = join(base, 'custom');
  const everythingRoot = join(base, 'everything');
  const nestedRoot = join(base, 'nested');
  try {
    await writeTree(defaultRoot, {
      '.git/HEAD': 'ref: refs/heads/main\n',
      'node_modules/pkg/index.js': 'module.exports = {};\n',
      '.DS_Store': 'junk',
      'index.js': 'export {};\n',
    });
    const result = await computeContentHash(defaultRoot);
    assert.equal(result.complete, true);
    assert.deepEqual(pathsOf(result), ['index.js']);
    assert.deepEqual(
      result.excluded.map((entry) => entry.path),
      ['.DS_Store', '.git', 'node_modules'],
    );
    assert.equal(result.excluded.every((entry) => entry.reason === 'excluded'), true);
    assert.deepEqual(DEFAULT_HASH_EXCLUDES, ['.git', 'node_modules', '.DS_Store']);
    assert.equal(result.hash, expectedAggregate([
      { path: 'index.js', sha256: sha256Hex('export {};\n') },
    ]));

    // Explicit excludes replace the defaults: .git is now hashed, custom is not.
    await writeTree(customRoot, {
      '.git/HEAD': 'ref: refs/heads/main\n',
      'custom/b.txt': 'b',
      'index.js': 'export {};\n',
    });
    const custom = await computeContentHash(customRoot, { excludes: ['custom'] });
    assert.equal(custom.complete, true);
    assert.deepEqual(pathsOf(custom), ['.git/HEAD', 'index.js']);
    assert.deepEqual(custom.excluded.map((entry) => entry.path), ['custom']);

    // An empty exclusion list hashes everything.
    await writeTree(everythingRoot, { '.git/HEAD': 'x', 'a.txt': 'a' });
    const everything = await computeContentHash(everythingRoot, { excludes: [] });
    assert.deepEqual(pathsOf(everything), ['.git/HEAD', 'a.txt']);

    // Multi-segment exclusions match a relative subtree.
    await writeTree(nestedRoot, { 'dist/cache/a.bin': 'x', 'dist/index.js': 'y' });
    const nested = await computeContentHash(nestedRoot, { excludes: ['dist/cache'] });
    assert.deepEqual(pathsOf(nested), ['dist/index.js']);
    assert.deepEqual(nested.excluded.map((entry) => entry.path), ['dist/cache']);
  } finally {
    await cleanup(base);
  }
});

test('symlinks are hashed by target and never followed outside the root', async (t) => {
  const root = await makeTempDir('trust-hash-symlink-root-');
  const outside = await makeTempDir('trust-hash-symlink-outside-');
  const outsideFile = join(outside, 'secret.txt');
  const outsideDir = join(outside, 'nested');
  const fileLink = join(root, 'link.txt');
  const dirLink = join(root, 'dirlink');
  try {
    await writeTree(outside, { 'secret.txt': 'outside-secret', 'nested/inner.txt': 'inner' });
    await writeTree(root, { 'index.js': 'export {};\n' });
    try {
      await symlink(outsideFile, fileLink);
      await symlink(outsideDir, dirLink);
    } catch {
      t.skip('symlinks are not supported in this environment');
      return;
    }

    const result = await computeContentHash(root);
    assert.equal(result.complete, true);
    assert.equal(result.hash !== null, true);
    const linkEntry = result.files.find((file) => file.path === 'link.txt');
    assert.ok(linkEntry);
    assert.equal(linkEntry.kind, 'symlink');
    assert.equal(linkEntry.link_target, outsideFile);
    assert.equal(linkEntry.sha256, sha256Hex(`${SYMLINK_HASH_DOMAIN}${outsideFile}`));
    assert.notEqual(linkEntry.sha256, sha256Hex('outside-secret'));
    assert.notEqual(linkEntry.sha256, sha256Hex(outsideFile));

    const dirEntry = result.files.find((file) => file.path === 'dirlink');
    assert.ok(dirEntry);
    assert.equal(dirEntry.kind, 'symlink');
    assert.equal(result.files.some((file) => file.path.includes('inner')), false);

    // Changing the target's bytes must not change the hash of the tree.
    await writeFile(outsideFile, 'changed-outside-secret');
    const after = await computeContentHash(root);
    assert.equal(after.hash, result.hash);

    // A dangling symlink is hashed by its raw target string, not followed.
    const danglingTarget = join(outside, 'missing.txt');
    await symlink(danglingTarget, join(root, 'dangling.txt'));
    const withDangling = await computeContentHash(root);
    assert.equal(withDangling.complete, true);
    assert.equal(
      withDangling.files.find((file) => file.path === 'dangling.txt')?.sha256,
      sha256Hex(`${SYMLINK_HASH_DOMAIN}${danglingTarget}`),
    );
  } finally {
    await cleanup(root);
    await cleanup(outside);
  }
});

test('unreadable files fail closed with no partial hash', async (t) => {
  if (process.platform === 'win32') {
    t.skip('chmod semantics differ on Windows');
    return;
  }
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    t.skip('running as root: chmod 000 does not block reads');
    return;
  }
  const root = await makeTempDir('trust-hash-locked-');
  const locked = join(root, 'locked.txt');
  try {
    await writeTree(root, { 'locked.txt': 'cannot read me', 'visible.txt': 'ok' });
    await chmod(locked, 0o000);
    const result = await computeContentHash(root);
    assert.equal(result.hash, null);
    assert.equal(result.complete, false);
    assert.ok(result.errors.length >= 1);
    assert.equal(result.errors.some((error) => error.path === 'locked.txt'), true);
    assert.equal(pathsOf(result).includes('locked.txt'), false);
    // The walk stops at the first failure, so the hash can never cover a
    // partially inspected tree; later entries are not collected either.
    assert.equal(pathsOf(result).includes('visible.txt'), false);
    assert.ok((result.errors[0]?.code ?? '').length > 0);
  } finally {
    await chmod(locked, 0o600).catch(() => undefined);
    await cleanup(root);
  }
});

test('file-count and byte limits fail closed with hash_limit', async () => {
  const root = await makeTempDir('trust-hash-limits-');
  const emptyRoot = await makeTempDir('trust-hash-limits-empty-');
  try {
    await writeTree(root, { 'a.txt': 'a', 'b.txt': 'b', 'c.txt': 'c' });

    const byCount = await computeContentHash(root, { maxFiles: 2 });
    assert.equal(byCount.hash, null);
    assert.equal(byCount.complete, false);
    assert.equal(byCount.errors.some((error) => error.code === 'hash_limit'), true);
    assert.equal(byCount.files.length, 2);

    const byBytes = await computeContentHash(root, { maxTotalBytes: 2 });
    assert.equal(byBytes.hash, null);
    assert.equal(byBytes.complete, false);
    assert.equal(byBytes.errors.some((error) => error.code === 'hash_limit'), true);
    assert.ok(byBytes.byte_count <= 2);

    // Zero limits only reject entries; an empty tree is still a complete hash.
    const empty = await computeContentHash(emptyRoot, { maxFiles: 0, maxTotalBytes: 0 });
    assert.equal(empty.complete, true);
    assert.equal(empty.hash, expectedAggregate([]));

    await assert.rejects(computeContentHash(root, { maxFiles: -1 }), TypeError);
    await assert.rejects(computeContentHash(root, { maxTotalBytes: Number.NaN }), TypeError);
    await assert.rejects(
      computeContentHash(root, { excludes: 'nope' as unknown as string[] }),
      TypeError,
    );
    await assert.rejects(
      computeContentHash(root, { excludes: ['/etc'] }),
      TypeError,
    );
    assert.equal(DEFAULT_HASH_MAX_FILES, 5000);
    assert.equal(DEFAULT_HASH_MAX_TOTAL_BYTES, 256 * 1024 * 1024);
  } finally {
    await cleanup(root);
    await cleanup(emptyRoot);
  }
});

test('missing and non-directory roots fail closed', async () => {
  const root = await makeTempDir('trust-hash-bad-root-');
  try {
    const missing = await computeContentHash(join(root, 'missing'));
    assert.equal(missing.hash, null);
    assert.equal(missing.complete, false);
    assert.equal(missing.errors[0]?.path, '.');
    assert.ok(missing.errors.length >= 1);

    await writeFile(join(root, 'plain.txt'), 'x');
    const notDirectory = await computeContentHash(join(root, 'plain.txt'));
    assert.equal(notDirectory.hash, null);
    assert.equal(notDirectory.complete, false);
    assert.equal(
      notDirectory.errors.some((error) => error.code === 'root_not_directory'),
      true,
    );
  } finally {
    await cleanup(root);
  }
});

test('sha256File returns the raw hex digest of file bytes', async () => {
  const root = await makeTempDir('trust-hash-file-');
  const file = join(root, 'sample.bin');
  const bytes = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe]);
  try {
    await writeFile(file, bytes);
    assert.equal(await sha256File(file), sha256Hex(bytes));
    assert.equal(await sha256File(file), createHash('sha256').update(bytes).digest('hex'));
    assert.equal((await sha256File(file)).length, 64);

    await writeFile(file, '');
    assert.equal(await sha256File(file), sha256Hex(''));

    await assert.rejects(sha256File(join(root, 'missing.bin')));
  } finally {
    await cleanup(root);
  }
});

test('nested paths are POSIX and the aggregate format is pinned', async () => {
  const root = await makeTempDir('trust-hash-format-');
  try {
    await writeTree(root, {
      'b.txt': 'bravo',
      'a/z.txt': 'zulu',
      'a/b/c.txt': 'charlie',
    });
    const result = await computeContentHash(root);
    assert.equal(result.complete, true);
    assert.deepEqual(pathsOf(result), ['a/b/c.txt', 'a/z.txt', 'b.txt']);
    assert.equal(pathsOf(result).every((path) => !path.includes('\\')), true);
    assert.equal(result.hash, expectedAggregate([
      { path: 'a/b/c.txt', sha256: sha256Hex('charlie') },
      { path: 'a/z.txt', sha256: sha256Hex('zulu') },
      { path: 'b.txt', sha256: sha256Hex('bravo') },
    ]));
    assert.equal(result.byte_count, 5 + 4 + 7);
  } finally {
    await cleanup(root);
  }
});
