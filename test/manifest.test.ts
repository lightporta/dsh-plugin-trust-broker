import { test } from 'node:test';
import assert from 'node:assert/strict';
import { symlink } from 'node:fs/promises';
import { join } from 'node:path';

import { fixturePath, makeTempDir, cleanup, writeTree } from './helpers.ts';
import {
  classifyDependencySpec,
  ManifestReadError,
  parseDeclaredCapabilities,
  readPluginManifest,
} from '../src/core/manifest.ts';
import { declarationPathState, declaredTrueKeys } from '../src/core/catalog.ts';

test('a package.json symlink cannot read a manifest outside the candidate root', {
  skip: process.platform === 'win32',
}, async () => {
  const root = await makeTempDir('trust-manifest-link-');
  try {
    await writeTree(root, { 'outside.json': '{"name":"outside","version":"1.0.0"}', 'plugin/code.js': '' });
    const plugin = join(root, 'plugin');
    await symlink('../outside.json', join(plugin, 'package.json'));
    await assert.rejects(readPluginManifest(plugin), (error: unknown) =>
      error instanceof ManifestReadError && error.reason === 'missing_package_json');
  } finally {
    await cleanup(root);
  }
});

test('manifest entry fields cannot point outside the candidate root', async () => {
  const root = await makeTempDir('trust-manifest-entry-');
  try {
    for (const escaped of [
      { main: '../other.js' },
      { exports: { '.': { node: './safe.js', default: '..\\other.js' } } },
      { dsh: { bundle: { patch: '/var/other.patch.yml' } } },
    ]) {
      const packageJson = { name: 'candidate', version: '1.0.0', ...escaped };
      await writeTree(root, { 'package.json': JSON.stringify(packageJson) });
      await assert.rejects(readPluginManifest(root), (error: unknown) =>
        error instanceof ManifestReadError && error.issues[0]?.code === 'unsafe_manifest_entry');
    }
  } finally {
    await cleanup(root);
  }
});

test('npm provenance reports direct and resolved transitive sources without URL credentials', async () => {
  const root = await makeTempDir('trust-manifest-lock-');
  try {
    const archive = 'https://user:password-fixture@mirror.invalid/archive.tgz?%74oken=query-fixture&ref=release';
    await writeTree(root, {
      'package.json': JSON.stringify({
        name: 'candidate',
        version: '1.0.0',
        repository: `git+${archive}`,
        scripts: { postinstall: `curl '${archive}'` },
        dependencies: { direct: archive },
      }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          'node_modules/direct/node_modules/transitive': { resolved: archive },
          'node_modules/standard': { resolved: 'https://registry.npmjs.org/standard/-/standard-1.0.0.tgz' },
        },
      }),
    });
    const manifest = await readPluginManifest(root);
    const rendered = JSON.stringify(manifest);
    assert.doesNotMatch(rendered, /password-fixture|query-fixture|user@/);
    assert.match(rendered, /mirror\.invalid\/archive\.tgz\?%74oken=\[redacted\]&ref=release/);
    assert.deepEqual(manifest.dependencies.map(({ name, kind }) => [name, kind]), [
      ['direct', 'url'], ['transitive', 'url'], ['standard', 'registry'],
    ]);
    assert.equal(manifest.dependencies[1]?.evidence.file, 'package-lock.json');
  } finally {
    await cleanup(root);
  }
});

test('complete declaration: identity, provenance, presence-aware slots, scripts, deps', async () => {
  const manifest = await readPluginManifest(fixturePath('manifest', 'declared-complete'));

  assert.equal(manifest.plugin_id, 'clean-declared');
  assert.equal(manifest.version, '2.0.0');
  assert.equal(manifest.repository, 'git+https://github.com/example/clean-declared.git');
  assert.equal(manifest.dsh_bundle_patch, './cordis.patch.yml');
  assert.equal(manifest.main_entry, './lib/index.js');
  assert.equal(manifest.description, 'Fixture with a complete, explicit permission declaration.');

  assert.equal(manifest.declaration.status, 'declared');
  assert.equal(manifest.declaration.source_field, 'package.json#dsh.bundle.capabilities');
  assert.equal(manifest.declaration.errors.length, 0);

  const declared = manifest.declaration.declared;
  assert.equal(declarationPathState(declared, 'network.fetch'), 'true');
  assert.equal(declarationPathState(declared, 'process.child_process'), 'false');
  assert.equal(declarationPathState(declared, 'filesystem.write'), 'false');
  assert.equal(declarationPathState(declared, 'env.read'), 'true');
  assert.equal(declarationPathState(declared, 'lifecycle.postinstall'), 'false');
  assert.equal(declarationPathState(declared, 'credentials.read'), 'false');
  assert.equal(declarationPathState(declared, 'dynamic_code.eval'), 'false');

  const trueKeys = declaredTrueKeys(declared).sort();
  assert.deepEqual(trueKeys, ['env.read', 'filesystem.read', 'llm.call', 'network.fetch', 'tool_registry.add']);

  // 22 explicit slots: presence is what makes the many `false` values meaningful.
  assert.equal(manifest.declaration.slots.length, 22);
  assert.ok(manifest.declaration.slots.every((slot) => slot.present));

  assert.equal(manifest.install_scripts.length, 1);
  assert.equal(manifest.install_scripts[0]?.name, 'postinstall');
  assert.equal(manifest.install_scripts[0]?.command, 'node setup.js');
  assert.deepEqual(manifest.install_scripts[0]?.evidence, {
    field: 'package.json#scripts.postinstall',
  });

  const dependencyKinds = new Map(manifest.dependencies.map((dep) => [dep.name, dep.kind]));
  assert.equal(dependencyKinds.get('zod'), 'registry');
  assert.equal(dependencyKinds.get('weird-dep'), 'git');
  assert.equal(manifest.auto_update_declared, false);
  assert.equal(manifest.errors.length, 0);
});

test('no declaration: status unstated, empty surface, explicit note', async () => {
  const manifest = await readPluginManifest(fixturePath('manifest', 'undeclared'));
  assert.equal(manifest.declaration.status, 'unstated');
  assert.equal(manifest.declaration.slots.length, 0);
  assert.deepEqual(manifest.declaration.declared_true_keys, []);
  assert.ok(manifest.declaration.notes.some((note) => note.includes('unstated')));
  assert.equal(manifest.install_scripts.length, 0);
});

test('malformed declaration: status malformed, valid subset kept, type errors reported', async () => {
  const manifest = await readPluginManifest(fixturePath('manifest', 'malformed'));
  const declaration = manifest.declaration;

  assert.equal(declaration.status, 'malformed');
  assert.ok(declaration.errors.length >= 2);
  assert.ok(declaration.errors.some((issue) => issue.code === 'declaration_type'));
  // The valid `process.child_process: false` slot survives the malformed sibling.
  assert.equal(declarationPathState(declaration.declared, 'process.child_process'), 'false');
  assert.ok(declaration.notes.some((note) => note.includes('unstated')));
});

test('partial declaration is parsed; incompleteness is decided against detection later', async () => {
  const manifest = await readPluginManifest(fixturePath('manifest', 'incomplete'));
  assert.equal(manifest.declaration.status, 'declared');
  assert.equal(manifest.declaration.slots.length, 1);
  assert.deepEqual(manifest.declaration.declared_true_keys, ['network.fetch']);
});

test('unreadable trees fail closed with a reason the decision layer can map', async () => {
  await assert.rejects(
    () => readPluginManifest(fixturePath('manifest', 'no-package')),
    (error: unknown) =>
      error instanceof ManifestReadError && error.reason === 'missing_package_json',
  );

  await assert.rejects(
    () => readPluginManifest(fixturePath('manifest', 'invalid-json')),
    (error: unknown) =>
      error instanceof ManifestReadError && error.reason === 'invalid_package_json',
  );

  await assert.rejects(
    () => readPluginManifest(fixturePath('manifest', 'bad-identity')),
    (error: unknown) =>
      error instanceof ManifestReadError &&
      error.reason === 'invalid_package_json' &&
      error.issues.some((issue) => issue.code === 'name_missing'),
  );

  // A regular file is not a plugin root.
  await assert.rejects(
    () => readPluginManifest(fixturePath('manifest', 'declared-complete', 'package.json')),
    (error: unknown) => error instanceof ManifestReadError && error.reason === 'unreadable_root',
  );
});

test('declaration discovery priority: dsh.capabilities wins over permissions', async () => {
  const root = await makeTempDir('manifest-priority-');
  try {
    await writeTree(root, {
      'package.json': JSON.stringify({
        name: 'priority-plugin',
        version: '1.0.0',
        permissions: { process: { child_process: true } },
        dsh: { capabilities: { network: { fetch: false } } },
      }),
    });
    const manifest = await readPluginManifest(root);
    assert.equal(manifest.declaration.source_field, 'package.json#dsh.capabilities');
    assert.equal(declarationPathState(manifest.declaration.declared, 'network.fetch'), 'false');
    assert.equal(declarationPathState(manifest.declaration.declared, 'process.child_process'), 'absent');
  } finally {
    await cleanup(root);
  }
});

test('parseDeclaredCapabilities: empty declarations, empty env list, unknown keys', () => {
  const emptyObject = parseDeclaredCapabilities({}, 'package.json#dsh.capabilities');
  assert.equal(emptyObject.status, 'unstated');
  assert.equal(emptyObject.slots.length, 0);

  const emptyFamily = parseDeclaredCapabilities({ network: {} }, 'package.json#dsh.capabilities');
  assert.equal(emptyFamily.status, 'incomplete');
  assert.ok(emptyFamily.notes.some((note) => note.includes('不完整')));

  const emptyEnv = parseDeclaredCapabilities({ env: { read: [] } }, 'package.json#dsh.capabilities');
  assert.equal(emptyEnv.status, 'declared');
  assert.equal(declarationPathState(emptyEnv.declared, 'env.read'), 'false');

  const unknown = parseDeclaredCapabilities(
    { network: { fetch: true }, telepathy: { read: true } },
    'package.json#dsh.capabilities',
  );
  assert.equal(unknown.status, 'declared');
  assert.ok(unknown.notes.some((note) => note.includes('telepathy')));

  const nonObject = parseDeclaredCapabilities('nope', 'package.json#dsh.capabilities');
  assert.equal(nonObject.status, 'malformed');
  assert.equal(nonObject.errors[0]?.code, 'declaration_not_object');
});

test('parseDeclaredCapabilities: non-boolean and non-string-array values are malformed', () => {
  const result = parseDeclaredCapabilities(
    {
      process: { child_process: 'no' },
      filesystem: { roots: [1, 2] },
      env: { read: ['OK', 3] },
    },
    'package.json#dsh.capabilities',
  );
  assert.equal(result.status, 'malformed');
  assert.ok(result.errors.length >= 3);
  assert.ok(result.errors.every((issue) => issue.field !== undefined));
});

test('dependency source classification covers registry, git, file, url and aliases', () => {
  const cases: Array<[string, string]> = [
    ['^1.2.3', 'registry'],
    ['1.2.3', 'registry'],
    ['~2.0.0', 'registry'],
    ['latest', 'registry'],
    ['*', 'registry'],
    ['npm:@scope/pkg@^1.0.0', 'registry'],
    ['git+https://github.com/example/pkg.git', 'git'],
    ['git:https://github.com/example/pkg.git', 'git'],
    ['github:example/pkg', 'git'],
    ['file:../local-pkg', 'file'],
    ['link:../local-pkg', 'file'],
    ['https://example.com/pkg.tgz', 'url'],
    ['workspace:*', 'workspace'],
    ['??', 'other'],
  ];
  for (const [spec, expected] of cases) {
    assert.equal(classifyDependencySpec(spec), expected, `spec ${spec}`);
  }
});

test('auto_update declaration is detected from dsh.autoUpdate and recorded with a pointer', async () => {
  const root = await makeTempDir('manifest-autoupdate-');
  try {
    await writeTree(root, {
      'package.json': JSON.stringify({
        name: 'auto-updating-plugin',
        version: '3.0.0',
        dsh: { autoUpdate: true },
      }),
    });
    const manifest = await readPluginManifest(root);
    assert.equal(manifest.auto_update_declared, true);
    assert.equal(manifest.auto_update_field, 'package.json#dsh.autoUpdate');
  } finally {
    await cleanup(root);
  }
});
