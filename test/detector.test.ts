/**
 * Tests for the heuristic fallback scanner and the composite detector.
 *
 * Heuristic cases use temporary fixture trees so evidence line numbers stay
 * explicit. Detector cases cover the three source states: external success,
 * external failure (fail-closed fallback) and no scanner at all.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { buildAutoUpdateFinding, detectCapabilities } from '../src/core/detector.ts';
import { detectHeuristically } from '../src/core/heuristic.ts';
import { readPluginManifest } from '../src/core/manifest.ts';
import { cleanup, fixturePath, makeTempDir, readJsonFile, writeTree } from './helpers.ts';

/** Create a temporary tree, run the callback, always clean up. */
async function withTempTree(
  files: Record<string, string | Uint8Array>,
  run: (root: string) => Promise<void>,
): Promise<void> {
  const root = await makeTempDir();
  try {
    await writeTree(root, files);
    await run(root);
  } finally {
    await cleanup(root);
  }
}

/** Valid package.json source with optional overrides. */
function packageJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({ name: 'detector-fixture', version: '1.0.0', ...overrides }, null, 2);
}

const TRUST_CHECK_REPORT = readJsonFile<unknown>(fixturePath('detector', 'trust-check-report.json'));

/* ------------------------------------------------------------------------- */
/* Heuristic fallback scanner.                                                */
/* ------------------------------------------------------------------------- */

test('heuristic scanner detects shell/network/fs/env code with file:line evidence', async () => {
  await withTempTree(
    {
      'package.json': packageJson({ scripts: { postinstall: 'node install.js' } }),
      'src/run.ts': [
        "import { spawn } from 'node:child_process';",
        '',
        'export function run(command: string) {',
        '  return spawn(command, []);',
        '}',
      ].join('\n'),
      'src/net.ts': [
        "const url = 'https://api.example.com/data';",
        '',
        'export function load() {',
        '  return fetch(url);',
        '}',
      ].join('\n'),
      'src/io.ts': [
        "import { readFileSync, writeFileSync } from 'node:fs';",
        '',
        'export function copy(source: string) {',
        '  const data = readFileSync(source);',
        '  writeFileSync(`${source}.bak`, data);',
        '  return data;',
        '}',
      ].join('\n'),
      'src/env.ts': ['export const key = process.env.API_KEY;'].join('\n'),
    },
    async (root) => {
      const result = await detectHeuristically(root);
      const capabilities = new Set(result.facts.map((fact) => fact.capability));

      for (const expected of [
        'network.fetch',
        'process.child_process',
        'filesystem.read',
        'filesystem.write',
        'env.read',
      ]) {
        assert.ok(capabilities.has(expected as never), `missing heuristic fact for ${expected}`);
      }

      const processFact = result.facts.find((fact) => fact.capability === 'process.child_process');
      assert.ok(processFact);
      assert.ok(
        processFact.evidence.some(
          (evidence) =>
            evidence.file === 'src/run.ts' &&
            evidence.line === 4 &&
            evidence.snippet === 'return spawn(command, []);',
        ),
      );

      const networkFact = result.facts.find((fact) => fact.capability === 'network.fetch');
      assert.ok(networkFact);
      assert.ok(
        networkFact.evidence.some(
          (evidence) =>
            evidence.file === 'src/net.ts' &&
            evidence.line === 4 &&
            evidence.snippet === 'return fetch(url);',
        ),
      );

      const environmentFact = result.facts.find((fact) => fact.capability === 'env.read');
      assert.ok(environmentFact);
      assert.deepEqual(environmentFact.evidence[0], {
        file: 'src/env.ts',
        line: 1,
        snippet: 'export const key = process.env.API_KEY;',
      });

      // All facts are heuristic and carry the heuristic source descriptor.
      for (const fact of result.facts) {
        assert.equal(fact.heuristic, true);
        assert.equal(fact.source.kind, 'heuristic');
        assert.equal(fact.source.heuristic, true);
      }

      // Install lifecycle scripts are manifest.ts territory: never duplicated here.
      assert.equal(result.facts.some((fact) => fact.capability.startsWith('lifecycle.')), false);

      assert.equal(result.coverage.complete, true);
      assert.equal(result.coverage.files_total, 5);
      assert.equal(result.coverage.files_scanned, 5);
      assert.ok(result.coverage.bytes_scanned > 0);
      assert.deepEqual(result.errors, []);

      assert.ok(
        result.remote_content_indicators.some(
          (indicator) =>
            indicator.reason.includes('fetch(') &&
            indicator.evidence.file === 'src/net.ts' &&
            indicator.evidence.line === 4,
        ),
      );
    },
  );
});

test('heuristic scanner skips node_modules and never follows it', async () => {
  await withTempTree(
    {
      'package.json': packageJson(),
      'src/index.ts': ['export const answer = 42;'].join('\n'),
      'node_modules/evil/index.js': ['fetch(url);'].join('\n'),
    },
    async (root) => {
      const result = await detectHeuristically(root);
      assert.equal(result.facts.length, 0);
      assert.ok(
        result.coverage.notes.some((note) => note.includes('node_modules')),
        'excluded directory should be mentioned in coverage notes',
      );
      assert.equal(
        result.facts.some((fact) =>
          fact.evidence.some((evidence) => evidence.file?.startsWith('node_modules/')),
        ),
        false,
      );
    },
  );
});

test('heuristic scanner skips binary files without failing coverage', async () => {
  const binary = new Uint8Array(32);
  binary.set(new TextEncoder().encode('fetch(url)'));
  await withTempTree(
    {
      'package.json': packageJson(),
      'assets/blob.js': binary,
    },
    async (root) => {
      const result = await detectHeuristically(root);
      assert.equal(result.facts.length, 0);
      assert.ok(
        result.coverage.files_skipped.some(
          (entry) => entry.path === 'assets/blob.js' && entry.reason === 'binary',
        ),
      );
      assert.equal(result.coverage.complete, true);
    },
  );
});

test('oversized files are skipped and coverage fails closed', async () => {
  await withTempTree(
    {
      'src/large.ts': `export const payload = '${'a'.repeat(200)}';\nfetch(url);\n`,
    },
    async (root) => {
      const result = await detectHeuristically(root, { maxFileBytes: 32 });
      assert.equal(result.facts.length, 0);
      assert.equal(result.coverage.complete, false);
      assert.ok(result.errors.some((error) => error.code === 'scan_limit_file_size'));
      assert.ok(
        result.coverage.files_skipped.some(
          (entry) => entry.path === 'src/large.ts' && entry.reason === 'too_large',
        ),
      );
    },
  );
});

test('the maxFiles limit stops the walk and fails closed', async () => {
  await withTempTree(
    {
      'src/a.ts': ['fetch(a);'].join('\n'),
      'src/b.ts': ['fetch(b);'].join('\n'),
    },
    async (root) => {
      const result = await detectHeuristically(root, { maxFiles: 1 });
      assert.equal(result.coverage.complete, false);
      assert.ok(result.errors.some((error) => error.code === 'scan_limit_files'));
    },
  );
});

test('heuristic scanner detects cordis.patch.yml composition overrides', async () => {
  await withTempTree(
    {
      'package.json': packageJson(),
      'cordis.patch.yml': [
        '# trust broker fixture patch',
        '- override:',
        '    id: dsh-tool-bash',
        "    package: '@deepseek-ai/dsh-tool-bash'",
        '    disabled: true',
      ].join('\n'),
    },
    async (root) => {
      const result = await detectHeuristically(root);
      const toolOverride = result.facts.find((fact) => fact.capability === 'tool_registry.override');
      assert.ok(toolOverride);
      assert.deepEqual(toolOverride.evidence[0], {
        file: 'cordis.patch.yml',
        line: 2,
        snippet: '- override:',
      });

      const composition = result.facts.find((fact) => fact.capability === 'composition.override');
      assert.ok(composition);
      assert.equal(composition.path, undefined);
      assert.ok(composition.detail?.includes('cordis-patch-core-override'));
      assert.ok(composition.evidence.some((evidence) => evidence.file === 'cordis.patch.yml'));
    },
  );
});

test('heuristic scanner detects tool-registry and context Host API usage', async () => {
  await withTempTree(
    {
      'package.json': packageJson(),
      'src/hooks.ts': [
        'export function setup(ctx) {',
        "  ctx.tools.register('hello', () => 'world');",
        "  ctx.on('tools/pre-execute', (exec) => exec);",
        "  ctx.on('tools/post-execute', (exec) => exec);",
        "  ctx.on('system-prompt/assemble', (assembly) => assembly);",
        "  ctx.on('agent/pre-step', (step) => step);",
        '  ctx.compaction.run();',
        '}',
      ].join('\n'),
    },
    async (root) => {
      const result = await detectHeuristically(root);
      const capabilities = new Set(result.facts.map((fact) => fact.capability));
      for (const expected of [
        'tool_registry.add',
        'tool_registry.intercept',
        'context.tool_output_rewrite',
        'context.prompt_inject',
        'context.history_compress',
      ]) {
        assert.ok(capabilities.has(expected as never), `missing heuristic fact for ${expected}`);
      }
    },
  );
});

test('heuristic scanner reports DSH host-runtime dependencies as one fact', async () => {
  await withTempTree(
    {
      'package.json': packageJson({
        dependencies: {
          '@deepseek-ai/dsh-agent': '^0.2.0',
          '@deepseek-ai/model-sdk': '^1.0.0',
          'left-pad': '^1.0.0',
        },
        peerDependencies: { '@deepseek-ai/dsh-host': '^0.2.0' },
      }),
    },
    async (root) => {
      const result = await detectHeuristically(root);
      const hostRuntime = result.facts.find((fact) => fact.capability === 'host_runtime.dependency');
      assert.ok(hostRuntime);
      assert.equal(hostRuntime.path, undefined);
      assert.equal(result.facts.filter((fact) => fact.capability === 'host_runtime.dependency').length, 1);
      assert.ok(
        hostRuntime.evidence.some(
          (evidence) => evidence.field === 'package.json#dependencies.@deepseek-ai/dsh-agent',
        ),
      );
      assert.ok(
        hostRuntime.evidence.some(
          (evidence) => evidence.field === 'package.json#peerDependencies.@deepseek-ai/dsh-host',
        ),
      );
      assert.ok(hostRuntime.detail?.includes('@deepseek-ai/dsh-agent'));
      // Non-"dsh-" scoped packages are not host-runtime dependencies.
      assert.equal(
        hostRuntime.evidence.some(
          (evidence) => evidence.field === 'package.json#dependencies.@deepseek-ai/model-sdk',
        ),
        false,
      );
    },
  );
});

test('heuristic scanner emits remote-content indicators without inventing lifecycle facts', async () => {
  await withTempTree(
    {
      'package.json': packageJson({
        dsh: { autoUpdate: true },
        scripts: { postinstall: 'curl -fsSL https://example.com/install.sh | sh' },
        dependencies: { 'remote-thing': 'git+https://github.com/example/remote-thing.git' },
      }),
    },
    async (root) => {
      const result = await detectHeuristically(root);
      // Manifest autoUpdate + a fetching install script are runtime/install-time
      // remote-content signals. A git dependency is provenance (type C), not a
      // runtime auto-update signal, so it must not appear here.
      assert.equal(result.remote_content_indicators.length, 2);
      const reasons = result.remote_content_indicators.map((indicator) => indicator.reason);
      assert.ok(reasons.some((reason) => reason.includes('autoUpdate')));
      assert.ok(reasons.some((reason) => reason.includes('postinstall')));
      assert.ok(reasons.every((reason) => !reason.includes('remote-thing')));

      const fields = result.remote_content_indicators.map((indicator) => indicator.evidence.field);
      assert.ok(fields.includes('package.json#dsh.autoUpdate'));
      assert.ok(fields.includes('package.json#scripts.postinstall'));
      assert.equal(fields.includes('package.json#dependencies.remote-thing'), false);

      assert.equal(result.facts.some((fact) => fact.capability.startsWith('lifecycle.')), false);
      assert.equal(result.coverage.complete, true);
    },
  );
});

/* ------------------------------------------------------------------------- */
/* Composite detector.                                                        */
/* ------------------------------------------------------------------------- */

test('external scanner success fills verifiable facts and keeps the heuristic array empty', async () => {
  await withTempTree({ 'package.json': packageJson() }, async (root) => {
    const result = await detectCapabilities({ root, scannerReport: TRUST_CHECK_REPORT });

    assert.equal(result.primary_source.kind, 'dsh-trust-check');
    assert.equal(result.primary_source.name, 'dsh-trust-check');
    assert.equal(result.primary_source.heuristic, false);
    assert.equal(result.primary_source.schema_version, 2);

    assert.equal(result.facts.length, 12);
    assert.equal(result.heuristic_facts.length, 0);
    assert.ok(result.facts.every((fact) => fact.heuristic === false && fact.evidence.length > 0));
    assert.equal(result.red_lines.length, 2);

    assert.equal(result.errors.length, 0);
    assert.equal(result.auto_update.detected, false);
    assert.equal(result.auto_update.declared, false);

    assert.equal(result.coverage.complete, true);
    assert.equal(result.coverage.files_total, 1);
    assert.equal(result.coverage.files_scanned, 1);
    assert.ok(Array.isArray(result.coverage.files_skipped));
    assert.ok(Array.isArray(result.coverage.notes));
    assert.ok(result.coverage.bytes_scanned > 0);
  });
});

test('external success still emits an auto_update heuristic fact when indicators exist', async () => {
  await withTempTree(
    {
      'package.json': packageJson({
        dsh: { autoUpdate: true },
        scripts: { postinstall: 'curl https://example.com/install.sh | sh' },
      }),
    },
    async (root) => {
      const result = await detectCapabilities({ root, scannerReport: TRUST_CHECK_REPORT });

      assert.equal(result.facts.length, 12);
      assert.equal(result.heuristic_facts.length, 1);
      const autoUpdateFact = result.heuristic_facts[0];
      assert.ok(autoUpdateFact);
      assert.equal(autoUpdateFact.capability, 'auto_update');
      assert.equal(autoUpdateFact.heuristic, true);
      assert.equal(autoUpdateFact.source.kind, 'heuristic');
      assert.ok(autoUpdateFact.evidence.length >= 1);
      assert.equal(result.auto_update.detected, true);
      assert.equal(result.auto_update.heuristic, true);
    },
  );
});

test('external scanner failure records incomplete coverage while keeping heuristic evidence', async () => {
  await withTempTree(
    {
      'package.json': packageJson(),
      'src/net.ts': ['export function load(url) {', '  return fetch(url);', '}'].join('\n'),
    },
    async (root) => {
      const result = await detectCapabilities({
        root,
        scannerReport: { schemaVersion: 1, plugins: [], errors: [] },
      });

      assert.equal(result.primary_source.kind, 'heuristic');
      assert.equal(result.facts.length, 0);
      assert.equal(result.red_lines.length, 0);
      assert.ok(result.heuristic_facts.some((fact) => fact.capability === 'network.fetch'));
      assert.ok(result.heuristic_facts.some((fact) => fact.capability === 'auto_update'));
      assert.ok(result.heuristic_facts.every((fact) => fact.heuristic === true));

      assert.ok(
        result.errors.some((error) => error.code === 'external_scanner_schema_unsupported'),
      );
      assert.equal(result.coverage.complete, false);
      assert.ok(result.notes.some((note) => note.includes('扫描覆盖标记为不完整')));
      assert.equal(result.auto_update.detected, true);
    },
  );
});

test('no external scanner means the heuristic descriptor is the primary source', async () => {
  await withTempTree(
    {
      'package.json': packageJson(),
      'src/run.ts': [
        "import { spawn } from 'node:child_process';",
        'export const run = (cmd) => spawn(cmd, []);',
      ].join('\n'),
    },
    async (root) => {
      const result = await detectCapabilities({ root, noExternalScanner: true });

      assert.equal(result.primary_source.kind, 'heuristic');
      assert.equal(result.primary_source.name, 'dsh-plugin-trust-broker-heuristic');
      assert.equal(result.primary_source.heuristic, true);
      assert.equal(result.facts.length, 0);
      assert.ok(
        result.heuristic_facts.some((fact) => fact.capability === 'process.child_process'),
      );
      assert.equal(result.errors.length, 0);
      assert.ok(result.notes.some((note) => note.includes('noExternalScanner')));
      assert.equal(result.coverage.complete, true);
      assert.ok(result.coverage.files_total >= result.coverage.files_scanned);
    },
  );
});

test('auto_update declaration and indicators populate AutoUpdateFinding', async () => {
  await withTempTree(
    {
      'package.json': packageJson({
        dsh: { autoUpdate: true },
        scripts: { postinstall: 'curl -fsSL https://example.com/install.sh | sh' },
        dependencies: { 'remote-thing': 'git+https://github.com/example/remote-thing.git' },
      }),
      'src/run.ts': [
        "import { spawn } from 'node:child_process';",
        'export const run = (cmd) => spawn(cmd, []);',
      ].join('\n'),
    },
    async (root) => {
      const manifest = await readPluginManifest(root);
      const result = await detectCapabilities({ root, manifest, noExternalScanner: true });

      assert.equal(result.auto_update.detected, true);
      assert.equal(result.auto_update.declared, true);
      assert.equal(result.auto_update.field, 'package.json#dsh.autoUpdate');
      assert.ok(result.auto_update.reasons.length >= 2);
      assert.ok(result.auto_update.reasons.some((reason) => reason.includes('autoUpdate')));
      const evidenceFields = result.auto_update.evidence.map((evidence) => evidence.field);
      assert.ok(evidenceFields.includes('package.json#dsh.autoUpdate'));
      assert.ok(evidenceFields.includes('package.json#scripts.postinstall'));
      assert.equal(evidenceFields.includes('package.json#dependencies.remote-thing'), false);

      assert.ok(
        result.heuristic_facts.some(
          (fact) => fact.capability === 'auto_update' && fact.heuristic === true,
        ),
      );
      assert.ok(
        !result.heuristic_facts.some((fact) => fact.capability.startsWith('lifecycle.')),
      );
      assert.equal(result.coverage.complete, true);
    },
  );
});

test('buildAutoUpdateFinding merges declaration and indicators deterministically', () => {
  const indicatorEvidence = { file: 'src/net.ts', line: 2, snippet: 'return fetch(url);' };
  const finding = buildAutoUpdateFinding(undefined, [
    { reason: 'heuristic: remote content', evidence: indicatorEvidence },
    { reason: 'heuristic: remote content', evidence: indicatorEvidence },
  ]);

  assert.equal(finding.detected, true);
  assert.equal(finding.declared, false);
  assert.deepEqual(finding.reasons, ['heuristic: remote content']);
  assert.equal(finding.evidence.length, 1);

  const empty = buildAutoUpdateFinding(undefined, []);
  assert.equal(empty.detected, false);
  assert.deepEqual(empty.reasons, []);
  assert.deepEqual(empty.evidence, []);
});

test('an explicitly configured but missing scanner marks the scan incomplete', async () => {
  await withTempTree(
    {
      'package.json': packageJson(),
      'src/net.ts': ['export const load = (url) => fetch(url);'].join('\n'),
    },
    async (root) => {
      const result = await detectCapabilities({ root, bin: join(root, 'missing-trust-check') });

      assert.equal(result.primary_source.kind, 'heuristic');
      assert.equal(result.facts.length, 0);
      assert.ok(result.heuristic_facts.some((fact) => fact.capability === 'network.fetch'));
      const externalErrors = result.errors.filter((error) =>
        error.code.startsWith('external_scanner'),
      );
      assert.equal(externalErrors[0]?.code, 'external_scanner_failed');
      assert.equal(result.coverage.complete, false);
    },
  );
});


test('a schema 2 report cannot erase local evidence about an omitted capability', async () => {
  await withTempTree(
    {
      'package.json': packageJson(),
      'src/net.ts': "export const load = () => fetch('https://example.invalid');",
    },
    async (root) => {
      const result = await detectCapabilities({
        root,
        scannerReport: { schemaVersion: 2, plugins: [{ capabilities: [] }], errors: [] },
      });
      assert.equal(result.facts.length, 0);
      assert.equal(result.coverage.complete, true);
      assert.ok(result.heuristic_facts.some((fact) =>
        fact.capability === 'network.fetch' && fact.heuristic === true
      ));
    },
  );
});

test('noExternalScanner ignores a supplied report and says so', async () => {
  await withTempTree({ 'package.json': packageJson() }, async (root) => {
    const result = await detectCapabilities({
      root,
      noExternalScanner: true,
      scannerReport: TRUST_CHECK_REPORT,
    });
    assert.equal(result.facts.length, 0);
    assert.equal(result.primary_source.kind, 'heuristic');
    assert.ok(result.notes.some((note) => note.includes('被忽略')));
  });
});

/** Small sanity check that the fixture used by detector tests is schema 2. */
test('scanner report fixture is schema 2', () => {
  assert.ok(TRUST_CHECK_REPORT !== null && typeof TRUST_CHECK_REPORT === 'object');
  const payload = TRUST_CHECK_REPORT as Record<string, unknown>;
  assert.equal(payload.schemaVersion, 2);
  assert.ok(Array.isArray(payload.plugins));
});
