/**
 * Tests for the external `dsh-trust-check` adapter: schema 2 validation,
 * mapping into the broker vocabulary, red-line pass-through, and the
 * explicit scanner selection and bounded subprocess behavior.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, readFile, symlink, truncate } from 'node:fs/promises';
import { delimiter, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { loadExternalScan } from '../src/core/external-scan.ts';
import type {
  ExternalScanFailure,
  ExternalScanOutcome,
  ExternalScanSuccess,
} from '../src/core/external-scan.ts';
import { cleanup, fixturePath, makeTempDir, readJsonFile, writeTree } from './helpers.ts';

/** Narrow an outcome to success (or fail the test). */
function assertSuccess(outcome: ExternalScanOutcome): ExternalScanSuccess {
  if (outcome === null) assert.fail('expected scanner success, got null');
  if (!outcome.ok) {
    assert.fail(`expected scanner success, got failure: ${outcome.errors.map((e) => e.code).join(', ')}`);
  }
  return outcome;
}

/** Narrow an outcome to failure (or fail the test). */
function assertFailure(outcome: ExternalScanOutcome): ExternalScanFailure {
  if (outcome === null) assert.fail('expected scanner failure, got null');
  if (outcome.ok) assert.fail('expected scanner failure, got success');
  return outcome;
}

const ROOT = fixturePath('detector');
const REPORT = readJsonFile<unknown>(fixturePath('detector', 'trust-check-report.json'));

test('schema 2 report maps scanner capabilities to broker facts', async () => {
  const outcome = await loadExternalScan({ root: ROOT, report: REPORT });
  const success = assertSuccess(outcome);

  assert.equal(success.scanner.name, 'dsh-trust-check');
  assert.equal(success.scanner.version, '2.1.0');
  assert.equal(success.scanner.schema_version, 2);

  const capabilities = new Set(success.facts.map((fact) => fact.capability));
  assert.equal(success.facts.length, 12);
  for (const expected of [
    'process.child_process',
    'network.fetch',
    'filesystem.read',
    'filesystem.write',
    'env.read',
    'credentials.read',
    'subagent.spawn',
    'host_runtime.dependency',
    'llm.call',
    'dynamic_code.eval',
    'context.prompt_inject',
    'composition.override',
  ]) {
    assert.ok(capabilities.has(expected as never), `missing fact for ${expected}`);
  }

  for (const fact of success.facts) {
    assert.equal(fact.heuristic, false);
    assert.equal(fact.source.kind, 'dsh-trust-check');
    assert.equal(fact.source.heuristic, false);
    assert.equal(fact.source.schema_version, 2);
    assert.ok(fact.evidence.length > 0, `fact ${fact.capability} has no evidence`);
  }
});

test('scanner capabilities keep their file:line evidence and mapped path', async () => {
  const success = assertSuccess(await loadExternalScan({ root: ROOT, report: REPORT }));

  const shell = success.facts.find((fact) => fact.capability === 'process.child_process');
  assert.ok(shell);
  assert.equal(shell.path, 'process.child_process');
  assert.deepEqual(shell.evidence[0], {
    file: 'src/run.ts',
    line: 3,
    snippet: "spawn('ls', ['-la'])",
  });

  const hostRuntime = success.facts.find((fact) => fact.capability === 'host_runtime.dependency');
  assert.ok(hostRuntime);
  assert.equal(hostRuntime.path, undefined);
  assert.ok(hostRuntime.evidence.some((evidence) => evidence.file === 'package.json'));
});

test('destinations and supplemental facts attach to network.fetch evidence', async () => {
  const success = assertSuccess(await loadExternalScan({ root: ROOT, report: REPORT }));

  const network = success.facts.find((fact) => fact.capability === 'network.fetch');
  assert.ok(network);
  assert.ok(network.evidence.some((evidence) => evidence.file === 'src/net.ts' && evidence.line === 5));
  assert.ok(network.evidence.some((evidence) => evidence.file === 'src/net.ts' && evidence.line === 6));
  assert.ok(network.detail?.includes('destination:api.example.com'));
});

test('injections map to prompt-inject and composition-override facts', async () => {
  const success = assertSuccess(await loadExternalScan({ root: ROOT, report: REPORT }));

  const promptInject = success.facts.find((fact) => fact.capability === 'context.prompt_inject');
  assert.ok(promptInject);
  assert.equal(promptInject.evidence[0]?.field, 'cordis.patch.yml');
  assert.ok(promptInject.detail?.includes('system-prompt'));

  const composition = success.facts.find((fact) => fact.capability === 'composition.override');
  assert.ok(composition);
  assert.equal(composition.path, undefined);
  assert.ok(composition.detail?.includes('override'));
  assert.equal(composition.evidence[0]?.field, 'cordis.patch.yml');
});

test('redLines pass through verbatim and scanner notes are forwarded', async () => {
  const success = assertSuccess(await loadExternalScan({ root: ROOT, report: REPORT }));

  assert.deepEqual(success.red_lines, [
    'reads .env and uploads it to a remote host',
    'disables the sandboxed bash tool via cordis.patch.yml',
  ]);
  assert.ok(success.notes.includes('trust-check schema 2 report'));
  assert.ok(success.notes.includes('scanner inspected 10 files'));
  assert.equal(
    success.notes.some((note) => note.includes('no file:line')),
    false,
    'fixture evidence is complete; no field-pointer fallback expected',
  );
});

test('scanner evidence, notes and red lines omit URL credentials', async () => {
  const url = 'https://user:synthetic-secret@example.test/path?token=synthetic-token';
  const report = {
    schemaVersion: 2,
    notes: [url],
    plugins: [{
      capabilities: ['network'],
      evidence: [{ capability: 'network', file: 'index.js', line: 2, snippet: url }],
      redLines: [url],
    }],
  };
  const success = assertSuccess(await loadExternalScan({ root: ROOT, report }));
  assert.doesNotMatch(JSON.stringify(success), /synthetic-secret|synthetic-token/);
  assert.match(JSON.stringify(success), /example\.test\/path/);
});

test('a report JSON file on disk is loaded as a report', async () => {
  const success = assertSuccess(
    await loadExternalScan({
      root: ROOT,
      reportPath: fixturePath('detector', 'trust-check-report.json'),
    }),
  );
  assert.equal(success.scanner.schema_version, 2);
  assert.ok(success.facts.length > 0);
});

test('corrupt report JSON is a failure, not silently ignored', async () => {
  const root = await makeTempDir();
  try {
    await writeTree(root, { 'report.json': '{ this is not json' });
    const failure = assertFailure(
      await loadExternalScan({ root, reportPath: join(root, 'report.json') }),
    );
    assert.equal(failure.errors[0]?.code, 'external_scanner_report_invalid');
    assert.ok(failure.notes.length >= 0);
  } finally {
    await cleanup(root);
  }
});

test('schemaVersion 1 is rejected as unsupported', async () => {
  const failure = assertFailure(
    await loadExternalScan({
      root: ROOT,
      report: { schemaVersion: 1, plugins: [], errors: [] },
    }),
  );
  assert.equal(failure.errors[0]?.code, 'external_scanner_schema_unsupported');
  assert.ok(failure.errors[0]?.message.includes('schema 2'));
});

test('a report without plugins[0] is a failure', async () => {
  const failure = assertFailure(
    await loadExternalScan({ root: ROOT, report: { schemaVersion: 2, plugins: [], errors: [] } }),
  );
  assert.equal(failure.errors[0]?.code, 'external_scanner_report_invalid');
});

test('a scanner payload with errors fails without exposing raw diagnostics', async () => {
  const failure = assertFailure(
    await loadExternalScan({
      root: ROOT,
      report: {
        schemaVersion: 2,
        plugins: [],
        errors: [{ code: 'scan_failed', message: 'scanner exploded' }],
      },
    }),
  );
  assert.equal(failure.errors[0]?.code, 'external_scanner_failed');
  assert.doesNotMatch(JSON.stringify(failure), /scanner exploded/);
});

test('report-only mode without a report does not attempt a scan', async () => {
  const root = await makeTempDir();
  try {
    const outcome = await loadExternalScan({ root, allowSpawn: false });
    assert.equal(outcome, null);
  } finally {
    await cleanup(root);
  }
});

test('an explicit missing scanner executable fails closed', async () => {
  const root = await makeTempDir();
  try {
    const failure = assertFailure(await loadExternalScan({ root, bin: join(root, 'missing-trust-check') }));
    assert.equal(failure.errors[0]?.code, 'external_scanner_failed');
  } finally {
    await cleanup(root);
  }
});

test('a capability without evidence rows falls back to a report field pointer', async () => {
  const success = assertSuccess(
    await loadExternalScan({
      root: ROOT,
      report: {
        schemaVersion: 2,
        plugins: [
          {
            name: 'bare-plugin',
            version: '0.0.1',
            spec: 'npm:bare-plugin@0.0.1',
            capabilities: ['network'],
            evidence: [],
            facts: [],
            destinations: [],
            injections: [],
            redLines: [],
          },
        ],
        errors: [],
      },
    }),
  );

  assert.equal(success.facts.length, 1);
  const network = success.facts[0];
  assert.ok(network);
  assert.equal(network.capability, 'network.fetch');
  assert.equal(network.evidence[0]?.field, 'dsh-trust-check#plugins[0].capabilities');
  assert.ok(success.notes.some((note) => note.includes('字段指针')));
});

test('unknown scanner capabilities are notes, not facts', async () => {
  const success = assertSuccess(
    await loadExternalScan({
      root: ROOT,
      report: {
        schemaVersion: 2,
        plugins: [
          {
            name: 'quantum-plugin',
            version: '0.0.1',
            spec: 'npm:quantum-plugin@0.0.1',
            capabilities: ['quantum-teleport'],
            evidence: [],
            facts: [],
            destinations: [],
            injections: [],
            redLines: [],
          },
        ],
        errors: [],
      },
    }),
  );
  assert.equal(success.facts.length, 0);
  assert.ok(success.notes.some((note) => note.includes('quantum-teleport')));
});

test('duplicate evidence rows are de-duplicated', async () => {
  const evidenceRow = { file: 'src/net.ts', line: 5, snippet: 'fetch(url)' };
  const success = assertSuccess(
    await loadExternalScan({
      root: ROOT,
      report: {
        schemaVersion: 2,
        plugins: [
          {
            name: 'dupe-plugin',
            version: '0.0.1',
            spec: 'npm:dupe-plugin@0.0.1',
            capabilities: ['network'],
            evidence: [
              { capability: 'network', ...evidenceRow },
              { capability: 'network', ...evidenceRow },
            ],
            facts: [],
            destinations: [],
            injections: [],
            redLines: [],
          },
        ],
        errors: [],
      },
    }),
  );

  const network = success.facts.find((fact) => fact.capability === 'network.fetch');
  assert.ok(network);
  assert.equal(network.evidence.length, 1);
});

async function writeScanner(directory: string, script: string): Promise<string> {
  const name = 'dsh-trust-check';
  await writeTree(directory, { [name]: `#!/usr/bin/env node\n${script}` });
  const bin = join(directory, name);
  await chmod(bin, 0o700);
  return bin;
}

test('ignores ambient PATH and rejects a relative scanner command', { skip: process.platform === 'win32' }, async () => {
  const dir = await makeTempDir();
  const previousPath = process.env.PATH;
  try {
    await writeScanner(dir, `process.stdout.write(${JSON.stringify(JSON.stringify(REPORT))});`);
    process.env.PATH = [dir, previousPath ?? ''].join(delimiter);
    assert.equal(await loadExternalScan({ root: ROOT }), null);
    const failure = assertFailure(await loadExternalScan({ root: ROOT, bin: 'dsh-trust-check' }));
    assert.equal(failure.errors[0]?.code, 'external_scanner_failed');
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    await cleanup(dir);
  }
});

test('an explicit scanner receives no parent credentials and stderr stays private', { skip: process.platform === 'win32' }, async () => {
  const dir = await makeTempDir();
  const key = 'TRUST_BROKER_TEST_API_KEY';
  const marker = 'synthetic credential in child stderr';
  const previous = process.env[key];
  try {
    process.env[key] = marker;
    const bin = await writeScanner(dir, `
      if (process.env.${key} || process.env.NODE_OPTIONS || process.env.HOME) process.exit(98);
      process.stdout.write(${JSON.stringify(JSON.stringify(REPORT))});
    `);
    assertSuccess(await loadExternalScan({ root: ROOT, bin }));

    await writeScanner(dir, `
      process.stderr.write(${JSON.stringify(marker)});
      process.stdout.write(${JSON.stringify(JSON.stringify(REPORT))});
      process.exitCode = 4;
    `);
    const failed = assertFailure(await loadExternalScan({ root: ROOT, bin }));
    assert.equal(failed.errors[0]?.code, 'external_scanner_failed');
    assert.ok(!JSON.stringify(failed).includes(marker));
  } finally {
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
    await cleanup(dir);
  }
});

test('timeout and abort terminate a scanner with an explicit failure', { skip: process.platform === 'win32' }, async () => {
  const dir = await makeTempDir();
  const controller = new AbortController();
  try {
    const bin = await writeScanner(dir, 'setInterval(() => {}, 1_000);');
    const timedOut = assertFailure(await loadExternalScan({ root: ROOT, bin, timeoutMs: 30 }));
    assert.equal(timedOut.errors[0]?.code, 'external_scanner_timeout');

    const marker = join(dir, 'pid');
    await writeScanner(dir, `
      require('node:fs').writeFileSync(${JSON.stringify(marker)}, String(process.pid));
      setInterval(() => {}, 1_000);
    `);
    const running = loadExternalScan({ root: ROOT, bin, signal: controller.signal });
    const deadline = Date.now() + 3_000;
    let childPid: number | undefined;
    while (childPid === undefined && Date.now() < deadline) {
      try {
        childPid = Number(await readFile(marker, 'utf8'));
      } catch {
        await delay(10);
      }
    }
    assert.ok(childPid !== undefined && childPid > 0, 'scanner must have started');
    controller.abort();
    const aborted = assertFailure(await running);
    assert.equal(aborted.errors[0]?.code, 'external_scanner_aborted');

    let exited = false;
    const killDeadline = Date.now() + 3_000;
    while (!exited && Date.now() < killDeadline) {
      try {
        process.kill(childPid, 0);
        await delay(10);
      } catch (error) {
        assert.equal((error as NodeJS.ErrnoException).code, 'ESRCH');
        exited = true;
      }
    }
    assert.ok(exited, 'scanner process must exit on abort');
  } finally {
    controller.abort();
    await cleanup(dir);
  }
});

test('an oversized scanner stream is terminated', { skip: process.platform === 'win32' }, async () => {
  const dir = await makeTempDir();
  try {
    const bin = await writeScanner(dir, 'process.stdout.write(Buffer.alloc(9 * 1024 * 1024)); setInterval(() => {}, 1_000);');
    const failed = assertFailure(await loadExternalScan({ root: ROOT, bin }));
    assert.equal(failed.errors[0]?.code, 'external_scanner_report_too_large');
  } finally {
    await cleanup(dir);
  }
});

test('report files are bounded and leaf symlinks are rejected', async () => {
  const dir = await makeTempDir();
  try {
    const reportPath = join(dir, 'report.json');
    await writeTree(dir, { 'report.json': JSON.stringify(REPORT) });
    await truncate(reportPath, 9 * 1024 * 1024);
    const oversized = assertFailure(await loadExternalScan({ root: ROOT, reportPath }));
    assert.equal(oversized.errors[0]?.code, 'external_scanner_report_too_large');

    if (process.platform === 'win32') return;
    const linked = join(dir, 'linked.json');
    await symlink(reportPath, linked);
    const unreadable = assertFailure(await loadExternalScan({ root: ROOT, reportPath: linked }));
    assert.equal(unreadable.errors[0]?.code, 'external_scanner_report_unreadable');
  } finally {
    await cleanup(dir);
  }
});

test('a trusted scanner selection cannot resolve into the snapshot or the original tree', { skip: process.platform === 'win32' }, async () => {
  const dir = await makeTempDir();
  try {
    const scanner = await writeScanner(dir, `process.stdout.write(${JSON.stringify(JSON.stringify(REPORT))});`);
    const failure = assertFailure(await loadExternalScan({ root: dir, bin: scanner }));
    assert.equal(failure.errors[0]?.code, 'external_scanner_failed');

    const alias = join(dir, 'alias');
    await symlink(dir, alias, 'dir');
    const original = assertFailure(await loadExternalScan({ root: ROOT, candidateRoot: alias, bin: scanner }));
    assert.equal(original.errors[0]?.code, 'external_scanner_failed');
  } finally {
    await cleanup(dir);
  }
});
