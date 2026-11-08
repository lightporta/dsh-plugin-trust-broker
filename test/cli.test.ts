import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import {
  cleanup,
  fixturePath,
  makeTempDir,
  readJsonLines,
  writeTree,
} from './helpers.ts';
import { runCli } from '../src/cli/main.ts';
import type { CliIO } from '../src/cli/main.ts';
import { anchorStorePath } from '../src/core/anchor-store.ts';
import { readJsonlFile } from '../src/core/jsonl.ts';

const UNSTATED = fixturePath('decision', 'unstated');
const UNDERSTATED = fixturePath('decision', 'understated');
const CONSISTENT = fixturePath('decision', 'consistent');

interface MemoryIO {
  io: CliIO;
  out: string[];
  err: string[];
  outText(): string;
  errText(): string;
}

function createMemoryIO(options: { tty?: boolean; answers?: string[] } = {}): MemoryIO {
  const out: string[] = [];
  const err: string[] = [];
  const answers = [...(options.answers ?? [])];
  const io: CliIO = {
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    isTTY: options.tty === true,
    env: { ...process.env, DSH_HOME: '/tmp/tb-test-dsh-home-not-used' },
    async prompt() {
      return answers.shift() ?? '';
    },
  };
  return {
    io,
    out,
    err,
    outText: () => out.join(''),
    errText: () => err.join(''),
  };
}

function parseOutput(text: string): {
  decision: Record<string, any>;
  admission: Record<string, any> | null;
} {
  return JSON.parse(text) as {
    decision: Record<string, any>;
    admission: Record<string, any> | null;
  };
}

test('version and help commands', async () => {
  const versionIO = createMemoryIO();
  assert.equal(await runCli(['version'], versionIO.io), 0);
  assert.match(versionIO.outText(), /dsh-plugin-trust-broker 0\.2\.0/);

  const helpIO = createMemoryIO();
  assert.equal(await runCli(['help'], helpIO.io), 0);
  assert.match(helpIO.outText(), /安装前审查/);
  assert.match(helpIO.outText(), /退出码/);

  const unknownIO = createMemoryIO();
  assert.equal(await runCli(['nope'], unknownIO.io), 1);
  assert.match(unknownIO.errText(), /未知命令/);
});

test('review --json on an unstated plugin: exit 2, confirmation shown, no anchor written', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const memory = createMemoryIO();
    const code = await runCli(
      ['review', UNSTATED, '--json', '--no-external-scanner', '--store-dir', storeDir],
      memory.io,
    );
    assert.equal(code, 2);
    const output = parseOutput(memory.outText());
    assert.equal(output.admission, null);
    assert.equal(output.decision.action, 'confirm');
    assert.equal(output.decision.declaration.status, 'unstated');
    assert.deepEqual(
      (output.decision.confirmations_required as Array<{ code: string }>).map((item) => item.code),
      ['unstated_capabilities'],
    );
    assert.match(output.decision.content_hash as string, /^sha256:[0-9a-f]{64}$/);
    assert.equal(existsSync(anchorStorePath(storeDir)), false);
  } finally {
    await cleanup(storeDir);
  }
});

test('review --json on a consistent plugin: exit 0, no forced confirmation', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const memory = createMemoryIO();
    const code = await runCli(
      ['review', CONSISTENT, '--json', '--no-external-scanner', '--store-dir', storeDir],
      memory.io,
    );
    assert.equal(code, 0);
    const output = parseOutput(memory.outText());
    assert.equal(output.decision.action, 'proceed');
    assert.deepEqual(output.decision.confirmations_required, []);
  } finally {
    await cleanup(storeDir);
  }
});

test('review --json with --accept-hash writes exactly one anchor and a decision journal line', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const review = createMemoryIO();
    await runCli(
      ['review', UNSTATED, '--json', '--no-external-scanner', '--store-dir', storeDir],
      review.io,
    );
    const decision = parseOutput(review.outText()).decision;
    const contentHash = decision.content_hash as string;

    const accept = createMemoryIO();
    const code = await runCli(
      [
        'review',
        UNSTATED,
        '--json',
        '--no-external-scanner',
        '--store-dir',
        storeDir,
        '--acknowledge-unstated',
        '--accept-hash',
        contentHash,
      ],
      accept.io,
    );
    assert.equal(code, 0);
    const output = parseOutput(accept.outText());
    assert.equal(output.admission?.accepted, true);
    assert.equal(output.admission?.anchor?.content_hash, contentHash);
    assert.equal(output.admission?.anchor?.confirmed_by, 'user');

    const anchorLines = readJsonLines(anchorStorePath(storeDir));
    assert.equal(anchorLines.length, 1);
    const anchor = anchorLines[0] as Record<string, any>;
    assert.equal(anchor.plugin_id, 'unstated-plugin');
    assert.equal(anchor.version, '2.3.4');
    assert.equal(anchor.content_hash, contentHash);
    assert.equal(anchor.schema_version, 1);
    assert.match(anchor.decision_digest as string, /^sha256:[0-9a-f]{64}$/);

    const decisions = readJsonLines(join(storeDir, 'decisions.jsonl'));
    const acceptedRecord = decisions.find(
      (entry) => (entry as Record<string, any>).accepted === true,
    ) as Record<string, any> | undefined;
    assert.ok(acceptedRecord !== undefined);
    assert.equal(acceptedRecord?.['plugin_id'], 'unstated-plugin');
    assert.equal(acceptedRecord?.['anchor_version'], '2.3.4');
  } finally {
    await cleanup(storeDir);
  }
});

test('accepting a wrong content hash is rejected as content_changed', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const memory = createMemoryIO();
    const code = await runCli(
      [
        'review',
        UNSTATED,
        '--json',
        '--no-external-scanner',
        '--store-dir',
        storeDir,
        '--acknowledge-unstated',
        '--accept-hash',
        `sha256:${'0'.repeat(64)}`,
      ],
      memory.io,
    );
    assert.equal(code, 2);
    const output = parseOutput(memory.outText());
    assert.equal(output.admission?.accepted, false);
    assert.equal(output.admission?.reason, 'content_changed');
    assert.equal(existsSync(anchorStorePath(storeDir)), false);
  } finally {
    await cleanup(storeDir);
  }
});

test('JSON accept without the required acknowledgement is rejected by the gate', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const review = createMemoryIO();
    await runCli(
      ['review', UNDERSTATED, '--json', '--no-external-scanner', '--store-dir', storeDir],
      review.io,
    );
    const decision = parseOutput(review.outText()).decision;

    const accept = createMemoryIO();
    const code = await runCli(
      [
        'review',
        UNDERSTATED,
        '--json',
        '--no-external-scanner',
        '--store-dir',
        storeDir,
        '--accept-hash',
        decision.content_hash as string,
      ],
      accept.io,
    );
    assert.equal(code, 2);
    const output = parseOutput(accept.outText());
    assert.equal(output.admission?.accepted, false);
    assert.equal(output.admission?.reason, 'acknowledgement_missing');
  } finally {
    await cleanup(storeDir);
  }
});

test('non-interactive review without acknowledgements exits 2 and lists the required flags', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const memory = createMemoryIO();
    const code = await runCli(
      ['review', UNDERSTATED, '--no-external-scanner', '--store-dir', storeDir, '--non-interactive'],
      memory.io,
    );
    assert.equal(code, 2);
    assert.match(memory.outText(), /--acknowledge-new-capability/);
    assert.match(memory.outText(), /需要确认/);
  } finally {
    await cleanup(storeDir);
  }
});

test('confirm command requires --accept-hash in non-interactive mode', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const memory = createMemoryIO();
    const code = await runCli(
      ['confirm', UNSTATED, '--no-external-scanner', '--store-dir', storeDir],
      memory.io,
    );
    assert.equal(code, 1);
    assert.match(memory.errText(), /--accept-hash/);
  } finally {
    await cleanup(storeDir);
  }
});

test('interactive review: token acknowledgement plus anchor confirmation writes the anchor', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const memory = createMemoryIO({ tty: true, answers: ['我已知悉', 'y'] });
    const code = await runCli(
      ['review', UNSTATED, '--no-external-scanner', '--store-dir', storeDir],
      memory.io,
    );
    assert.equal(code, 0);
    assert.match(memory.outText(), /已写入信任锚点/);
    assert.equal(readJsonLines(anchorStorePath(storeDir)).length, 1);
  } finally {
    await cleanup(storeDir);
  }
});

test('interactive review aborts when the acknowledgement token is wrong', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const memory = createMemoryIO({ tty: true, answers: ['no'] });
    const code = await runCli(
      ['review', UNSTATED, '--no-external-scanner', '--store-dir', storeDir],
      memory.io,
    );
    assert.equal(code, 2);
    assert.match(memory.outText(), /已中止/);
    assert.equal(existsSync(anchorStorePath(storeDir)), false);
  } finally {
    await cleanup(storeDir);
  }
});

test('candidate control sequences are visible as data before interactive approval', async () => {
  const root = await makeTempDir('tb-terminal-candidate-');
  const storeDir = await makeTempDir('tb-cli-store-');
  const spoof = '\u001b[2J\u001b[H\n伪造提示\u202e';
  try {
    await writeTree(root, {
      'package.json': JSON.stringify({ name: 'test-package', version: `1.0.0${spoof}` }),
      'index.js': 'export const apply = () => 0;\n',
    });
    const memory = createMemoryIO({ tty: true });
    memory.io.env = { NO_COLOR: '1' };
    memory.io.prompt = async () => {
      assert.match(memory.outText(), /内容哈希\s+sha256:[0-9a-f]{64}/);
      assert.match(memory.outText(), /\\u001b\[2J\\u001b\[H\\u000a伪造提示\\u202e/);
      assert.doesNotMatch(memory.outText(), /[\u001b\u202e]/);
      return 'no';
    };
    assert.equal(await runCli(['review', root, '--store-dir', storeDir], memory.io), 2);
    assert.equal(existsSync(anchorStorePath(storeDir)), false);
  } finally {
    await cleanup(root);
    await cleanup(storeDir);
  }
});

test('anchors command lists persisted anchors as JSON', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const review = createMemoryIO();
    await runCli(
      ['review', CONSISTENT, '--json', '--no-external-scanner', '--store-dir', storeDir],
      review.io,
    );
    const decision = parseOutput(review.outText()).decision;
    const accept = createMemoryIO();
    const acceptCode = await runCli(
      [
        'review',
        CONSISTENT,
        '--json',
        '--no-external-scanner',
        '--store-dir',
        storeDir,
        '--accept-hash',
        decision.content_hash as string,
      ],
      accept.io,
    );
    assert.equal(acceptCode, 0);

    const list = createMemoryIO();
    const code = await runCli(['anchors', '--json', '--store-dir', storeDir], list.io);
    assert.equal(code, 0);
    const payload = JSON.parse(list.outText()) as { anchors: Array<Record<string, any>> };
    assert.equal(payload.anchors.length, 1);
    assert.equal(payload.anchors[0]?.['plugin_id'], 'consistent-plugin');
    assert.equal(payload.anchors[0]?.['content_hash'], decision.content_hash);
  } finally {
    await cleanup(storeDir);
  }
});

test('scan command exposes raw detection for debugging', async () => {
  const memory = createMemoryIO();
  const code = await runCli(
    ['scan', CONSISTENT, '--json', '--no-external-scanner'],
    memory.io,
  );
  assert.equal(code, 0);
  const payload = JSON.parse(memory.outText()) as Record<string, any>;
  assert.equal(payload['declaration']?.status, 'declared');
  assert.ok((payload['detection']?.heuristic_facts as unknown[]).length >= 2);
  assert.match(payload['content_hash']?.hash as string, /^sha256:[0-9a-f]{64}$/);
});

test('audit --verify accepts a well-formed JSONL and reports malformed records', async () => {
  const root = await makeTempDir('tb-cli-audit-');
  try {
    const goodLine = JSON.stringify({
      schema_version: 1,
      event: 'tool_call',
      seq: 1,
      id: 'evt-1',
      ts: '2026-01-01T00:00:00.000Z',
    });
    const goodFile = join(root, 'good.jsonl');
    await writeTree(root, { 'good.jsonl': `${goodLine}\n` });
    const good = createMemoryIO();
    assert.equal(
      await runCli(['audit', '--verify', '--json', '--audit-file', goodFile], good.io),
      0,
    );

    const badFile = join(root, 'bad.jsonl');
    await writeTree(root, { 'bad.jsonl': `${goodLine}\n{"event":"tool_call"}\nnot-json\n` });
    const bad = createMemoryIO();
    assert.equal(
      await runCli(['audit', '--verify', '--json', '--audit-file', badFile], bad.io),
      1,
    );
    const payload = JSON.parse(bad.outText()) as { problems: string[] };
    assert.ok(payload.problems.length >= 2);
  } finally {
    await cleanup(root);
  }
});

test('unscannable plugin exits 3 and source mismatches block by default', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const unscannable = createMemoryIO();
    const code = await runCli(
      [
        'review',
        fixturePath('manifest', 'no-package'),
        '--json',
        '--no-external-scanner',
        '--store-dir',
        storeDir,
      ],
      unscannable.io,
    );
    assert.equal(code, 3);
    assert.equal(parseOutput(unscannable.outText()).decision.action, 'block_for_review');

    const mismatch = createMemoryIO();
    const mismatchCode = await runCli(
      [
        'review',
        CONSISTENT,
        '--json',
        '--no-external-scanner',
        '--store-dir',
        storeDir,
        '--expected-hash',
        `sha256:${'f'.repeat(64)}`,
      ],
      mismatch.io,
    );
    assert.equal(mismatchCode, 3);
    assert.equal(
      parseOutput(mismatch.outText()).decision.source_trust.kind,
      'hash_mismatch',
    );
  } finally {
    await cleanup(storeDir);
  }
});

test('policy file can waive forced confirmation and is reflected in the decision', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  const policyRoot = await makeTempDir('tb-cli-policy-');
  try {
    await writeTree(policyRoot, {
      'policy.json': JSON.stringify({ confirm_on_new_capability: false }),
    });
    const memory = createMemoryIO();
    const code = await runCli(
      [
        'review',
        UNDERSTATED,
        '--json',
        '--no-external-scanner',
        '--store-dir',
        storeDir,
        '--policy',
        join(policyRoot, 'policy.json'),
      ],
      memory.io,
    );
    assert.equal(code, 0);
    const decision = parseOutput(memory.outText()).decision;
    assert.equal(decision.action, 'proceed');
    assert.equal(decision.policy.confirm_on_new_capability, false);
  } finally {
    await cleanup(storeDir);
    await cleanup(policyRoot);
  }
});

test('audit tail defaults read the store audit file', async () => {
  const storeDir = await makeTempDir('tb-cli-store-');
  try {
    const auditFile = join(storeDir, 'audit.jsonl');
    await writeTree(storeDir, {
      'audit.jsonl': `${JSON.stringify({
        schema_version: 1,
        event: 'tool_call',
        seq: 7,
        id: 'evt-7',
        ts: '2026-01-02T00:00:00.000Z',
        tool: 'bash',
        scope: 'unattributed',
      })}\n`,
    });
    const memory = createMemoryIO();
    assert.equal(await runCli(['audit', '--lines', '5', '--store-dir', storeDir], memory.io), 0);
    assert.match(memory.outText(), /tool_call/);
    assert.match(memory.outText(), /seq|7/);
    const parsed = readJsonlFile(auditFile);
    assert.equal(parsed.errors.length, 0);
    assert.equal(parsed.records.length, 1);
  } finally {
    await cleanup(storeDir);
  }
});
