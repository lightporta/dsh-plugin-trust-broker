/**
 * Host-side tests for the pre-install review service.
 *
 * Coverage:
 * - candidate spec parsing (local path wins, npm, git, tarball, invalid inputs)
 * - local review + confirm writing exactly one anchor
 * - review cache: unknown/expired reviews, double confirm, LRU eviction
 * - unstated plugin confirmation queue, unscannable decisions never anchored
 * - npm flow against a local `node:http` fake registry: version/range/tag
 *   resolution, tarball integrity verification, `package/` stripping
 * - tarball safety: traversal, absolute paths, symlinks, hardlinks, devices
 * - git clone (skipped when `git` is unavailable)
 * - the JSON HTTP handler (health/review/confirm, 400/404/405, body cap)
 * - `formatAgentGate` approval prompts and the empty-spec allow path
 *
 * All scratch data lives under uniquely created temp directories; no network
 * access beyond loopback and no dependency outside `node:test`/Node built-ins.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdir, readFile, readdir, stat, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

import {
  AGENT_GATE_REASON_LIMIT,
  buildAgentGateFailure,
  sanitizeUntrustedText,
} from '../src/host/summary.ts';
import { createTrustHostServices, type TrustHostServices } from '../src/host/service.ts';
import {
  parseSemver,
  parseSemverRange,
  resolveNpmVersion,
  satisfiesSemverRange,
} from '../src/host/materialize.ts';
import { parseCandidateSpec } from '../src/host/spec.ts';
import { TRUST_BROKER_VERSION } from '../src/version.ts';
import { cleanup, makeTempDir, packageJsonFixture, readJsonLines, writeTree } from './helpers.ts';

/* ------------------------------------------------------------------------- */
/* Test helpers                                                               */
/* ------------------------------------------------------------------------- */

interface Sandbox {
  root: string;
  storeDir: string;
  anchorsFile: string;
  services: TrustHostServices;
  dispose(): Promise<void>;
}

async function createSandbox(overrides: { now?: () => Date } = {}): Promise<Sandbox> {
  const root = await makeTempDir('trust-broker-host-');
  const storeDir = join(root, 'store');
  const anchorsFile = join(storeDir, 'anchors.jsonl');
  const services = createTrustHostServices({
    storeDir,
    anchorsFile,
    ...(overrides.now !== undefined ? { now: overrides.now } : {}),
  });
  return {
    root,
    storeDir,
    anchorsFile,
    services,
    async dispose() {
      services.dispose();
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 60));
      await cleanup(root);
    },
  };
}

/** Register cleanup for a sandbox at the end of one test. */
function sandboxFor(t: TestContext): Promise<Sandbox> {
  return createSandbox().then((sandbox) => {
    t.after(async () => {
      await sandbox.dispose();
    });
    return sandbox;
  });
}

async function writeDeclaredPlugin(root: string, overrides: Record<string, unknown> = {}): Promise<void> {
  await writeTree(root, {
    'package.json': `${JSON.stringify(
      packageJsonFixture({
        name: 'declared-plugin',
        version: '1.0.0',
        description: 'Minimal declared plugin fixture.',
        dsh: { capabilities: { network: { fetch: true } } },
        ...overrides,
      }),
      null,
      2,
    )}\n`,
    'lib/index.js': 'export function ping() { return 1; }\n',
  });
}

async function writeRiskyPlugin(root: string): Promise<void> {
  await writeTree(root, {
    'package.json': `${JSON.stringify(
      packageJsonFixture({
        name: '@scope/risky-plugin',
        version: '2.3.4',
        scripts: { postinstall: 'node setup.js' },
        dsh: { capabilities: { network: { fetch: true } } },
      }),
      null,
      2,
    )}\n`,
    'lib/index.js':
      "import { spawn } from 'node:child_process';\n" +
      "import { writeFileSync } from 'node:fs';\n" +
      'export function run(command) {\n' +
      '  spawn(command);\n' +
      "  writeFileSync('/tmp/risky-out', 'x');\n" +
      "  return fetch('https://example.com');\n" +
      '}\n',
  });
}

async function writeUnstatedPlugin(root: string): Promise<void> {
  await writeTree(root, {
    'package.json': `${JSON.stringify(
      packageJsonFixture({ name: 'unstated-plugin', version: '0.4.0' }),
      null,
      2,
    )}\n`,
    'lib/index.js':
      "import { writeFileSync } from 'node:fs';\n" +
      'export function save(value) {\n' +
      "  writeFileSync('/tmp/unstated-out', value);\n" +
      '}\n',
  });
}

/** Count review candidate directories under `<storeDir>/candidates`. */
async function candidateDirs(storeDir: string): Promise<string[]> {
  try {
    const entries = await readdir(join(storeDir, 'candidates'));
    return entries.filter((entry) => entry.startsWith('review-'));
  } catch {
    return [];
  }
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

/* ---------------------------------- tar ---------------------------------- */

function writeOctalField(header: Buffer, offset: number, length: number, value: number): void {
  header.write(value.toString(8).padStart(length - 1, '0'), offset, length - 1, 'ascii');
  header[offset + length - 1] = 0;
}

interface TarFixtureEntry {
  name: string;
  content?: string | Buffer;
  /** ustar typeflag; defaults to regular file `'0'`. */
  type?: string;
  linkname?: string;
}

function tarEntry(entry: TarFixtureEntry): Buffer {
  const type = entry.type ?? '0';
  const data = Buffer.isBuffer(entry.content)
    ? entry.content
    : Buffer.from(entry.content ?? '', 'utf8');
  const size = type === '5' ? 0 : data.byteLength;
  const header = Buffer.alloc(512, 0);
  const nameBytes = Buffer.from(entry.name, 'utf8');
  nameBytes.copy(header, 0, 0, Math.min(nameBytes.byteLength, 100));
  writeOctalField(header, 100, 8, 0o644);
  writeOctalField(header, 108, 8, 0);
  writeOctalField(header, 116, 8, 0);
  writeOctalField(header, 124, 12, size);
  writeOctalField(header, 136, 12, Math.floor(Date.now() / 1000));
  header.write('        ', 148, 'ascii');
  header.write(type, 156, 'ascii');
  if (entry.linkname !== undefined) header.write(entry.linkname, 157, 'ascii');
  header.write('ustar\0', 257, 'ascii');
  header.write('00', 263, 'ascii');
  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  const padded = Buffer.alloc(Math.ceil(size / 512) * 512, 0);
  data.copy(padded);
  return Buffer.concat([header, padded]);
}

function paxRecord(key: string, value: string): string {
  const body = `${key}=${value}\n`;
  let length = Buffer.byteLength(body, 'utf8') + 3;
  for (;;) {
    const record = `${length} ${body}`;
    const actual = Buffer.byteLength(record, 'utf8');
    if (actual === length) return record;
    length = actual;
  }
}

function makeTarball(entries: TarFixtureEntry[]): Buffer {
  const blocks = entries.map(tarEntry);
  return gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024, 0)]));
}

function declaredPackageJson(name: string, version: string): string {
  return `${JSON.stringify(
    {
      name,
      version,
      type: 'module',
      dsh: { capabilities: { network: { fetch: true } } },
    },
    null,
    2,
  )}\n`;
}

/* ------------------------------- registry -------------------------------- */

interface RegistryVersion {
  tarball: Buffer;
  /** `null` omits integrity; `undefined` computes a correct sha512. */
  integrity?: string | null;
}

interface RegistryConfig {
  packageName: string;
  versions: Record<string, RegistryVersion>;
  latest?: string;
}

interface FakeRegistry {
  base: string;
  requests: Array<{ path: string; accept: string }>;
  close(): Promise<void>;
}

function sha512Base64(bytes: Uint8Array): string {
  return createHash('sha512').update(bytes).digest('base64');
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Minimal npm registry: packument + tarballs over loopback HTTP. */
async function startFakeRegistry(config: RegistryConfig): Promise<FakeRegistry> {
  const requests: Array<{ path: string; accept: string }> = [];
  const server = createServer((req, res) => {
    const origin = `http://${req.headers.host ?? '127.0.0.1'}`;
    const url = new URL(req.url ?? '/', origin);
    requests.push({ path: url.pathname, accept: req.headers.accept ?? '' });
    const decodedPath = decodeURIComponent(url.pathname);
    if (decodedPath === `/${config.packageName}`) {
      const versions: Record<string, unknown> = {};
      for (const [version, entry] of Object.entries(config.versions)) {
        versions[version] = {
          name: config.packageName,
          version,
          dist: {
            tarball: `${origin}/-/tarball/${version}.tgz`,
            ...(entry.integrity === null
              ? {}
              : { integrity: entry.integrity ?? `sha512-${sha512Base64(entry.tarball)}` }),
          },
        };
      }
      const latest = config.latest ?? Object.keys(config.versions).sort().pop() ?? '0.0.0';
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          name: config.packageName,
          'dist-tags': { latest },
          versions,
        }),
      );
      return;
    }
    const tarballMatch = /^\/-\/tarball\/(.+)\.tgz$/.exec(url.pathname);
    if (tarballMatch !== null) {
      const version = tarballMatch[1] ?? '';
      const entry = config.versions[version];
      if (entry === undefined) {
        res.statusCode = 404;
        res.end('{}');
        return;
      }
      res.setHeader('content-type', 'application/octet-stream');
      res.end(entry.tarball);
      return;
    }
    res.statusCode = 404;
    res.end('{}');
  });
  await new Promise<void>((resolvePromise) => {
    server.listen(0, '127.0.0.1', () => resolvePromise());
  });
  const address = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>((resolvePromise) => server.close(() => resolvePromise())),
  };
}

function registryTarball(name: string, version: string): Buffer {
  return makeTarball([
    { name: 'package/', type: '5' },
    { name: 'package/package.json', content: declaredPackageJson(name, version) },
    { name: 'package/index.js', content: 'export const value = 42;\n' },
  ]);
}

/* ------------------------------ HTTP helpers ------------------------------ */

interface MockResponse {
  statusCode: number;
  headers: Record<string, string | number>;
  body: string;
  headersSent: boolean;
  writableEnded: boolean;
  setHeader(name: string, value: string | number): void;
  end(chunk?: unknown): void;
}

async function invokeHandler(
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>,
  request: { method: string; url: string; body?: string },
): Promise<MockResponse> {
  const chunks = request.body === undefined ? [] : [Buffer.from(request.body, 'utf8')];
  const req = Readable.from(chunks) as unknown as IncomingMessage & { method?: string; url?: string };
  req.method = request.method;
  req.url = request.url;
  const response: MockResponse = {
    statusCode: 0,
    headers: {},
    body: '',
    headersSent: false,
    writableEnded: false,
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    end(chunk) {
      this.writableEnded = true;
      this.body =
        typeof chunk === 'string'
          ? chunk
          : Buffer.isBuffer(chunk)
            ? chunk.toString('utf8')
            : chunk === undefined
              ? ''
              : String(chunk);
    },
  };
  await handler(req, response as unknown as ServerResponse);
  return response;
}

function parseJsonBody<T>(response: MockResponse): T {
  assert.match(String(response.headers['content-type']), /application\/json/);
  return JSON.parse(response.body) as T;
}

/* ------------------------------------------------------------------------- */
/* Spec parsing                                                              */
/* ------------------------------------------------------------------------- */

test('parses local paths, file: URIs, npm, git and tarball specs', async (t) => {
  const root = await makeTempDir('trust-broker-spec-');
  t.after(async () => {
    await cleanup(root);
  });
  const pluginDir = join(root, 'spec-plugin');
  await writeDeclaredPlugin(pluginDir);
  await writeFile(join(root, 'archive.tgz'), makeTarball([{ name: 'package/package.json', content: '{}' }]));

  // Local paths (absolute, relative, file: URI) are detected first.
  const absolute = await parseCandidateSpec(pluginDir);
  assert.equal(absolute.kind, 'local');
  assert.equal(absolute.path, pluginDir);

  const relative = await parseCandidateSpec('spec-plugin', { cwd: root });
  assert.equal(relative.kind, 'local');
  assert.equal(relative.path, pluginDir);

  const fileUri = await parseCandidateSpec(pathToFileURL(pluginDir).href);
  assert.equal(fileUri.kind, 'local');
  assert.equal(fileUri.path, pluginDir);

  // An existing path named like a package wins over the npm interpretation.
  const shadowDir = join(root, 'left-pad');
  await writeDeclaredPlugin(shadowDir, { name: 'left-pad-shadow' });
  const shadow = await parseCandidateSpec('left-pad', { cwd: root });
  assert.equal(shadow.kind, 'local');
  assert.equal(shadow.path, shadowDir);

  // Local tarballs.
  const localArchive = await parseCandidateSpec(join(root, 'archive.tgz'));
  assert.equal(localArchive.kind, 'tarball');
  assert.equal(localArchive.path, join(root, 'archive.tgz'));

  // npm.
  assert.deepEqual(await parseCandidateSpec('dsh-plugin-whale-pet'), {
    kind: 'npm',
    raw: 'dsh-plugin-whale-pet',
    name: 'dsh-plugin-whale-pet',
  });
  const scoped = await parseCandidateSpec('@scope/pkg@^1.2.0');
  assert.equal(scoped.kind, 'npm');
  assert.equal(scoped.name, '@scope/pkg');
  assert.equal(scoped.range, '^1.2.0');
  const tagged = await parseCandidateSpec('pkg@next');
  assert.equal(tagged.range, 'next');

  // git forms all normalize to a clone URL.
  const gitPlus = await parseCandidateSpec('git+https://github.com/owner/repo.git');
  assert.equal(gitPlus.kind, 'git');
  assert.equal(gitPlus.git_url, 'https://github.com/owner/repo.git');
  const scp = await parseCandidateSpec('git@github.com:owner/repo.git');
  assert.equal(scp.kind, 'git');
  assert.equal(scp.git_url, 'git@github.com:owner/repo.git');
  const shorthand = await parseCandidateSpec('owner/repo');
  assert.equal(shorthand.kind, 'git');
  assert.equal(shorthand.git_url, 'https://github.com/owner/repo.git');
  const shorthandRef = await parseCandidateSpec('owner/repo#v1.2.3');
  assert.equal(shorthandRef.git_ref, 'v1.2.3');
  const githubPrefix = await parseCandidateSpec('github:owner/repo');
  assert.equal(githubPrefix.git_url, 'https://github.com/owner/repo.git');
  const httpsGit = await parseCandidateSpec('https://example.com/owner/repo.git');
  assert.equal(httpsGit.kind, 'git');

  // Remote tarballs.
  const remoteArchive = await parseCandidateSpec('https://example.com/pkg.tar.gz?token=abc');
  assert.equal(remoteArchive.kind, 'tarball');
});

test('rejects empty, ambiguous and missing specs with invalid_spec', async (t) => {
  const root = await makeTempDir('trust-broker-spec-bad-');
  t.after(async () => {
    await cleanup(root);
  });
  await writeFile(join(root, 'not-a-tarball.txt'), 'hello');
  const expectInvalid = async (spec: string): Promise<void> => {
    await assert.rejects(parseCandidateSpec(spec, { cwd: root }), (error: unknown) => {
      assert.equal((error as { code?: string }).code, 'invalid_spec');
      return true;
    });
  };
  await expectInvalid('');
  await expectInvalid('   ');
  await expectInvalid('./does-not-exist');
  await expectInvalid('not-a-tarball.txt');
  await expectInvalid('https://example.com/some/page');
  await expectInvalid('two words');
  await expectInvalid('@broken-scope');
  await expectInvalid('owner/repo#bad ref');
  await expectInvalid('owner/repo#--upload-pack=evil');
  await expectInvalid(`bad\u0000spec`);

  // Symlinked local roots are refused (the decision layer requires real trees).
  const realDir = join(root, 'real-plugin');
  await writeDeclaredPlugin(realDir);
  const linkDir = join(root, 'linked-plugin');
  try {
    await symlink(realDir, linkDir);
    await assert.rejects(parseCandidateSpec(linkDir), (error: unknown) => {
      assert.equal((error as { code?: string }).code, 'invalid_spec');
      return true;
    });
  } catch {
    // Symlink creation is unavailable (or privileges differ): skip this check.
  }
});

/* ------------------------------------------------------------------------- */
/* Local review and anchor confirmation                                      */
/* ------------------------------------------------------------------------- */

test('reviews a local directory and confirm writes exactly one anchor', async (t) => {
  const sandbox = await sandboxFor(t);
  const pluginDir = join(sandbox.root, 'plugins', 'declared-plugin');
  await writeDeclaredPlugin(pluginDir, { version: '3.1.4' });

  const response = await sandbox.services.review(pluginDir);
  assert.equal(response.ok, true);
  if (!response.ok) return;
  const { review } = response;
  assert.equal(review.resolved.kind, 'local');
  assert.equal(review.resolved.install_spec, pluginDir);
  assert.equal(review.resolved.name, 'declared-plugin');
  assert.equal(review.resolved.version, '3.1.4');
  assert.equal(review.decision.plugin.id, 'declared-plugin');
  assert.equal(review.decision.status, 'scanned');
  assert.equal(review.decision.action, 'proceed');
  assert.equal(review.decision.coverage_complete, true);
  assert.match(review.decision.content_hash ?? '', /^sha256:[0-9a-f]{64}$/);
  // The wire payload never exposes a temporary candidate path.
  assert.ok(!JSON.stringify(review).includes(join(sandbox.storeDir, 'candidates')));

  const confirmed = await sandbox.services.confirm({
    review_id: review.review_id,
    acknowledgements: [],
  });
  assert.equal(confirmed.ok, true);
  if (!confirmed.ok) return;
  assert.equal(confirmed.anchor.plugin_id, 'declared-plugin');
  assert.equal(confirmed.anchor.version, '3.1.4');
  assert.equal(confirmed.anchor.content_hash, review.decision.content_hash);

  const anchors = readJsonLines(sandbox.anchorsFile) as Array<Record<string, unknown>>;
  assert.equal(anchors.length, 1);
  assert.equal(anchors[0]?.plugin_id, 'declared-plugin');
  assert.equal(anchors[0]?.content_hash, review.decision.content_hash);
  assert.equal(anchors[0]?.confirmed_by, 'user');

  // Review ids are single-use: a second confirm must not append a second anchor.
  const duplicate = await sandbox.services.confirm({
    review_id: review.review_id,
    acknowledgements: [],
  });
  assert.equal(duplicate.ok, false);
  if (!duplicate.ok) assert.equal(duplicate.error.code, 'review_expired');
  assert.equal((readJsonLines(sandbox.anchorsFile) as unknown[]).length, 1);
});

test('unknown and expired reviews are rejected with review_expired', async (t) => {
  let current = new Date('2026-01-01T00:00:00.000Z');
  const sandbox = await createSandbox({ now: () => new Date(current.getTime()) });
  t.after(async () => {
    await sandbox.dispose();
  });
  const pluginDir = join(sandbox.root, 'plugins', 'declared-plugin');
  await writeDeclaredPlugin(pluginDir);

  const unknown = await sandbox.services.confirm({ review_id: 'no-such-review', acknowledgements: [] });
  assert.equal(unknown.ok, false);
  if (!unknown.ok) assert.equal(unknown.error.code, 'review_expired');

  const response = await sandbox.services.review(pluginDir);
  assert.equal(response.ok, true);
  if (!response.ok) return;
  assert.equal(response.review.created_at, '2026-01-01T00:00:00.000Z');
  assert.equal(response.review.expires_at, '2026-01-01T00:30:00.000Z');

  // Advance past the 30-minute review TTL.
  current = new Date(current.getTime() + 31 * 60 * 1000);
  const expired = await sandbox.services.confirm({
    review_id: response.review.review_id,
    acknowledgements: [],
  });
  assert.equal(expired.ok, false);
  if (!expired.ok) assert.equal(expired.error.code, 'review_expired');
  assert.equal(await fileExists(sandbox.anchorsFile), false);
});

test('unstated plugins require every acknowledgement before anchoring', async (t) => {
  const sandbox = await sandboxFor(t);
  const pluginDir = join(sandbox.root, 'plugins', 'unstated-plugin');
  await writeUnstatedPlugin(pluginDir);

  const response = await sandbox.services.review(pluginDir);
  assert.equal(response.ok, true);
  if (!response.ok) return;
  const requirements = response.review.decision.confirmations_required;
  const codes = requirements.map((requirement) => requirement.code);
  assert.ok(codes.includes('unstated_capabilities'), `expected unstated ack, got ${codes.join(',')}`);
  assert.equal(response.review.decision.action, 'confirm');

  const missing = await sandbox.services.confirm({
    review_id: response.review.review_id,
    acknowledgements: [],
  });
  assert.equal(missing.ok, false);
  if (!missing.ok) assert.equal(missing.error.code, 'acknowledgement_missing');
  assert.equal(await fileExists(sandbox.anchorsFile), false);

  // Partial acknowledgements still fail while requirements remain.
  if (codes.length > 1) {
    const partial = await sandbox.services.confirm({
      review_id: response.review.review_id,
      acknowledgements: codes.slice(0, 1),
    });
    assert.equal(partial.ok, false);
    if (!partial.ok) assert.equal(partial.error.code, 'acknowledgement_missing');
  }

  const accepted = await sandbox.services.confirm({
    review_id: response.review.review_id,
    acknowledgements: codes,
  });
  assert.equal(accepted.ok, true);
  assert.equal((readJsonLines(sandbox.anchorsFile) as unknown[]).length, 1);
});

test('an unscannable decision is shown but never anchored', async (t) => {
  const sandbox = await sandboxFor(t);
  const emptyDir = join(sandbox.root, 'empty-candidate');
  await mkdir(emptyDir, { recursive: true });

  const response = await sandbox.services.review(emptyDir);
  assert.equal(response.ok, true, 'acquisition succeeded; the decision itself is unscannable');
  if (!response.ok) return;
  assert.equal(response.review.decision.status, 'unscannable');
  assert.equal(response.review.decision.content_hash, null);
  assert.equal(response.review.decision.action, 'block_for_review');

  const rejected = await sandbox.services.confirm({
    review_id: response.review.review_id,
    acknowledgements: [],
  });
  assert.equal(rejected.ok, false);
  if (!rejected.ok) assert.equal(rejected.error.code, 'blocked_for_review');
  assert.equal(await fileExists(sandbox.anchorsFile), false, 'no anchor may be fabricated');
});

test('confirm rejects a candidate that changed after the review (TOCTOU)', async (t) => {
  const sandbox = await sandboxFor(t);
  const pluginDir = join(sandbox.root, 'plugins', 'declared-plugin');
  await writeDeclaredPlugin(pluginDir);

  const response = await sandbox.services.review(pluginDir);
  assert.equal(response.ok, true);
  if (!response.ok) return;

  // The local candidate is reviewed in place: mutate it before confirming.
  await writeFile(join(pluginDir, 'lib', 'index.js'), 'export function ping() { return 2; }\n');
  const rejected = await sandbox.services.confirm({
    review_id: response.review.review_id,
    acknowledgements: [],
  });
  assert.equal(rejected.ok, false);
  if (!rejected.ok) assert.equal(rejected.error.code, 'content_changed');
  assert.equal(await fileExists(sandbox.anchorsFile), false);
});

test('review cache evicts the least recently used review beyond 32 entries', async (t) => {
  const sandbox = await sandboxFor(t);
  const pluginDir = join(sandbox.root, 'plugins', 'declared-plugin');
  await writeDeclaredPlugin(pluginDir);

  const reviewIds: string[] = [];
  for (let index = 0; index < 33; index += 1) {
    const response = await sandbox.services.review(pluginDir);
    assert.equal(response.ok, true);
    if (response.ok) reviewIds.push(response.review.review_id);
  }
  const first = reviewIds[0];
  const last = reviewIds[reviewIds.length - 1];
  assert.notEqual(first, undefined);
  assert.notEqual(last, undefined);

  const evicted = await sandbox.services.confirm({
    review_id: first as string,
    acknowledgements: [],
  });
  assert.equal(evicted.ok, false);
  if (!evicted.ok) assert.equal(evicted.error.code, 'review_expired');

  const accepted = await sandbox.services.confirm({
    review_id: last as string,
    acknowledgements: [],
  });
  assert.equal(accepted.ok, true);
  assert.equal((readJsonLines(sandbox.anchorsFile) as unknown[]).length, 1);
});

/* ------------------------------------------------------------------------- */
/* npm acquisition                                                           */
/* ------------------------------------------------------------------------- */

test('npm flow resolves versions, verifies integrity and strips package/', async (t) => {
  const sandbox = await sandboxFor(t);
  const tarball100 = registryTarball('fake-pkg', '1.0.0');
  const tarball110 = registryTarball('fake-pkg', '1.1.0');
  const registry = await startFakeRegistry({
    packageName: 'fake-pkg',
    versions: {
      '1.0.0': { tarball: tarball100 },
      '1.1.0': { tarball: tarball110 },
    },
    latest: '1.1.0',
  });
  t.after(async () => {
    await registry.close();
  });

  const latest = await sandbox.services.review('fake-pkg', { registry: registry.base });
  assert.equal(latest.ok, true);
  if (!latest.ok) return;
  assert.equal(latest.review.resolved.kind, 'npm');
  assert.equal(latest.review.resolved.install_spec, 'fake-pkg@1.1.0');
  assert.equal(latest.review.resolved.registry, registry.base);
  assert.equal(latest.review.resolved.integrity, 'verified');
  assert.equal(latest.review.resolved.tarball_sha256, sha256Hex(tarball110));
  assert.equal(latest.review.decision.plugin.id, 'fake-pkg');
  assert.equal(latest.review.decision.plugin.version, '1.1.0');
  // `package/` was stripped: the manifest was found at the extraction root.
  assert.equal(latest.review.decision.status, 'scanned');
  assert.ok(
    registry.requests.some(
      (request) => request.accept === 'application/vnd.npm.install-v1+json',
    ),
    'registry metadata must be requested with the install-v1 accept header',
  );

  const pinned = await sandbox.services.review('fake-pkg@1.0.0', { registry: registry.base });
  assert.equal(pinned.ok, true);
  if (pinned.ok) assert.equal(pinned.review.resolved.install_spec, 'fake-pkg@1.0.0');

  const range = await sandbox.services.review('fake-pkg@^1.0.0', { registry: registry.base });
  assert.equal(range.ok, true);
  if (range.ok) assert.equal(range.review.resolved.install_spec, 'fake-pkg@1.1.0');

  const tag = await sandbox.services.review('fake-pkg@latest', { registry: registry.base });
  assert.equal(tag.ok, true);
  if (tag.ok) assert.equal(tag.review.resolved.install_spec, 'fake-pkg@1.1.0');

  // A range the small resolver cannot parse falls back to dist-tags.latest with a note.
  const unsupportedRange = await sandbox.services.review('fake-pkg@1.x.y', { registry: registry.base });
  assert.equal(unsupportedRange.ok, true);
  if (unsupportedRange.ok) {
    assert.equal(unsupportedRange.review.resolved.install_spec, 'fake-pkg@1.1.0');
    assert.match(unsupportedRange.review.resolved.note ?? '', /已回退到 dist-tags.latest/);
  }

  // Scoped packages encode the slash as `%2F` and keep the leading `@`.
  const scopedRegistry = await startFakeRegistry({
    packageName: '@scope/fake-pkg',
    versions: { '1.0.0': { tarball: registryTarball('@scope/fake-pkg', '1.0.0') } },
  });
  try {
    const scoped = await sandbox.services.review('@scope/fake-pkg', {
      registry: scopedRegistry.base,
    });
    assert.equal(scoped.ok, true);
    if (scoped.ok) {
      assert.equal(scoped.review.resolved.install_spec, '@scope/fake-pkg@1.0.0');
      assert.equal(scoped.review.decision.plugin.id, '@scope/fake-pkg');
    }
    assert.ok(
      scopedRegistry.requests.some((request) => request.path === '/@scope%2Ffake-pkg'),
      'scoped metadata must be requested as @scope%2Fname',
    );
  } finally {
    await scopedRegistry.close();
  }

  // Confirming an npm review anchors the extracted tree and cleans the candidate.
  assert.equal((await candidateDirs(sandbox.storeDir)).length >= 1, true);
  const confirmed = await sandbox.services.confirm({
    review_id: latest.review.review_id,
    acknowledgements: [],
  });
  assert.equal(confirmed.ok, true);
  if (confirmed.ok) {
    assert.equal(confirmed.anchor.plugin_id, 'fake-pkg');
    assert.equal(confirmed.anchor.version, '1.1.0');
  }
  assert.equal((readJsonLines(sandbox.anchorsFile) as unknown[]).length, 1);
});

test('npm tarball integrity mismatch fails closed without touching the cache', async (t) => {
  const sandbox = await sandboxFor(t);
  const tarball = registryTarball('tampered-pkg', '2.0.0');
  const wrongIntegrity = `sha512-${createHash('sha512').update('other bytes').digest('base64')}`;
  const registry = await startFakeRegistry({
    packageName: 'tampered-pkg',
    versions: { '2.0.0': { tarball, integrity: wrongIntegrity } },
  });
  t.after(async () => {
    await registry.close();
  });

  const response = await sandbox.services.review('tampered-pkg', { registry: registry.base });
  assert.equal(response.ok, false);
  if (!response.ok) {
    assert.equal(response.error.code, 'tarball_integrity_mismatch');
    assert.match(response.error.message, /integrity|摘要/);
  }
  assert.deepEqual(await candidateDirs(sandbox.storeDir), []);
});

test('npm unknown package, unsatisfiable range and unreachable registry have stable codes', async (t) => {
  const sandbox = await sandboxFor(t);
  const registry = await startFakeRegistry({
    packageName: 'known-pkg',
    versions: { '1.0.0': { tarball: registryTarball('known-pkg', '1.0.0') } },
  });
  t.after(async () => {
    await registry.close();
  });

  const missingPackage = await sandbox.services.review('unknown-pkg', { registry: registry.base });
  assert.equal(missingPackage.ok, false);
  if (!missingPackage.ok) assert.equal(missingPackage.error.code, 'version_not_found');

  const unsatisfiable = await sandbox.services.review('known-pkg@^9.0.0', { registry: registry.base });
  assert.equal(unsatisfiable.ok, false);
  if (!unsatisfiable.ok) assert.equal(unsatisfiable.error.code, 'version_not_found');

  const unreachable = await sandbox.services.review('known-pkg', { registry: 'http://127.0.0.1:1' });
  assert.equal(unreachable.ok, false);
  if (!unreachable.ok) assert.equal(unreachable.error.code, 'registry_unreachable');

  const badRegistry = await sandbox.services.review('known-pkg', { registry: 'not a url' });
  assert.equal(badRegistry.ok, false);
  if (!badRegistry.ok) assert.equal(badRegistry.error.code, 'invalid_spec');
});

test('a local tarball candidate is reviewed and marked integrity-unavailable', async (t) => {
  const sandbox = await sandboxFor(t);
  const tarball = registryTarball('local-tar-plugin', '4.5.6');
  const archivePath = join(sandbox.root, 'local-tar-plugin-4.5.6.tgz');
  await writeFile(archivePath, tarball);

  const response = await sandbox.services.review(archivePath);
  assert.equal(response.ok, true);
  if (!response.ok) return;
  assert.equal(response.review.resolved.kind, 'tarball');
  assert.equal(response.review.resolved.install_spec, archivePath);
  assert.equal(response.review.resolved.integrity, 'unavailable');
  assert.equal(response.review.resolved.tarball_sha256, sha256Hex(tarball));
  assert.match(response.review.resolved.note ?? '', /SHA-256/);
  assert.equal(response.review.decision.plugin.id, 'local-tar-plugin');
  assert.equal(response.review.decision.plugin.version, '4.5.6');

  // A generic archive without the npm `package/` root is reviewed as-is.
  const genericArchive = join(sandbox.root, 'generic-plugin.tgz');
  await writeFile(
    genericArchive,
    makeTarball([
      { name: 'package.json', content: declaredPackageJson('generic-tar-plugin', '2.0.0') },
      { name: 'index.js', content: 'export const ok = true;\n' },
    ]),
  );
  const generic = await sandbox.services.review(genericArchive);
  assert.equal(generic.ok, true);
  if (generic.ok) {
    assert.equal(generic.review.resolved.kind, 'tarball');
    assert.equal(generic.review.decision.plugin.id, 'generic-tar-plugin');
    assert.equal(generic.review.decision.status, 'scanned');
  }
});

/* ------------------------------------------------------------------------- */
/* Tarball safety                                                            */
/* ------------------------------------------------------------------------- */

test('unsafe archive entries are rejected fail-closed', async (t) => {
  const sandbox = await sandboxFor(t);
  const safetyPlugin = declaredPackageJson('safe-plugin', '1.0.0');
  const cases: Array<{ label: string; entries: TarFixtureEntry[] }> = [
    {
      label: 'path traversal',
      entries: [{ name: 'package/../../escape.txt', content: 'evil' }],
    },
    {
      label: 'absolute path',
      entries: [{ name: '/etc/evil.conf', content: 'evil' }],
    },
    {
      label: 'symlink entry',
      entries: [
        { name: 'package/package.json', content: safetyPlugin },
        { name: 'package/link', type: '2', linkname: '/etc/passwd' },
      ],
    },
    {
      label: 'hardlink entry',
      entries: [
        { name: 'package/package.json', content: safetyPlugin },
        { name: 'package/linked.json', type: '1', linkname: 'package/package.json' },
      ],
    },
    {
      label: 'character device',
      entries: [
        { name: 'package/package.json', content: safetyPlugin },
        { name: 'package/null', type: '3' },
      ],
    },
    {
      label: 'fifo',
      entries: [
        { name: 'package/package.json', content: safetyPlugin },
        { name: 'package/pipe', type: '6' },
      ],
    },
    {
      label: 'duplicate path',
      entries: [
        { name: 'package/package.json', content: safetyPlugin },
        { name: 'package/package.json', content: safetyPlugin },
      ],
    },
    {
      label: 'PAX-smuggled traversal path',
      entries: [
        { name: 'PaxHeader', type: 'x', content: paxRecord('path', 'package/../../pax-escape') },
        { name: 'ignored', content: 'payload' },
      ],
    },
    {
      label: 'NUL byte in PAX path',
      entries: [
        { name: 'PaxHeader', type: 'x', content: paxRecord('path', 'package/a\u0000b') },
        { name: 'ignored', content: 'payload' },
      ],
    },
  ];

  for (const [index, entryCase] of cases.entries()) {
    const archivePath = join(sandbox.root, `unsafe-${index}.tgz`);
    await writeFile(archivePath, makeTarball(entryCase.entries));
    const response = await sandbox.services.review(archivePath);
    assert.equal(response.ok, false, `case "${entryCase.label}" must be rejected`);
    if (!response.ok) {
      assert.equal(response.error.code, 'unsafe_archive_entry', `case "${entryCase.label}"`);
    }
  }
  assert.equal(await fileExists(join(sandbox.root, 'escape.txt')), false);
  assert.equal(await fileExists(join(sandbox.root, 'etc', 'evil.conf')), false);
  assert.deepEqual(await candidateDirs(sandbox.storeDir), []);
});

/* ------------------------------------------------------------------------- */
/* git acquisition                                                           */
/* ------------------------------------------------------------------------- */

const gitAvailable = spawnSync('git', ['--version'], { stdio: 'ignore' }).status === 0;

test('git candidates are shallow-cloned, reviewed without .git, and not commit-pinned', { skip: !gitAvailable }, async (t) => {
  const sandbox = await sandboxFor(t);
  const repoDir = join(sandbox.root, 'git-plugin-repo');
  await writeDeclaredPlugin(repoDir, { name: 'git-plugin', version: '0.9.0' });
  const runGit = (args: string[]): void => {
    const result = spawnSync('git', args, { cwd: repoDir, encoding: 'utf8' });
    assert.equal(result.status, 0, `git ${args.join(' ')} failed: ${result.stderr ?? ''}`);
  };
  runGit(['init', '-q']);
  runGit(['-c', 'user.email=test@example.com', '-c', 'user.name=Test', 'add', '-A']);
  runGit(['-c', 'user.email=test@example.com', '-c', 'user.name=Test', 'commit', '-q', '-m', 'init']);

  const spec = `git+${pathToFileURL(repoDir).href}`;
  const response = await sandbox.services.review(spec);
  assert.equal(response.ok, true);
  if (!response.ok) return;
  assert.equal(response.review.resolved.kind, 'git');
  assert.equal(response.review.resolved.install_spec, spec);
  assert.match(response.review.resolved.note ?? '', /未固定 commit/);
  assert.equal(response.review.decision.plugin.id, 'git-plugin');
  assert.equal(response.review.decision.plugin.version, '0.9.0');

  // `.git` is removed before the review: the candidate tree has no git metadata.
  const candidateNames = await candidateDirs(sandbox.storeDir);
  assert.equal(candidateNames.length, 1);
  const candidatePath = join(sandbox.storeDir, 'candidates', candidateNames[0] ?? '');
  assert.equal(await fileExists(join(candidatePath, '.git')), false);
  assert.equal(await fileExists(join(candidatePath, 'package.json')), true);
});

test('git unavailable surfaces git_unavailable', { skip: !gitAvailable }, async (t) => {
  const sandbox = await sandboxFor(t);
  const previousPath = process.env.PATH;
  process.env.PATH = '/nonexistent-bin-directory';
  try {
    const response = await sandbox.services.review('git+https://example.com/owner/repo.git');
    assert.equal(response.ok, false);
    if (!response.ok) assert.equal(response.error.code, 'git_unavailable');
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
});

/* ------------------------------------------------------------------------- */
/* Semver resolver                                                           */
/* ------------------------------------------------------------------------- */

test('small semver resolver handles common npm ranges', () => {
  const packument = {
    'dist-tags': { latest: '1.4.0', next: '2.0.0-beta.1' },
    versions: {
      '1.0.0': {},
      '1.2.3': {},
      '1.4.0': {},
      '2.0.0-beta.1': {},
      '2.0.0': {},
    },
  };

  assert.deepEqual(resolveNpmVersion(packument), { version: '1.4.0' });
  assert.deepEqual(resolveNpmVersion(packument, '1.2.3'), { version: '1.2.3' });
  assert.deepEqual(resolveNpmVersion(packument, '^1.0.0'), { version: '1.4.0' });
  assert.deepEqual(resolveNpmVersion(packument, '~1.2.0'), { version: '1.2.3' });
  assert.deepEqual(resolveNpmVersion(packument, '>=1.0.0 <1.3.0'), { version: '1.2.3' });
  assert.deepEqual(resolveNpmVersion(packument, '1.x'), { version: '1.4.0' });
  assert.deepEqual(resolveNpmVersion(packument, '1.0.0 || 2.0.0'), { version: '2.0.0' });
  assert.deepEqual(resolveNpmVersion(packument, 'next'), { version: '2.0.0-beta.1' });
  assert.deepEqual(resolveNpmVersion(packument, '>=2.0.0-beta.1 <2.0.0'), {
    version: '2.0.0-beta.1',
  });

  // Unsupported syntax falls back to latest with a note instead of guessing.
  const fallback = resolveNpmVersion(packument, 'definitely-not-a-range');
  assert.equal(fallback.version, '1.4.0');
  assert.match(fallback.note ?? '', /已回退到 dist-tags.latest/);

  // Parsed range with no matching release fails closed.
  assert.throws(
    () => resolveNpmVersion(packument, '^3.0.0'),
    (error: unknown) => (error as { code?: string }).code === 'version_not_found',
  );

  const caret = parseSemverRange('^1.2.0');
  assert.ok(caret !== undefined);
  const inside = parseSemver('1.9.9');
  const outside = parseSemver('2.0.0');
  assert.ok(inside !== undefined && outside !== undefined);
  assert.equal(satisfiesSemverRange(inside, caret), true);
  assert.equal(satisfiesSemverRange(outside, caret), false);
  assert.equal(parseSemver('1.2'), undefined);
});

/* ------------------------------------------------------------------------- */
/* HTTP handler                                                              */
/* ------------------------------------------------------------------------- */

test('HTTP handler serves health, review, confirm and rejects malformed requests', async (t) => {
  const sandbox = await sandboxFor(t);
  const pluginDir = join(sandbox.root, 'plugins', 'declared-plugin');
  await writeDeclaredPlugin(pluginDir);
  const handler = sandbox.services.createHttpHandler();

  // Mock request/response checks: malformed bodies, methods, routes, body cap.
  const malformed = await invokeHandler(handler, {
    method: 'POST',
    url: '/api/trust-broker/review',
    body: '{not json',
  });
  assert.equal(malformed.statusCode, 400);
  assert.equal(parseJsonBody<{ ok: boolean }>(malformed).ok, false);

  const missingSpec = await invokeHandler(handler, {
    method: 'POST',
    url: '/api/trust-broker/review',
    body: '{}',
  });
  assert.equal(missingSpec.statusCode, 400);

  const wrongMethod = await invokeHandler(handler, {
    method: 'GET',
    url: '/api/trust-broker/review',
  });
  assert.equal(wrongMethod.statusCode, 405);
  assert.equal(wrongMethod.headers.allow, 'POST');

  const wrongHealthMethod = await invokeHandler(handler, {
    method: 'POST',
    url: '/api/trust-broker/health',
    body: '{}',
  });
  assert.equal(wrongHealthMethod.statusCode, 405);
  assert.equal(wrongHealthMethod.headers.allow, 'GET');

  const unknownRoute = await invokeHandler(handler, {
    method: 'GET',
    url: '/api/trust-broker/nope',
  });
  assert.equal(unknownRoute.statusCode, 404);

  const oversizedBody = JSON.stringify({ spec: 'x'.repeat(70 * 1024) });
  const oversized = await invokeHandler(handler, {
    method: 'POST',
    url: '/api/trust-broker/review',
    body: oversizedBody,
  });
  assert.equal(oversized.statusCode, 400);

  // The handler also tolerates an already prefix-stripped mount point.
  const strippedHealth = await invokeHandler(handler, { method: 'GET', url: '/health' });
  assert.equal(strippedHealth.statusCode, 200);
  const healthBody = parseJsonBody<{ ok: boolean; version: string; store_dir: string }>(strippedHealth);
  assert.equal(healthBody.ok, true);
  assert.equal(healthBody.version, TRUST_BROKER_VERSION);
  assert.equal(healthBody.store_dir, sandbox.storeDir);

  // Full loop over a real HTTP server.
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  await new Promise<void>((resolvePromise) => {
    server.listen(0, '127.0.0.1', () => resolvePromise());
  });
  t.after(async () => {
    await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
  });
  const address = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${address.port}/api/trust-broker`;

  const healthResponse = await fetch(`${base}/health`);
  assert.equal(healthResponse.status, 200);
  assert.match(healthResponse.headers.get('content-type') ?? '', /application\/json/);
  const health = (await healthResponse.json()) as { ok: boolean; version: string };
  assert.equal(health.ok, true);
  assert.equal(health.version, TRUST_BROKER_VERSION);

  const reviewResponse = await fetch(`${base}/review`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ spec: pluginDir }),
  });
  assert.equal(reviewResponse.status, 200);
  const reviewBody = (await reviewResponse.json()) as {
    ok: boolean;
    review?: { review_id: string; resolved: { install_spec: string } };
  };
  assert.equal(reviewBody.ok, true);
  assert.equal(reviewBody.review?.resolved.install_spec, pluginDir);

  const confirmResponse = await fetch(`${base}/confirm`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ review_id: reviewBody.review?.review_id, acknowledgements: [] }),
  });
  assert.equal(confirmResponse.status, 200);
  const confirmBody = (await confirmResponse.json()) as { ok: boolean; anchor?: { plugin_id: string } };
  assert.equal(confirmBody.ok, true);
  assert.equal(confirmBody.anchor?.plugin_id, 'declared-plugin');

  const expiredConfirm = await fetch(`${base}/confirm`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ review_id: 'nope', acknowledgements: [] }),
  });
  assert.equal(expiredConfirm.status, 200, 'domain errors are 200 with ok:false');
  const expiredBody = (await expiredConfirm.json()) as { ok: boolean; error?: { code: string } };
  assert.equal(expiredBody.ok, false);
  assert.equal(expiredBody.error?.code, 'review_expired');
});

test('candidate cache lives under storeDir/candidates with 0700 and is removed on dispose', async (t) => {
  const shell = await createSandbox();
  // Not registered with t.after: this test disposes the service itself.
  try {
    const registry = await startFakeRegistry({
      packageName: 'cache-pkg',
      versions: { '1.0.0': { tarball: registryTarball('cache-pkg', '1.0.0') } },
    });
    try {
      const response = await shell.services.review('cache-pkg', { registry: registry.base });
      assert.equal(response.ok, true);
      if (!response.ok) return;
      const confirmed = await shell.services.confirm({
        review_id: response.review.review_id,
        acknowledgements: [],
      });
      assert.equal(confirmed.ok, true);
      const secondReview = await shell.services.review('cache-pkg', { registry: registry.base });
      assert.equal(secondReview.ok, true);
      const candidatesRoot = join(shell.storeDir, 'candidates');
      const entries = await candidateDirs(shell.storeDir);
      assert.equal(entries.length, 1);
      const rootStat = await stat(candidatesRoot);
      assert.equal(rootStat.mode & 0o777, 0o700);
      const candidateStat = await stat(join(candidatesRoot, entries[0] ?? ''));
      assert.equal(candidateStat.mode & 0o777, 0o700);

      shell.services.dispose();
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 120));
      assert.equal(await fileExists(candidatesRoot), false);
      // Anchors survive dispose: the journal is the durable outcome of a confirm.
      assert.equal(await fileExists(join(shell.storeDir, 'anchors.jsonl')), true);
    } finally {
      await registry.close();
    }
  } finally {
    shell.services.dispose();
    await cleanup(shell.root);
  }
});

/* ------------------------------------------------------------------------- */
/* Agent gate formatting                                                     */
/* ------------------------------------------------------------------------- */

test('formatAgentGate asks with a review summary and allows an empty spec', async (t) => {
  const sandbox = await sandboxFor(t);
  const riskyDir = join(sandbox.root, 'plugins', 'risky-plugin');
  await writeRiskyPlugin(riskyDir);
  const declaredDir = join(sandbox.root, 'plugins', 'declared-plugin');
  await writeDeclaredPlugin(declaredDir);

  assert.deepEqual(await sandbox.services.formatAgentGate('   '), { kind: 'allow' });

  const gate = await sandbox.services.formatAgentGate(riskyDir);
  assert.equal(gate.kind, 'ask');
  assert.ok((gate.reason ?? '').length > 0);
  assert.ok((gate.reason ?? '').length <= AGENT_GATE_REASON_LIMIT);
  assert.match(gate.reason ?? '', /@scope\/risky-plugin@2\.3\.4/);
  assert.match(gate.reason ?? '', /批准安装/);
  assert.match(gate.reason ?? '', /取消/);
  assert.match(gate.reason ?? '', /高权限能力/);
  assert.match(gate.reason ?? '', /子进程/);
  assert.match(gate.reason ?? '', /postinstall/);
  assert.match(gate.reason ?? '', /sha256:/);
  assert.match(gate.reason ?? '', /差异/);
  // Control characters from plugin-controlled strings must be stripped.
  assert.doesNotMatch(gate.reason ?? '', /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/);

  assert.ok(gate.displayReason !== undefined);
  assert.ok((gate.displayReason?.zh ?? '').length > 0);
  assert.match(gate.displayReason?.en ?? '', /pre-install review/i);
  assert.match(gate.displayReason?.en ?? '', /@scope\/risky-plugin@2\.3\.4/);

  // A "proceed" review still asks in the agent path (approval is never silent).
  const proceedGate = await sandbox.services.formatAgentGate(declaredDir);
  assert.equal(proceedGate.kind, 'ask');
  assert.match(proceedGate.reason ?? '', /declared-plugin@1\.0\.0/);

  // Review failures degrade to an explicit warning prompt, never an allow.
  const failedGate = await sandbox.services.formatAgentGate('./missing-plugin-dir');
  assert.equal(failedGate.kind, 'ask');
  assert.match(failedGate.reason ?? '', /未能完成/);
  assert.match(failedGate.reason ?? '', /invalid_spec/);
  assert.match(failedGate.displayReason?.en ?? '', /could not complete/i);

  // Fail-closed (unscannable) reviews are still shown in the prompt.
  const emptyDir = join(sandbox.root, 'empty-gate-candidate');
  await mkdir(emptyDir, { recursive: true });
  const unscannableGate = await sandbox.services.formatAgentGate(emptyDir);
  assert.equal(unscannableGate.kind, 'ask');
  assert.match(unscannableGate.reason ?? '', /无法完整扫描/);

  // An agent-gated npm review releases its candidate directory immediately
  // (the approval prompt never exposes a review id the UI could confirm).
  const registry = await startFakeRegistry({
    packageName: 'gate-pkg',
    versions: { '1.0.0': { tarball: registryTarball('gate-pkg', '1.0.0') } },
  });
  try {
    const npmGate = await sandbox.services.formatAgentGate('gate-pkg', { registry: registry.base });
    assert.equal(npmGate.kind, 'ask');
    assert.match(npmGate.reason ?? '', /gate-pkg@1\.0\.0/);
    assert.deepEqual(await candidateDirs(sandbox.storeDir), []);
  } finally {
    await registry.close();
  }
});

test('sanitizeUntrustedText strips controls and caps length', () => {
  assert.equal(sanitizeUntrustedText('a\u0000b\nc\td'), 'a b c d');
  assert.equal(sanitizeUntrustedText('line1\r\nline2\u0007', 100, true), 'line1\nline2');
  assert.equal(sanitizeUntrustedText('x'.repeat(500), 40).length, 40);
  assert.equal(sanitizeUntrustedText('  spaced   out  '), 'spaced out');
  assert.equal(sanitizeUntrustedText(undefined), '');

  const failure = buildAgentGateFailure({ code: 'registry_unreachable', message: '无法访问\u0000 registry' });
  assert.equal(failure.kind, 'ask');
  assert.match(failure.reason ?? '', /registry_unreachable/);
  assert.doesNotMatch(failure.reason ?? '', /\u0000/);
  assert.ok((failure.reason ?? '').length <= AGENT_GATE_REASON_LIMIT);
  assert.match(failure.displayReason?.en ?? '', /could not complete/i);
});
