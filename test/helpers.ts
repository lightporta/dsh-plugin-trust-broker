/**
 * Shared test helpers. Kept dependency-free (Node's built-in test runner) so the
 * whole suite runs with `node --test "test/**\/*.test.ts"` on Node 24 without a
 * build step or extra packages.
 */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { RuntimeHostContext } from '../src/types.ts';

/** Absolute path of a file under `test/fixtures`. */
export function fixturePath(...segments: string[]): string {
  return fileURLToPath(new URL(`./fixtures/${segments.join('/')}`, import.meta.url));
}

/** Create a unique temporary directory outside the repo. */
export async function makeTempDir(prefix = 'trust-broker-test-'): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

/** Remove a temporary directory recursively (best effort). */
export async function cleanup(root: string): Promise<void> {
  await rm(root, { recursive: true, force: true });
}

/** Write a tree of files under `root`; parent directories are created. */
export async function writeTree(
  root: string,
  files: Record<string, string | Uint8Array>,
): Promise<void> {
  for (const [relativePath, content] of Object.entries(files)) {
    const target = join(root, relativePath);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content);
  }
}

/** Read a JSON file from disk. */
export function readJsonFile<T>(file: string): T {
  return JSON.parse(readFileSync(file, 'utf8')) as T;
}

/** Read a JSONL file and return the parsed records (throws on malformed line). */
export function readJsonLines(file: string): unknown[] {
  const text = readFileSync(file, 'utf8');
  return text
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as unknown);
}

/** Fixed clock for deterministic timestamps. */
export function fixedClock(iso = '2026-01-01T00:00:00.000Z'): () => Date {
  return () => new Date(iso);
}

export interface FakeContext {
  /** Structurally compatible with the Host context slice the runtime audit uses. */
  ctx: RuntimeHostContext & { provide(name: string, service: unknown): unknown };
  listeners: Map<string, Array<(...args: any[]) => any>>;
  services: Map<string, unknown>;
  logs: Array<{ level: 'info' | 'warn' | 'error'; message: string }>;
  /** Call every listener of one event in registration order. */
  invoke(name: string, ...args: any[]): Promise<unknown[]>;
  /** Call the first listener of one event (waterfall style: pass `next` yourself). */
  invokeFirst(name: string, ...args: any[]): Promise<unknown>;
  listener(name: string): ((...args: any[]) => any) | undefined;
}

/** In-memory Host context for testing the runtime audit factory. */
export function createFakeContext(): FakeContext {
  const listeners = new Map<string, Array<(...args: any[]) => any>>();
  const services = new Map<string, unknown>();
  const logs: Array<{ level: 'info' | 'warn' | 'error'; message: string }> = [];

  const ctx: FakeContext['ctx'] = {
    on(name, listener) {
      const current = listeners.get(name) ?? [];
      current.push(listener);
      listeners.set(name, current);
      return () => {
        const entries = listeners.get(name) ?? [];
        const index = entries.indexOf(listener);
        if (index >= 0) entries.splice(index, 1);
      };
    },
    provide(name, service) {
      services.set(name, service);
    },
    get(name: string) {
      return services.get(name);
    },
    logger: {
      info(message: string) {
        logs.push({ level: 'info', message });
      },
      warn(message: string) {
        logs.push({ level: 'warn', message });
      },
      error(message: string) {
        logs.push({ level: 'error', message });
      },
    },
  };

  return {
    ctx,
    listeners,
    services,
    logs,
    async invoke(name, ...args) {
      const entries = [...(listeners.get(name) ?? [])];
      const results: unknown[] = [];
      for (const entry of entries) results.push(await entry(...args));
      return results;
    },
    async invokeFirst(name, ...args) {
      const entry = listeners.get(name)?.[0];
      if (entry === undefined) throw new Error(`no listener registered for ${name}`);
      return await entry(...args);
    },
    listener(name) {
      return listeners.get(name)?.[0];
    },
  };
}

/** Build a benign package.json object for fixtures. */
export function packageJsonFixture(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: 'fixture-plugin',
    version: '1.0.0',
    private: true,
    type: 'module',
    description: 'Test fixture plugin.',
    ...overrides,
  };
}
