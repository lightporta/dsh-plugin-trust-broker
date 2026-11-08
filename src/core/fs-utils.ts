/**
 * Small dependency-free helpers shared by the detector, the anchor store, the
 * CLI and the runtime audit channel. Deterministic JSON/digest behaviour is a
 * security property here: a content anchor must not depend on object key order.
 */

import { createHash } from 'node:crypto';

const MAX_CANONICAL_DEPTH = 64;

/** Lowercase hex sha-256 of a string or byte buffer. */
export function sha256Hex(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Canonical JSON: sorted object keys, stable array order, JSON-safe scalars. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value, new Set<object>(), 0));
}

/**
 * Stable digest of any JSON-ish value. Returns `sha256:<hex>` so digests are
 * self-describing when copied between records.
 */
export function digestJson(value: unknown): string {
  return `sha256:${sha256Hex(canonicalJson(value))}`;
}

/** Digest of a raw text payload (tool output, prompt text, message list). */
export function digestText(text: string): string {
  return `sha256:${sha256Hex(text)}`;
}

/** `sha256:abcdef...` -> `abcdef...`; other strings pass through. */
export function digestHex(digest: string): string {
  return digest.startsWith('sha256:') ? digest.slice('sha256:'.length) : digest;
}

/** First `length` characters of a digest, for display. */
export function shortDigest(digest: string | null | undefined, length = 12): string {
  if (digest === null || digest === undefined) return '-';
  const raw = digestHex(digest);
  return raw.length <= length ? raw : `${raw.slice(0, length)}…`;
}

/** ISO-8601 timestamp from an injectable clock. */
export function isoNow(clock: () => Date = () => new Date()): string {
  return clock().toISOString();
}

/** Common secret-ish argument keys redacted before an audit digest is computed. */
export const DEFAULT_REDACT_KEYS: readonly string[] = [
  'apiKey',
  'api_key',
  'apikey',
  'authorization',
  'bearer',
  'cookie',
  'credential',
  'credentials',
  'password',
  'passwd',
  'privateKey',
  'private_key',
  'secret',
  'token',
];

/** Redact URL credentials in display strings, including URLs embedded in commands. */
export function redactUrlCredentials(text: string): string {
  return text.replace(/[a-z][a-z\d+.-]*:\/\/[^\s"'`<>\\]+/gi, (url) => {
    const withoutUserInfo = url.replace(/^([a-z][a-z\d+.-]*:\/\/)[^/?#]*@/i, '$1');
    const query = withoutUserInfo.indexOf('?');
    const fragment = withoutUserInfo.indexOf('#');
    if (query === -1 || (fragment !== -1 && fragment < query)) return withoutUserInfo;
    const queryEnd = fragment === -1 ? withoutUserInfo.length : fragment;
    const redacted = withoutUserInfo.slice(query, queryEnd).replace(
      /([?&])([^=&?]+)=([^&]*)/g,
      (pair, separator: string, key: string) => {
        let name: string;
        try {
          name = decodeURIComponent(key).replace(/[-_]/g, '').toLowerCase();
        } catch {
          return `${separator}${key}=[redacted]`;
        }
        const secret = /(?:apikey|credential|password|passwd|secret|signature|token)$/.test(name) ||
          ['accesskey', 'auth', 'authorization', 'code', 'key', 'sig'].includes(name);
        return secret ? `${separator}${key}=[redacted]` : pair;
      },
    );
    return withoutUserInfo.slice(0, query) + redacted + withoutUserInfo.slice(queryEnd);
  });
}

/**
 * Deep-copy a JSON-ish value, replacing matching object values with
 * `[redacted]`. Matching is case-insensitive and suffix-aware (`apiKey`,
 * `GITHUB_TOKEN`, `db_password`). Keys are never removed, so argument shape
 * stays visible in the audit digest.
 */
export function redactDeep(
  value: unknown,
  keys: readonly string[] = DEFAULT_REDACT_KEYS,
  depth = 0,
): unknown {
  if (depth > MAX_CANONICAL_DEPTH) return '[depth-limit]';
  if (Array.isArray(value)) return value.map((item) => redactDeep(item, keys, depth + 1));
  if (value === null || typeof value !== 'object') return value;
  const lowered = keys.map((key) => key.toLowerCase());
  const output: Record<string, unknown> = Object.create(null);
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const normalized = key.toLowerCase().replace(/[-_]/g, '');
    const sensitive = lowered.some((candidate) => {
      const flat = candidate.replace(/[-_]/g, '');
      return normalized === flat || normalized.endsWith(flat);
    });
    output[key] = sensitive ? '[redacted]' : redactDeep(child, keys, depth + 1);
  }
  return output;
}

/** Safe message extraction for catch blocks. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

function normalize(value: unknown, seen: Set<object>, depth: number): unknown {
  if (depth > MAX_CANONICAL_DEPTH) return '[depth-limit]';
  if (value === null || value === undefined) return null;
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return value;
  if (type === 'number') return Number.isFinite(value as number) ? value : null;
  if (type === 'bigint') return String(value);
  if (type === 'function' || type === 'symbol') return null;
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Uint8Array) {
    return { $bytes: Buffer.from(value).toString('base64') };
  }
  if (Array.isArray(value)) return value.map((item) => normalize(item, seen, depth + 1));
  if (typeof value === 'object') {
    if (seen.has(value)) return '[circular]';
    seen.add(value);
    const source = value as Record<string, unknown>;
    const output: Record<string, unknown> = Object.create(null);
    for (const key of Object.keys(source).sort()) {
      const child = source[key];
      if (child === undefined) continue;
      output[key] = normalize(child, seen, depth + 1);
    }
    seen.delete(value);
    return output;
  }
  return null;
}
