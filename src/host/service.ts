/**
 * Public Host service for pre-install plugin review.
 *
 * One `createTrustHostServices(...)` instance owns:
 * - candidate acquisition (see `materialize.ts`) and the short-lived review
 *   cache that keeps a materialized tree alive until the user confirms;
 * - the review -> anchor write path: `confirm` re-runs the admission gate over
 *   the exact decision the client saw and appends one trust anchor;
 * - the same-origin HTTP JSON API mounted by the bundle entry under
 *   `/api/trust-broker` (`review`, `confirm`, `health`);
 * - the native approval prompt for model-initiated `plugin_manager` installs.
 *
 * Security invariants:
 * - the client never receives a temporary candidate path, a stack trace, or an
 *   unsanitized error string;
 * - a review whose content hash is `null` is still shown (it is a fail-closed
 *   decision), but `confirm` never fabricates an anchor for it;
 * - review ids are single-use on success and expire after 30 minutes; the cache
 *   holds at most 32 entries and evicts least-recently-used candidates.
 */

import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { resolve } from 'node:path';

import { admitDecision } from '../admission/gate.ts';
import { evaluatePluginTrust } from '../core/decision.ts';
import { errorMessage } from '../core/fs-utils.ts';
import type {
  AdmissionOutcome,
  ConfirmationRequirement,
  PolicyConfig,
  TrustDecision,
} from '../types.ts';
import { TRUST_BROKER_VERSION } from '../version.ts';
import {
  DEFAULT_REGISTRY,
  createCandidateWorkspace,
  materializeCandidate,
  normalizeRegistryBase,
  type CandidateWorkspace,
  type MaterializedCandidate,
} from './materialize.ts';
import type {
  AgentGateReview,
  ConfirmRequest,
  ConfirmResponse,
  HealthResponse,
  ReviewFailure,
  ReviewResponse,
  UiResolvedCandidate,
  UiReview,
} from './protocol.ts';
import {
  HostError,
  hostErrorCode,
  hostErrorMessage,
  isHostError,
  parseCandidateSpec,
} from './spec.ts';
import {
  buildAgentGateFailure,
  buildAgentGateReview,
  sanitizeUntrustedText,
  toUiDecision,
} from './summary.ts';

/** How long a review stays confirmable. */
const REVIEW_TTL_MS = 30 * 60 * 1000;

/** Maximum number of cached reviews before the least-recently-used one is dropped. */
const MAX_CACHED_REVIEWS = 32;

/** How often expired reviews are swept even when nobody calls `confirm`. */
const REVIEW_SWEEP_INTERVAL_MS = 60 * 1000;

/** HTTP request body cap for the JSON API. */
const MAX_REQUEST_BODY_BYTES = 64 * 1024;

/** Upper bound on one agent-gate review (including acquisition). */
const AGENT_GATE_TIMEOUT_MS = 60 * 1000;

/** Path prefix the bundle entry mounts this handler at. */
const SERVICE_PREFIX = '/api/trust-broker';

/** Options accepted by {@link createTrustHostServices}. */
export interface TrustHostServicesOptions {
  /** Store directory for anchors, audit data and the candidate cache. */
  storeDir: string;
  /** Anchor journal path (`<storeDir>/anchors.jsonl` by convention). */
  anchorsFile: string;
  /** Policy overrides merged over the fail-closed defaults. */
  policy?: Partial<PolicyConfig>;
  /** Registry base override; defaults to `https://registry.npmjs.org`. */
  registryBase?: string;
  /** Clock override for deterministic tests. */
  now?: () => Date;
  /** Injectable `fetch` for tests and custom transports. */
  fetchImpl?: typeof fetch;
}

/** Review feature as seen by the bundle entry. */
export interface TrustHostServices {
  /** Acquire one candidate and return its compact review. */
  review(spec: string, options?: { signal?: AbortSignal; registry?: string }): Promise<ReviewResponse>;
  /** Confirm a review (acknowledge its requirements) and append one trust anchor. */
  confirm(request: ConfirmRequest): Promise<ConfirmResponse>;
  /** Handler for `<prefix>/review`, `<prefix>/confirm` and `<prefix>/health`. */
  createHttpHandler(): HttpRouteHandler;
  /** Review a model-initiated install and format the native approval prompt. */
  formatAgentGate(spec: string, options?: { signal?: AbortSignal; registry?: string }): Promise<AgentGateReview>;
  /** Stop timers and delete every cached candidate directory. */
  dispose(): void;
}

/** Node HTTP handler signature used by the DSH `webServer` route registration. */
export type HttpRouteHandler = (req: IncomingMessage, res: ServerResponse) => Promise<void>;

interface CachedReview {
  readonly id: string;
  readonly spec: string;
  readonly resolved: UiResolvedCandidate;
  readonly decision: TrustDecision;
  readonly candidateDir: string;
  readonly temporary: boolean;
  readonly createdAt: number;
  readonly expiresAt: number;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isAbortError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.name === 'AbortError' || (error as NodeJS.ErrnoException).code === 'ABORT_ERR';
}

function failure(code: ReviewFailure['error']['code'], message: string): ReviewFailure {
  return { ok: false, error: { code, message: sanitizeUntrustedText(message, 500) } };
}

/** Map any thrown value into a wire-safe review failure. */
function toReviewFailure(error: unknown): ReviewFailure {
  if (isHostError(error)) return failure(error.code, error.message);
  if (isAbortError(error)) return failure('aborted', '审查已取消。');
  return failure('review_failed', `审查失败：${sanitizeUntrustedText(errorMessage(error), 300)}`);
}

/** Project an acquired candidate + its decision into the wire candidate view. */
function toUiResolved(materialized: MaterializedCandidate, decision: TrustDecision): UiResolvedCandidate {
  const resolved: UiResolvedCandidate = {
    kind: materialized.kind,
    // The install spec is handed back verbatim to the native installer; it was
    // already validated by the spec parser or built from registry metadata.
    install_spec: materialized.install_spec,
    name: sanitizeUntrustedText(materialized.name ?? decision.plugin.id, 200),
    version: sanitizeUntrustedText(materialized.version ?? decision.plugin.version, 100),
  };
  if (materialized.registry !== undefined) resolved.registry = materialized.registry;
  if (materialized.tarball_sha256 !== undefined) resolved.tarball_sha256 = materialized.tarball_sha256;
  if (materialized.integrity !== undefined) resolved.integrity = materialized.integrity;
  if (materialized.note !== undefined) resolved.note = sanitizeUntrustedText(materialized.note, 400);
  return resolved;
}

/** Acknowledgement codes the admission gate can act on. */
const KNOWN_ACKNOWLEDGEMENT_CODES: ReadonlySet<string> = new Set<ConfirmationRequirement['code']>([
  'unstated_capabilities',
  'new_capability',
  'supply_chain_dependency',
  'red_line',
  'scan_incomplete',
  'source_mismatch',
]);

/** Keep only acknowledgement codes the admission gate understands. */
function filterAcknowledgements(codes: readonly string[]): ConfirmationRequirement['code'][] {
  return codes.filter((code): code is ConfirmationRequirement['code'] =>
    KNOWN_ACKNOWLEDGEMENT_CODES.has(code),
  );
}

/** Parse and validate a `confirm` request body. */
function parseConfirmRequest(body: unknown): ConfirmRequest | undefined {
  if (!isPlainObject(body)) return undefined;
  const reviewId = body.review_id;
  const acknowledgements = body.acknowledgements;
  if (typeof reviewId !== 'string' || reviewId.trim() === '') return undefined;
  if (!Array.isArray(acknowledgements)) return undefined;
  if (!acknowledgements.every((entry): entry is string => typeof entry === 'string')) return undefined;
  return { review_id: reviewId.trim(), acknowledgements: [...acknowledgements] };
}

/** Read the `spec` field of a `review` request body. */
function parseReviewRequest(body: unknown): string | undefined {
  if (!isPlainObject(body)) return undefined;
  return typeof body.spec === 'string' ? body.spec : undefined;
}

/** Extract the unescaped pathname of a raw request URL. */
function requestPathname(rawUrl: string | undefined): string {
  const raw = typeof rawUrl === 'string' && rawUrl !== '' ? rawUrl : '/';
  try {
    return new URL(raw, 'http://localhost').pathname;
  } catch {
    const withoutQuery = raw.split('?')[0] ?? '/';
    return withoutQuery.split('#')[0] ?? '/';
  }
}

/** Resolve one route, tolerating both prefixed and already-stripped URLs. */
function resolveRoute(pathname: string): 'review' | 'confirm' | 'health' | undefined {
  const clean = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  let relative = clean;
  if (relative === SERVICE_PREFIX || relative.startsWith(`${SERVICE_PREFIX}/`)) {
    relative = relative.slice(SERVICE_PREFIX.length);
  }
  switch (relative) {
    case '/review':
      return 'review';
    case '/confirm':
      return 'confirm';
    case '/health':
      return 'health';
    default:
      return undefined;
  }
}

function sendJson(
  res: ServerResponse,
  status: number,
  payload: unknown,
  headers: Record<string, string> = {},
): void {
  if (res.headersSent || res.writableEnded) return;
  const body = JSON.stringify(payload);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-content-type-options', 'nosniff');
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
  res.end(body);
}

/** Read a bounded JSON request body; explicit errors map to HTTP 400. */
async function readJsonBody(req: IncomingMessage, maxBytes: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    total += buffer.byteLength;
    if (total > maxBytes) {
      throw new HostError('invalid_request', `请求体超过 ${Math.round(maxBytes / 1024)} KiB 上限。`);
    }
    chunks.push(buffer);
  }
  if (total === 0) throw new HostError('invalid_request', '请求体为空。');
  const text = Buffer.concat(chunks).toString('utf8');
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new HostError('invalid_request', '请求体不是合法 JSON。');
  }
}

/**
 * Create the review Host service.
 *
 * The returned instance is stateful (review cache, candidate workspace): the
 * bundle entry must keep one instance and call {@link TrustHostServices.dispose}
 * on unload.
 */
export function createTrustHostServices(options: TrustHostServicesOptions): TrustHostServices {
  if (!isPlainObject(options as unknown)) {
    throw new TypeError('createTrustHostServices: options object is required');
  }
  const storeDir = typeof options.storeDir === 'string' ? options.storeDir.trim() : '';
  const anchorsFile = typeof options.anchorsFile === 'string' ? options.anchorsFile.trim() : '';
  if (storeDir === '') throw new TypeError('createTrustHostServices: options.storeDir is required');
  if (anchorsFile === '') throw new TypeError('createTrustHostServices: options.anchorsFile is required');

  const resolvedStoreDir = resolve(storeDir);
  const resolvedAnchorsFile = resolve(anchorsFile);
  const clock = options.now ?? (() => new Date());
  const defaultRegistryBase =
    options.registryBase === undefined ? DEFAULT_REGISTRY : normalizeRegistryBase(options.registryBase);
  const workspace: CandidateWorkspace = createCandidateWorkspace(resolvedStoreDir);
  const cache = new Map<string, CachedReview>();

  let disposed = false;

  const sweepTimer = setInterval(() => {
    sweepExpired();
  }, REVIEW_SWEEP_INTERVAL_MS);
  // Never keep the Host process alive just for cache bookkeeping.
  sweepTimer.unref?.();

  function sweepExpired(): void {
    const nowMs = clock().getTime();
    for (const [id, entry] of [...cache.entries()]) {
      if (nowMs >= entry.expiresAt) {
        cache.delete(id);
        void releaseCandidate(entry);
      }
    }
  }

  async function releaseCandidate(entry: CachedReview): Promise<void> {
    cache.delete(entry.id);
    if (!entry.temporary) return;
    try {
      await workspace.releaseDir(entry.candidateDir);
    } catch {
      // Candidate cleanup is best effort; the directory lives under our store.
    }
  }

  function storeReview(entry: CachedReview): void {
    while (cache.size >= MAX_CACHED_REVIEWS) {
      const oldest = cache.keys().next();
      if (oldest.done === true) break;
      const evicted = cache.get(oldest.value);
      cache.delete(oldest.value);
      if (evicted !== undefined) void releaseCandidate(evicted);
    }
    cache.set(entry.id, entry);
  }

  function takeReview(id: string): CachedReview | undefined {
    const entry = cache.get(id);
    if (entry === undefined) return undefined;
    if (clock().getTime() >= entry.expiresAt) {
      cache.delete(id);
      void releaseCandidate(entry);
      return undefined;
    }
    // Refresh LRU recency.
    cache.delete(id);
    cache.set(id, entry);
    return entry;
  }

  async function review(
    spec: string,
    reviewOptions: { signal?: AbortSignal; registry?: string } = {},
  ): Promise<ReviewResponse> {
    if (disposed) return failure('internal_error', '审查服务已卸载。');
    const { signal } = reviewOptions;
    try {
      signal?.throwIfAborted();
      const parsed = await parseCandidateSpec(spec);
      const registryBase =
        reviewOptions.registry === undefined ? defaultRegistryBase : normalizeRegistryBase(reviewOptions.registry);
      const materialized = await materializeCandidate(parsed, {
        storeDir: resolvedStoreDir,
        workspace,
        registryBase,
        ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
        ...(signal !== undefined ? { signal } : {}),
      });
      try {
        signal?.throwIfAborted();
        const decision = await evaluatePluginTrust({
          root: materialized.candidateDir,
          noExternalScanner: true,
          storeDir: resolvedStoreDir,
          anchorsFile: resolvedAnchorsFile,
          ...(options.policy !== undefined ? { policy: options.policy } : {}),
          now: () => clock(),
          sourceMetadata: {
            spec: materialized.install_spec,
            ...(materialized.repository !== undefined ? { repository: materialized.repository } : {}),
          },
          ...(signal !== undefined ? { signal } : {}),
        });
        signal?.throwIfAborted();
        if (disposed) {
          if (materialized.temporary) {
            try {
              await workspace.releaseDir(materialized.candidateDir);
            } catch {
              // Cleanup is best effort.
            }
          }
          return failure('internal_error', '审查服务已卸载。');
        }
        const reviewId = randomUUID();
        const createdAt = clock().getTime();
        const resolved = toUiResolved(materialized, decision);
        const entry: CachedReview = {
          id: reviewId,
          spec: typeof spec === 'string' ? spec.trim() : '',
          resolved,
          decision,
          candidateDir: materialized.candidateDir,
          temporary: materialized.temporary,
          createdAt,
          expiresAt: createdAt + REVIEW_TTL_MS,
        };
        storeReview(entry);
        const uiReview: UiReview = {
          review_id: reviewId,
          spec: sanitizeUntrustedText(entry.spec, 2048),
          resolved,
          decision: toUiDecision(decision),
          created_at: new Date(createdAt).toISOString(),
          expires_at: new Date(entry.expiresAt).toISOString(),
        };
        return { ok: true, review: uiReview };
      } catch (error) {
        if (materialized.temporary) {
          try {
            await workspace.releaseDir(materialized.candidateDir);
          } catch {
            // Cleanup is best effort.
          }
        }
        throw error;
      }
    } catch (error) {
      return toReviewFailure(error);
    }
  }

  async function confirm(request: ConfirmRequest): Promise<ConfirmResponse> {
    if (disposed) return failure('internal_error', '审查服务已卸载。');
    const parsedRequest = parseConfirmRequest(request);
    if (parsedRequest === undefined) {
      return failure(
        'review_not_confirmable',
        '确认请求格式不正确：需要 review_id 字符串与 acknowledgements 字符串数组。',
      );
    }
    const entry = takeReview(parsedRequest.review_id);
    if (entry === undefined) {
      return failure('review_expired', '审查不存在、已确认或已过期，请重新发起审查。');
    }
    let outcome: AdmissionOutcome;
    try {
      outcome = await admitDecision(entry.decision, {
        acknowledgements: filterAcknowledgements(parsedRequest.acknowledgements),
        acceptedContentHash: entry.decision.content_hash ?? undefined,
        anchorsFile: resolvedAnchorsFile,
        now: () => clock(),
      });
    } catch (error) {
      // A failed anchor write must never look like a successful admission.
      return failure(
        'review_not_confirmable',
        `写入信任锚点失败：${sanitizeUntrustedText(hostErrorMessage(error), 300)}`,
      );
    }
    if (outcome.accepted) {
      await releaseCandidate(entry);
      return {
        ok: true,
        anchor: {
          plugin_id: outcome.anchor.plugin_id,
          version: outcome.anchor.version,
          content_hash: outcome.anchor.content_hash,
          confirmed_at: outcome.anchor.confirmed_at,
        },
      };
    }
    // An acknowledgement mismatch is retryable from the UI; every other
    // rejection means this review can never be confirmed.
    if (outcome.reason !== 'acknowledgement_missing') await releaseCandidate(entry);
    return {
      ok: false,
      error: { code: outcome.reason, message: sanitizeUntrustedText(outcome.message, 500) },
    };
  }

  async function formatAgentGate(
    spec: string,
    gateOptions: { signal?: AbortSignal; registry?: string } = {},
  ): Promise<AgentGateReview> {
    const trimmed = typeof spec === 'string' ? spec.trim() : '';
    if (trimmed === '') return { kind: 'allow' };

    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort(new HostError('review_failed', '预安装审查超时。'));
    }, AGENT_GATE_TIMEOUT_MS);
    const signal =
      gateOptions.signal === undefined
        ? controller.signal
        : AbortSignal.any([gateOptions.signal, controller.signal]);
    try {
      const response = await review(trimmed, {
        signal,
        ...(gateOptions.registry !== undefined ? { registry: gateOptions.registry } : {}),
      });
      if (!response.ok) {
        if (controller.signal.aborted && gateOptions.signal?.aborted !== true) {
          return buildAgentGateFailure({
            code: 'review_failed',
            message: `预安装审查超时（${Math.round(AGENT_GATE_TIMEOUT_MS / 1000)} 秒）。`,
          });
        }
        return buildAgentGateFailure(response.error);
      }
      const gate = buildAgentGateReview({
        decision: response.review.decision,
        resolved: response.review.resolved,
      });
      // The approval prompt does not expose the review id, so the cached
      // review (and its candidate directory) can be released immediately.
      const cached = takeReview(response.review.review_id);
      if (cached !== undefined) await releaseCandidate(cached);
      return gate;
    } catch (error) {
      return buildAgentGateFailure({ code: hostErrorCode(error), message: hostErrorMessage(error) });
    } finally {
      clearTimeout(timer);
    }
  }

  function createHttpHandler(): HttpRouteHandler {
    return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
      try {
        const route = resolveRoute(requestPathname(req.url));
        if (route === undefined) {
          sendJson(res, 404, failure('invalid_request', '未知的信任代理接口。'));
          return;
        }
        if (route === 'health') {
          if (req.method !== 'GET') {
            sendJson(res, 405, failure('invalid_request', '该接口只接受 GET 请求。'), { allow: 'GET' });
            return;
          }
          const health: HealthResponse = {
            ok: true,
            version: TRUST_BROKER_VERSION,
            store_dir: resolvedStoreDir,
          };
          sendJson(res, 200, health);
          return;
        }
        if (req.method !== 'POST') {
          sendJson(res, 405, failure('invalid_request', '该接口只接受 POST 请求。'), { allow: 'POST' });
          return;
        }
        let body: unknown;
        try {
          body = await readJsonBody(req, MAX_REQUEST_BODY_BYTES);
        } catch (error) {
          sendJson(res, 400, failure('invalid_request', hostErrorMessage(error)));
          return;
        }
        if (route === 'review') {
          const spec = parseReviewRequest(body);
          if (spec === undefined) {
            sendJson(res, 400, failure('invalid_request', '请求体必须是 {"spec": "<插件规格>"}。'));
            return;
          }
          sendJson(res, 200, await review(spec));
          return;
        }
        const request = parseConfirmRequest(body);
        if (request === undefined) {
          sendJson(
            res,
            400,
            failure('invalid_request', '请求体必须是 {"review_id": "...", "acknowledgements": [...]}。'),
          );
          return;
        }
        sendJson(res, 200, await confirm(request));
      } catch {
        // Never throw out of the HTTP handler and never leak a stack trace.
        try {
          if (!res.headersSent && !res.writableEnded) {
            sendJson(res, 500, failure('internal_error', '信任代理内部错误。'));
          } else if (!res.writableEnded) {
            res.end();
          }
        } catch {
          // The response is already gone; nothing else to do.
        }
      }
    };
  }

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    clearInterval(sweepTimer);
    const entries = [...cache.values()];
    cache.clear();
    const cleanup = (async (): Promise<void> => {
      await Promise.allSettled(entries.map((entry) => releaseCandidate(entry)));
      await workspace.dispose();
    })();
    void cleanup.catch(() => undefined);
  }

  return { review, confirm, createHttpHandler, formatAgentGate, dispose };
}
