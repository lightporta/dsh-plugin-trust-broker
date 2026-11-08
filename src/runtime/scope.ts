/**
 * Runtime scope classification (face four, detection half).
 *
 * Given a tool name and its arguments, estimate which capability categories the
 * call can exercise, then compare that estimate with the confirmed anchor of the
 * plugin that owns the tool. The result is descriptive only: v1 records
 * `scope_exceeded` events, it does not deny the call.
 *
 * The catalog in `src/core/catalog.ts` is the single vocabulary; this module
 * never writes anchors and never mutates them.
 */

import {
  ARGUMENT_CAPABILITY_HINTS,
  CAPABILITY_DEFINITIONS,
  DEFAULT_TOOL_CAPABILITIES,
} from '../core/catalog.ts';
import type { CapabilityKey, TrustAnchor } from '../types.ts';

/** How tool+arguments were classified, and which rules produced the categories. */
export interface ClassifiedToolCall {
  /** Deduplicated capability categories in canonical catalog order. */
  categories: CapabilityKey[];
  /** Rule ids that contributed, e.g. `tool-map:bash`, `argument:network-url-argument`. */
  sources: string[];
}

/** Input of {@link checkToolScope}. */
export interface ScopeCheckInput {
  tool: string;
  categories: CapabilityKey[];
  /** Owner plugin id; takes precedence over `tool_owners[tool]` when provided. */
  owner_plugin_id?: string;
  /** All anchors known to the caller; latest per plugin is selected internally. */
  anchors: readonly TrustAnchor[];
  /** Tool name -> owning plugin id, used when `owner_plugin_id` is absent. */
  tool_owners?: Readonly<Record<string, string>>;
}

/** Result of comparing one tool call with its owner's anchored surface. */
export interface ToolScopeVerdict {
  scope: 'declared' | 'undeclared_scope' | 'unattributed';
  /** Categories not present in the owner anchor; order preserved, deduplicated. */
  exceeded: CapabilityKey[];
  /** The owner anchor's confirmed capability keys; empty when unattributed. */
  declared: CapabilityKey[];
  owner_plugin_id?: string;
}

/** Catalog position of every capability, used to normalize category order. */
const CATALOG_ORDER: ReadonlyMap<CapabilityKey, number> = new Map(
  CAPABILITY_DEFINITIONS.map((definition, index) => [definition.path, index]),
);

const MAX_ARGUMENT_DEPTH = 8;

/**
 * Classify a tool call into capability categories.
 *
 * Order of precedence:
 * 1. configured `overrides` for the tool (replaces the default map entry),
 * 2. `DEFAULT_TOOL_CAPABILITIES` for the tool,
 * 3. argument heuristics from `ARGUMENT_CAPABILITY_HINTS` (union, never replace).
 */
export function classifyToolCall(
  tool: string,
  args: unknown,
  overrides?: Readonly<Record<string, CapabilityKey[]>>,
): ClassifiedToolCall {
  const categories: CapabilityKey[] = [];
  const sources: string[] = [];

  const override = overrides?.[tool];
  const defaults = DEFAULT_TOOL_CAPABILITIES[tool];
  if (override !== undefined) {
    categories.push(...override);
    sources.push(`override:${tool}`);
  } else if (defaults !== undefined) {
    categories.push(...defaults);
    sources.push(`tool-map:${tool}`);
  }

  const haystack = argumentHaystack(args);
  if (haystack !== '') {
    for (const hint of ARGUMENT_CAPABILITY_HINTS) {
      if (hint.match.test(haystack)) {
        categories.push(hint.capability);
        sources.push(`argument:${hint.evidence}`);
      }
    }
  }

  return { categories: dedupeInCatalogOrder(categories), sources: dedupeStrings(sources) };
}

/**
 * Resolve the plugin that owns `tool` to its latest confirmed anchor.
 *
 * @returns the anchor with the greatest `confirmed_at` for the owner plugin;
 *   a later JSONL line wins ties. `undefined` when the tool has no owner or the
 *   owner has no anchor.
 */
export function resolveToolOwner(
  tool: string,
  toolOwners: Readonly<Record<string, string>>,
  anchors: readonly TrustAnchor[],
): TrustAnchor | undefined {
  const pluginId = toolOwners[tool];
  if (pluginId === undefined) return undefined;
  return latestAnchorForPlugin(pluginId, anchors);
}

/**
 * Compare a tool call's categories with its owner's anchored capability set.
 *
 * - no owner / owner without anchor -> `unattributed`
 * - every category declared -> `declared`
 * - otherwise -> `undeclared_scope` with the undeclared categories as `exceeded`
 */
export function checkToolScope(input: ScopeCheckInput): ToolScopeVerdict {
  const ownerPluginId = input.owner_plugin_id ?? input.tool_owners?.[input.tool];
  if (ownerPluginId === undefined) {
    return { scope: 'unattributed', exceeded: [], declared: [] };
  }
  const anchor = latestAnchorForPlugin(ownerPluginId, input.anchors);
  if (anchor === undefined) {
    return { scope: 'unattributed', exceeded: [], declared: [], owner_plugin_id: ownerPluginId };
  }
  const declared = [...anchor.capability_keys];
  const declaredSet = new Set(declared);
  const exceeded = dedupeStrings(input.categories.filter((category) => !declaredSet.has(category)));
  return {
    scope: exceeded.length === 0 ? 'declared' : 'undeclared_scope',
    exceeded,
    declared,
    owner_plugin_id: ownerPluginId,
  };
}

/** Latest anchor of one plugin; later lines win `confirmed_at` ties. */
function latestAnchorForPlugin(
  pluginId: string,
  anchors: readonly TrustAnchor[],
): TrustAnchor | undefined {
  let latest: TrustAnchor | undefined;
  let latestTime = Number.NEGATIVE_INFINITY;
  for (const anchor of anchors) {
    if (anchor.plugin_id !== pluginId) continue;
    const time = Date.parse(anchor.confirmed_at);
    if (latest === undefined || time >= latestTime) {
      latest = anchor;
      latestTime = time;
    }
  }
  return latest;
}

/** Deduplicate and sort categories into canonical catalog order. */
function dedupeInCatalogOrder(keys: readonly CapabilityKey[]): CapabilityKey[] {
  return dedupeStrings(keys).sort((left, right) => orderOf(left) - orderOf(right));
}

function orderOf(key: CapabilityKey): number {
  return CATALOG_ORDER.get(key) ?? Number.MAX_SAFE_INTEGER;
}

/** Deduplicate strings while preserving first-seen order. */
function dedupeStrings<T extends string>(values: readonly T[]): T[] {
  const seen = new Set<T>();
  const unique: T[] = [];
  for (const value of values) {
    if (seen.has(value)) continue;
    seen.add(value);
    unique.push(value);
  }
  return unique;
}

/**
 * Flatten argument object keys and string values into newline-joined haystack.
 *
 * Keys are included so secret-like *key names* (`api_key`, `token`) are visible
 * to the heuristics even when their values are short; values are included so a
 * URL or a shell command passed as a value is visible too.
 */
function argumentHaystack(args: unknown): string {
  const parts: string[] = [];
  collectArgumentStrings(args, parts, 0);
  return parts.join('\n');
}

function collectArgumentStrings(value: unknown, parts: string[], depth: number): void {
  if (depth > MAX_ARGUMENT_DEPTH) return;
  if (typeof value === 'string') {
    parts.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectArgumentStrings(item, parts, depth + 1);
    return;
  }
  if (value === null || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    parts.push(key);
    collectArgumentStrings(child, parts, depth + 1);
  }
}
