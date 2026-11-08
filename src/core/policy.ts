/**
 * Profile-level policy: the only knobs that can change the broker's suggested
 * action. Defaults implement the brief's fail-closed rules verbatim; anything a
 * policy relaxes is recorded in the decision object so the change is reviewable.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import type { PolicyConfig } from '../types.ts';

/** Resolve the default store directory from the environment. */
export function defaultStoreDir(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.DSH_TRUST_BROKER_STORE?.trim();
  if (override !== undefined && override !== '') return override;
  const dshHome = env.DSH_HOME?.trim();
  if (dshHome !== undefined && dshHome !== '') return join(dshHome, 'trust-broker');
  return join(homedir(), '.dsh', 'trust-broker');
}

/** Default policy; each value maps to a documented rule in docs/SECURITY-MODEL.md. */
export function defaultPolicy(env: NodeJS.ProcessEnv = process.env): PolicyConfig {
  return {
    schema_version: 1,
    require_ack_for_unstated: true,
    confirm_on_new_capability: true,
    block_on_unscannable: true,
    block_on_source_hash_mismatch: true,
    // Off by default: only `new_capability` diffs force confirmation, per the brief.
    confirm_on_non_registry_dependency: false,
    external_red_lines: 'display',
    hash_excludes: [],
    store_dir: defaultStoreDir(env),
  };
}

const BOOLEAN_KEYS = [
  'require_ack_for_unstated',
  'confirm_on_new_capability',
  'block_on_unscannable',
  'block_on_source_hash_mismatch',
  'confirm_on_non_registry_dependency',
] as const;

/** Merge caller overrides over defaults. Unknown keys are ignored, not trusted. */
export function resolvePolicy(
  overrides?: Partial<PolicyConfig>,
  env: NodeJS.ProcessEnv = process.env,
): PolicyConfig {
  const policy = defaultPolicy(env);
  if (overrides === undefined) return policy;

  for (const key of BOOLEAN_KEYS) {
    const value = overrides[key];
    if (typeof value === 'boolean') policy[key] = value;
  }
  if (overrides.external_red_lines === 'display' || overrides.external_red_lines === 'confirm') {
    policy.external_red_lines = overrides.external_red_lines;
  }
  if (Array.isArray(overrides.hash_excludes)) {
    policy.hash_excludes = overrides.hash_excludes.filter(
      (entry): entry is string => typeof entry === 'string',
    );
  }
  if (typeof overrides.store_dir === 'string' && overrides.store_dir.trim() !== '') {
    policy.store_dir = overrides.store_dir;
  }
  if (typeof overrides.trust_check_bin === 'string') {
    policy.trust_check_bin = overrides.trust_check_bin;
  }
  return policy;
}

/**
 * Load a JSON policy file. Unknown keys are ignored; wrong types are reported so
 * a bad policy cannot silently weaken the defaults.
 */
export async function loadPolicyFile(path: string): Promise<Partial<PolicyConfig>> {
  const { readFile } = await import('node:fs/promises');
  const { errorMessage } = await import('./fs-utils.ts');
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    throw new Error(`策略文件不可读：${errorMessage(error)}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    throw new Error('策略文件不是合法 JSON。');
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('策略文件顶层必须是对象');
  }
  const record = raw as Record<string, unknown>;
  const overrides: Partial<PolicyConfig> = {};
  for (const key of BOOLEAN_KEYS) {
    if (record[key] !== undefined && typeof record[key] !== 'boolean') {
      throw new Error(`策略字段 ${key} 必须是布尔值`);
    }
    if (typeof record[key] === 'boolean') {
      (overrides as Record<string, unknown>)[key] = record[key];
    }
  }
  if (
    record.external_red_lines !== undefined &&
    record.external_red_lines !== 'display' &&
    record.external_red_lines !== 'confirm'
  ) {
    throw new Error('策略字段 external_red_lines 只能是 "display" 或 "confirm"');
  }
  if (typeof record.external_red_lines === 'string') {
    overrides.external_red_lines = record.external_red_lines as PolicyConfig['external_red_lines'];
  }
  if (record.hash_excludes !== undefined) {
    if (
      !Array.isArray(record.hash_excludes) ||
      record.hash_excludes.some((entry) => typeof entry !== 'string')
    ) {
      throw new Error('策略字段 hash_excludes 必须是字符串数组');
    }
    overrides.hash_excludes = record.hash_excludes as string[];
  }
  if (typeof record.store_dir === 'string') overrides.store_dir = record.store_dir;
  if (record.trust_check_bin !== undefined) {
    if (typeof record.trust_check_bin !== 'string') {
      throw new Error('策略字段 trust_check_bin 必须是字符串');
    }
    overrides.trust_check_bin = record.trust_check_bin;
  }
  return overrides;
}
