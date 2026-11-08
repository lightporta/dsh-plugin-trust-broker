/**
 * Tests for the runtime scope classifier: tool+argument capability inference
 * (`classifyToolCall`) and the declared-vs-detected comparison against the
 * owning plugin's latest trust anchor (`resolveToolOwner`, `checkToolScope`).
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { checkToolScope, classifyToolCall, resolveToolOwner } from '../src/runtime/scope.ts';
import { anchorFixture } from './fixtures/runtime/anchors.ts';

describe('classifyToolCall', () => {
  it('maps a default tool to its declared catalog categories in catalog order', () => {
    const result = classifyToolCall('bash', { command: 'echo hi' });
    assert.deepEqual(result.categories, [
      'process.child_process',
      'process.exec',
      'filesystem.read',
      'filesystem.write',
    ]);
    assert.deepEqual(result.sources, ['tool-map:bash']);
  });

  it('returns an empty classification for an unknown tool without argument hints', () => {
    const result = classifyToolCall('mystery_tool', undefined);
    assert.deepEqual(result.categories, []);
    assert.deepEqual(result.sources, []);
  });

  it('lets a config override replace the default tool map entry', () => {
    const result = classifyToolCall('bash', {}, { bash: ['network.fetch', 'llm.call'] });
    assert.deepEqual(result.categories, ['network.fetch', 'llm.call']);
    assert.deepEqual(result.sources, ['override:bash']);
  });

  it('adds network.fetch for an http URL argument', () => {
    const result = classifyToolCall('read', { url: 'https://example.com/api/items' });
    assert.deepEqual(result.categories, ['network.fetch', 'filesystem.read']);
    assert.deepEqual(result.sources, ['tool-map:read', 'argument:network-url-argument']);
  });

  it('adds network.fetch for a URL nested inside an array argument', () => {
    const result = classifyToolCall('mystery_tool', { urls: ['https://a.example', 'https://b.example'] });
    assert.ok(result.categories.includes('network.fetch'));
    assert.ok(result.sources.includes('argument:network-url-argument'));
  });

  it('adds process.exec for a shell-like command argument', () => {
    const result = classifyToolCall('read', { command: 'curl https://example.com' });
    assert.deepEqual(result.categories, ['process.exec', 'filesystem.read']);
    assert.ok(result.sources.includes('argument:shell-command-argument'));
  });

  it('adds credentials.read for a secret-like argument key', () => {
    const result = classifyToolCall('read', { api_key: 'abc123' });
    assert.deepEqual(result.categories, ['filesystem.read', 'credentials.read']);
    assert.ok(result.sources.includes('argument:secret-like-argument'));
  });

  it('deduplicates categories and keeps canonical catalog order across all rules', () => {
    const result = classifyToolCall('bash', {
      command: 'bash -c "echo hi"',
      url: 'https://example.com',
      token: 'abc',
    });
    assert.deepEqual(result.categories, [
      'network.fetch',
      'process.child_process',
      'process.exec',
      'filesystem.read',
      'filesystem.write',
      'credentials.read',
    ]);
    assert.equal(new Set(result.categories).size, result.categories.length);
    assert.deepEqual(result.sources, [
      'tool-map:bash',
      'argument:network-url-argument',
      'argument:shell-command-argument',
      'argument:secret-like-argument',
    ]);
  });
});

describe('resolveToolOwner', () => {
  it('resolves the latest anchor by confirmed_at for the owning plugin', () => {
    const older = anchorFixture({
      confirmed_at: '2026-01-01T00:00:00.000Z',
      capability_keys: ['filesystem.read'],
    });
    const newer = anchorFixture({
      confirmed_at: '2026-02-01T00:00:00.000Z',
      capability_keys: ['network.fetch'],
    });
    const owner = resolveToolOwner('bash', { bash: 'plugin-a' }, [newer, older]);
    assert.ok(owner);
    assert.deepEqual(owner.capability_keys, ['network.fetch']);
  });

  it('lets the later JSONL line win a confirmed_at tie', () => {
    const first = anchorFixture({ capability_keys: ['filesystem.read'] });
    const second = anchorFixture({ capability_keys: ['network.fetch'] });
    const owner = resolveToolOwner('bash', { bash: 'plugin-a' }, [first, second]);
    assert.ok(owner);
    assert.deepEqual(owner.capability_keys, ['network.fetch']);
  });

  it('ignores anchors of other plugins', () => {
    const pluginA = anchorFixture({
      plugin_id: 'plugin-a',
      capability_keys: ['filesystem.read'],
      confirmed_at: '2026-01-01T00:00:00.000Z',
    });
    const pluginB = anchorFixture({
      plugin_id: 'plugin-b',
      capability_keys: ['network.fetch'],
      confirmed_at: '2026-03-01T00:00:00.000Z',
    });
    const owner = resolveToolOwner('bash', { bash: 'plugin-a' }, [pluginB, pluginA]);
    assert.equal(owner, pluginA);
  });

  it('returns undefined for an unknown tool or a toolless owner', () => {
    const anchors = [anchorFixture()];
    assert.equal(resolveToolOwner('grep', {}, anchors), undefined);
    assert.equal(resolveToolOwner('grep', { grep: 'plugin-missing' }, anchors), undefined);
  });
});

describe('checkToolScope', () => {
  const anchors = [
    anchorFixture({
      plugin_id: 'plugin-a',
      capability_keys: ['network.fetch', 'filesystem.read'],
    }),
  ];

  it('reports declared when every category is inside the anchored surface', () => {
    const verdict = checkToolScope({
      tool: 'grep',
      categories: ['filesystem.read'],
      anchors,
      tool_owners: { grep: 'plugin-a' },
    });
    assert.equal(verdict.scope, 'declared');
    assert.deepEqual(verdict.exceeded, []);
    assert.deepEqual(verdict.declared, ['network.fetch', 'filesystem.read']);
    assert.equal(verdict.owner_plugin_id, 'plugin-a');
  });

  it('reports undeclared_scope with the missing categories in input order', () => {
    const verdict = checkToolScope({
      tool: 'bash',
      categories: ['process.exec', 'network.fetch', 'filesystem.write', 'process.exec'],
      owner_plugin_id: 'plugin-a',
      anchors,
    });
    assert.equal(verdict.scope, 'undeclared_scope');
    assert.deepEqual(verdict.exceeded, ['process.exec', 'filesystem.write']);
    assert.deepEqual(verdict.declared, ['network.fetch', 'filesystem.read']);
  });

  it('reports unattributed when the tool has no owner mapping', () => {
    const verdict = checkToolScope({ tool: 'bash', categories: ['process.exec'], anchors });
    assert.equal(verdict.scope, 'unattributed');
    assert.deepEqual(verdict.exceeded, []);
    assert.deepEqual(verdict.declared, []);
    assert.equal(verdict.owner_plugin_id, undefined);
  });

  it('reports unattributed when the owner has no anchor', () => {
    const verdict = checkToolScope({
      tool: 'bash',
      categories: ['process.exec'],
      owner_plugin_id: 'plugin-ghost',
      anchors,
    });
    assert.equal(verdict.scope, 'unattributed');
    assert.deepEqual(verdict.exceeded, []);
    assert.deepEqual(verdict.declared, []);
  });

  it('resolves the owner from the tool_owners map when no explicit owner is given', () => {
    const verdict = checkToolScope({
      tool: 'web_fetch',
      categories: ['network.fetch'],
      anchors,
      tool_owners: { web_fetch: 'plugin-a' },
    });
    assert.equal(verdict.scope, 'declared');
    assert.equal(verdict.owner_plugin_id, 'plugin-a');
  });

  it('prefers an explicit owner_plugin_id over the tool_owners map', () => {
    const anchorsWithSecondPlugin = [
      ...anchors,
      anchorFixture({
        plugin_id: 'plugin-b',
        capability_keys: ['network.fetch', 'process.exec', 'process.child_process', 'filesystem.read', 'filesystem.write'],
      }),
    ];
    const verdict = checkToolScope({
      tool: 'bash',
      categories: ['process.exec'],
      owner_plugin_id: 'plugin-b',
      anchors: anchorsWithSecondPlugin,
      tool_owners: { bash: 'plugin-a' },
    });
    assert.equal(verdict.scope, 'declared');
    assert.equal(verdict.owner_plugin_id, 'plugin-b');
  });

  it('reports declared for an empty category set on an anchored tool', () => {
    const verdict = checkToolScope({
      tool: 'job_list',
      categories: [],
      anchors,
      tool_owners: { job_list: 'plugin-a' },
    });
    assert.equal(verdict.scope, 'declared');
    assert.deepEqual(verdict.exceeded, []);
  });
});
