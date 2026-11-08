/**
 * Structural smoke test for the Web Client half (`client.js`).
 *
 * No rendering and no DOM: the module is evaluated exactly the way the DSH
 * browser module loader would call it (capture `window.__ModuleLoader__.load`,
 * then invoke the factory with a fake `require`), and the resulting plugin's
 * `inject`/`apply` registrations and locale dictionaries are inspected.
 *
 * Browser rendering and interaction are intentionally NOT covered here; those
 * are verified only by installing the bundle and inspecting the live slot.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const CLIENT_FILE = new URL('../client.js', import.meta.url);
const CLIENT_SOURCE = readFileSync(CLIENT_FILE, 'utf8');

const LOCALE_NAMESPACE = 'dsh-trust-broker-client';
const SLOT_ID = 'trust-broker-review';

type SlotRegistration = { options: Record<string, unknown>; component: unknown };
type LocaleCall = { namespace: string; dictionaries: Record<string, Record<string, string>> };

function evaluateModule(): { definition: { id: string; factory: (require: (id: string) => unknown) => unknown }; requested: string[] } {
  let definition: { id: string; factory: (require: (id: string) => unknown) => unknown } | undefined;
  const fakeReact = {
    createElement: () => ({ type: 'element' }),
    useState: (initial: unknown) => [initial, () => undefined],
    useEffect: () => undefined,
    useRef: (initial: unknown) => ({ current: initial }),
    useCallback: (callback: unknown) => callback,
  };
  const window = {
    __ModuleLoader__: {
      load: (loaded: typeof definition) => {
        definition = loaded;
      },
    },
  };
  runInNewContext(CLIENT_SOURCE, {
    window,
    console,
    setTimeout,
    clearTimeout,
    AbortController,
    Date,
  });
  assert.ok(definition, 'client.js must call window.__ModuleLoader__.load');
  const requested: string[] = [];
  const originalFactory = definition.factory;
  const factory = (require: (id: string) => unknown) => {
    const wrappedRequire = (id: string) => {
      requested.push(id);
      if (id === 'react') return fakeReact;
      throw new Error(`unexpected client module require: ${id}`);
    };
    return originalFactory(wrappedRequire);
  };
  return { definition: { id: definition.id, factory }, requested };
}

function makeContext() {
  const effects: Array<() => void> = [];
  const localeCalls: LocaleCall[] = [];
  const slotInjections: Array<{ ownerKey: string; callback: () => unknown }> = [];
  const registrations: SlotRegistration[] = [];
  const localeFace = {
    register(namespace: string, dictionaries: Record<string, Record<string, string>>) {
      localeCalls.push({ namespace, dictionaries });
      return () => undefined;
    },
    bind(namespace: string) {
      return (key: string) => `${namespace}:${key}`;
    },
    getSnapshot() {
      return { active: 'zh', locales: ['en', 'zh'], revision: 1 };
    },
  };
  const slotsFace = {
    inject(ownerKey: string, callback: () => unknown) {
      slotInjections.push({ ownerKey, callback });
      return () => undefined;
    },
    register(options: Record<string, unknown>, component: unknown) {
      registrations.push({ options, component });
      return () => undefined;
    },
  };
  const ctx = {
    effect(fn: () => unknown) {
      const dispose = fn();
      effects.push(typeof dispose === 'function' ? (dispose as () => void) : () => undefined);
      return dispose;
    },
    locale: localeFace,
    slots: slotsFace,
  };
  return { ctx, effects, localeCalls, slotInjections, registrations };
}

test('client.js registers a browser module factory with the package id', () => {
  const { definition } = evaluateModule();
  assert.equal(definition.id, 'dsh-plugin-trust-broker');
  assert.equal(typeof definition.factory, 'function');
});

test('factory exposes slots/locale injection and an apply function', () => {
  const { definition } = evaluateModule();
  const plugin = definition.factory(() => undefined) as { inject?: unknown; apply?: unknown };
  // The plugin object comes from the vm realm, so compare a host-realm copy.
  assert.deepEqual(Array.from(plugin.inject as unknown as string[]), ['slots', 'locale']);
  assert.equal(typeof plugin.apply, 'function');
});

test('apply registers both locale dictionaries under one namespace', () => {
  const { definition } = evaluateModule();
  const plugin = definition.factory(() => undefined) as { inject?: unknown; apply?: unknown };
  const { ctx, effects, localeCalls } = makeContext();
  (plugin.apply as (context: unknown) => void)(ctx);

  assert.equal(effects.length, 1, 'the dictionaries must be registered inside ctx.effect');
  assert.equal(localeCalls.length, 1);
  assert.equal(localeCalls[0]!.namespace, LOCALE_NAMESPACE);
  const dictionaries = localeCalls[0]!.dictionaries;
  assert.deepEqual(Object.keys(dictionaries).sort(), ['en', 'zh']);
  for (const [language, dictionary] of Object.entries(dictionaries)) {
    assert.ok(Object.keys(dictionary).length > 0, `${language} dictionary must not be empty`);
  }
});

test('apply contributes one localized plugins.tab entry with the expected id and order', () => {
  const { definition } = evaluateModule();
  const plugin = definition.factory(() => undefined) as { inject?: unknown; apply?: unknown };
  const { ctx, slotInjections, registrations } = makeContext();
  (plugin.apply as (context: unknown) => void)(ctx);

  assert.equal(slotInjections.length, 1);
  const injection = slotInjections[0]!;
  assert.equal(injection.ownerKey, 'plugins.tab');
  assert.equal(typeof injection.callback, 'function');
  injection.callback();

  assert.equal(registrations.length, 1);
  const registration = registrations[0]!;
  assert.equal(registration.options.name, 'plugins.tab');
  assert.equal(registration.options.id, SLOT_ID);
  assert.equal(registration.options.order, 20);
  assert.equal(registration.options.locale, LOCALE_NAMESPACE);
  assert.equal(typeof registration.options.label, 'function');
  assert.equal((registration.options.label as () => string)(), `${LOCALE_NAMESPACE}:tab`);
  assert.equal(typeof registration.component, 'function');
});

test('en and zh dictionaries cover exactly the same keys, including every t() key in the source', () => {
  const { definition } = evaluateModule();
  const plugin = definition.factory(() => undefined) as { inject?: unknown; apply?: unknown };
  const { ctx, localeCalls } = makeContext();
  (plugin.apply as (context: unknown) => void)(ctx);
  const dictionaries = localeCalls[0]!.dictionaries as Record<string, Record<string, string>>;

  assert.deepEqual(Object.keys(dictionaries.en!).sort(), Object.keys(dictionaries.zh!).sort());

  const usedKeys = new Set<string>();
  const keyPattern = /(?:^|[^A-Za-z0-9_$])t\('([A-Za-z0-9_.-]+)'/g;
  for (const match of CLIENT_SOURCE.matchAll(keyPattern)) usedKeys.add(match[1]!);
  assert.ok(usedKeys.size > 50, `expected the tab to use many dictionary keys, found ${usedKeys.size}`);

  for (const key of usedKeys) {
    assert.ok(key in dictionaries.en!, `missing en dictionary key: ${key}`);
    assert.ok(key in dictionaries.zh!, `missing zh dictionary key: ${key}`);
  }
});

test('review and confirm use the frozen same-origin relative routes', () => {
  assert.ok(CLIENT_SOURCE.includes("'api/trust-broker/review'"));
  assert.ok(CLIENT_SOURCE.includes("'api/trust-broker/confirm'"));
  assert.ok(!CLIENT_SOURCE.includes('"/api/trust-broker/'));
  assert.ok(!CLIENT_SOURCE.includes("'/api/trust-broker/"));
});

test('the client half does not import Host/Client primitives or touch DOM globals it should not own', () => {
  assert.equal(CLIENT_SOURCE.includes("require('@deepseek-ai/dsh-client-ui-primitives')"), false);
  assert.equal(CLIENT_SOURCE.includes('document.body'), false);
  assert.equal(CLIENT_SOURCE.includes('window.location'), false);
  assert.equal(CLIENT_SOURCE.includes('localStorage'), false);
});
