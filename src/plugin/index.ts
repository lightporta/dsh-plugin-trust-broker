/**
 * DSH Host bundle entry.
 *
 * Registers the face-four runtime audit channel and exposes the `trustBroker`
 * service (`ctx.provide`) so a loader admission hook can call `evaluate()` and
 * consume the `TrustDecision` BEFORE any third-party plugin's `apply` runs.
 *
 * The bundle itself does not load or execute plugin code; the decision is data.
 */

import type {
  RuntimeAuditConfig,
  RuntimeHostContext,
  TrustBrokerService,
} from '../types.ts';
import { evaluatePluginTrust } from '../core/decision.ts';
import { createRuntimeAudit } from '../runtime/audit.ts';
import { TRUST_BROKER_NAME } from '../version.ts';

export const name = TRUST_BROKER_NAME;

export function apply(ctx: RuntimeHostContext, config?: RuntimeAuditConfig): void {
  const handle = createRuntimeAudit(ctx, config);
  const pending = new Set<Promise<unknown>>();
  const lifetime = new AbortController();

  const service: TrustBrokerService = {
    store_dir: handle.service.store_dir,
    audit_log_path: handle.service.audit_log_path,
    anchors_log_path: handle.service.anchors_log_path,
    version: handle.service.version,
    listAnchors: (pluginId) => handle.service.listAnchors(pluginId),
    record: (event) => handle.service.record(event),
    reloadAnchors: () => handle.service.reloadAnchors(),
    setToolOwner: (tool, pluginId) => handle.service.setToolOwner(tool, pluginId),
    async evaluate({ root, signal }) {
      const evaluationSignal =
        signal === undefined ? lifetime.signal : AbortSignal.any([lifetime.signal, signal]);
      evaluationSignal.throwIfAborted();
      const evaluation = evaluatePluginTrust({
        root,
        signal: evaluationSignal,
        noExternalScanner: true,
        storeDir: handle.service.store_dir,
        anchorsFile: handle.service.anchors_log_path,
      });
      pending.add(evaluation);
      try {
        const decision = await evaluation;
        evaluationSignal.throwIfAborted();
        return decision;
      } finally {
        pending.delete(evaluation);
      }
    },
  };

  ctx.provide?.('trustBroker', service);
  ctx.effect?.(() => async () => {
    if (!lifetime.signal.aborted) {
      lifetime.abort(new Error('trust-broker Host service is disposed'));
      handle.dispose();
    }
    await Promise.allSettled(pending);
  });
}

export type { TrustBrokerService };
