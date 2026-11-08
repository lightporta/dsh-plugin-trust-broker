# Audit Log Schema (v1)

[简体中文](AUDIT-SCHEMA.md)

This document defines the fields in three append-only JSONL files for consumers such as `audit` and `policy`. Each line contains one JSON object. Field names are stable, breaking changes increment `schema_version`, and consumers must ignore unknown fields. Treat audit entries as evidence and assess them in context.

```text
<store_dir>/audit.jsonl       # Runtime audit written by the Host bundle
<store_dir>/anchors.jsonl     # Append-only TrustAnchor records written on confirmation
<store_dir>/decisions.jsonl   # CLI review, acceptance, and rejection records
```

The default `<store_dir>` is `$DSH_HOME/trust-broker` when `DSH_HOME` is set, otherwise `~/.dsh/trust-broker`. Override it with `DSH_TRUST_BROKER_STORE` or `--store-dir`.

## 1. Event envelope

Every `audit.jsonl` record has the following envelope.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schema_version` | `1` | Yes | Audit schema version |
| `event` | `string` | Yes | Event type, listed in section 2 |
| `seq` | `number` | Yes | Sequence number starting at 1 and increasing within one writer. Global ordering across processes is unspecified |
| `id` | `string` | Yes | Unique event ID. Tests can inject it. The runtime generates a random ID |
| `ts` | `string` | Yes | ISO 8601 timestamp. The clock can be injected |
| `plugin_id` | `string` | No | Owning plugin when attributed |
| `plugin_version` | `string` | No | Owning plugin version |
| `session_id` | `string` | No | DSH session ID |
| `agent_id` | `string` | No | Agent or session ID from the event payload |

The writer puts envelope fields before event fields. Parse records by field name regardless of field order.

## 2. Event types

### 2.1 `tool_call` (before dispatch, `tools/pre-execute`)

| Field | Type | Meaning |
|---|---|---|
| `tool` | `string` | Tool name |
| `call_id` | `string?` | Tool call ID |
| `arguments_digest` | `string` | SHA-256 of canonical JSON for the redacted arguments (`sha256:<hex>`) |
| `argument_keys` | `string[]` | Top-level argument keys |
| `categories` | `string[]` | Intended capability categories inferred from the tool mapping and argument heuristics |
| `scope` | `'declared' \| 'undeclared_scope' \| 'unattributed'` | Relationship to the owning plugin's anchored capabilities |
| `owner_plugin_id` | `string?` | Owning plugin when known |

```json
{"schema_version":1,"event":"tool_call","seq":1,"id":"evt_01","ts":"2026-11-08T05:13:45.178Z","tool":"bash","call_id":"call-1","arguments_digest":"sha256:…","argument_keys":["command"],"categories":["process.exec","process.child_process","filesystem.read","filesystem.write"],"scope":"unattributed"}
```

### 2.2 `tool_result` (after dispatch, `tools/post-execute`)

| Field | Type | Meaning |
|---|---|---|
| `tool` | `string` | Tool name |
| `call_id` | `string?` | Tool call ID |
| `ok` | `boolean` | Whether `result.isError === false` |
| `result_digest` | `string` | Digest of the result entering the post-execute waterfall |
| `settled_digest` | `string` | Audit digest after applying the DSH waterfall decision to the original result |
| `rewritten` | `boolean` | Whether the digest changed, indicating an observed rewrite, blocking feedback, or additional context |

DSH's default decision, `{ kind: 'accept' }`, preserves the original result. The audit accounts for explicit replacement `content` or `value`, blocking `feedback`, and `additionalContexts`. For `value`, it records the change to the replacement value. DSH renders the actual output afterward.

### 2.3 `scope_exceeded` (capability outside the anchor)

| Field | Type | Meaning |
|---|---|---|
| `tool` | `string` | Tool name |
| `call_id` | `string?` | Tool call ID |
| `owner_plugin_id` | `string` | Known owning plugin |
| `exceeded` | `string[]` | Categories outside the anchored capability surface |
| `declared` | `string[]` | Anchored capabilities of the plugin |
| `evidence` | `string` | Basis for the finding, such as `tool-call-outside-anchored-surface` |

The Broker emits this event only when it can identify the tool owner and find an anchor for that plugin.

### 2.4 `context_write` (context integrity)

| Field | Type | Meaning |
|---|---|---|
| `channel` | `'prompt_inject' \| 'tool_output_rewrite' \| 'history_compress' \| 'prompt_assembly' \| 'inbox_insert'` | Context write channel |
| `before_digest` | `string?` | Digest before the write |
| `after_digest` | `string?` | Digest after the write |
| `chars_before` | `number?` | Character count before the write when available |
| `chars_after` | `number?` | Character count after the write when available |
| `detail` | `string?` | Context such as `compaction/summary` or the message source kind |

Context changes are audited alongside filesystem writes. Changes to the waterfall digests trigger `tool_output_rewrite` and `prompt_assembly`. A `compaction/*` payload on `session/event` triggers `history_compress`. The `agent/inbox/inserted` event triggers `inbox_insert`.

### 2.5 Events for Host integrations

Runtime observers and the Host's `service.record()` method write `audit.jsonl`. The CLI writes its decision journal to `decisions.jsonl`. The following events are available to Host anchor and decision integrations.

| Event | Fields | Meaning |
|---|---|---|
| `anchor_created` | `anchor: TrustAnchor` | Record after writing an anchor. The free-form `notes` field is omitted |
| `decision_recorded` | `decision_digest: string`, `action: string` | Decision finalized |
| `audit_error` | `operation: string`, `message: string` | Audit failure. The `message` field stores a digest |

The Host service keeps known event fields. For events supplied through the service, it also hashes `context_write.detail`. For events generated by runtime observers, `detail` retains the event type or message source label.

## 3. Write guarantees

- **Append only.** The file descriptor uses `O_APPEND` and each line takes one `write(2)` call. If a crash leaves a partial final line, the reader reports its line number and skips it.
- **Ordering.** The writer's `seq` advances only after a successful append. The Host service accepts events with an existing envelope and preserves their sequence number.
- **Dispatch continuity.** `logger.warn` reports the operation type on write or classification failures. A waterfall listener passes through the value or exception from `next()`. Unload closes the writer and drops records that in-flight callbacks have yet to write.
- **Redaction.** Before calculating `arguments_digest`, the writer substitutes `[redacted]` for values whose key matches or ends with a built-in sensitive key, such as `authorization`, `token`, `secret`, `password`, `cookie`, `credential`, or `apiKey`. Configure `redact_argument_keys` to extend the set. Top-level key names remain in the metadata.
- **File permissions.** Newly created storage directories use `0700` and JSONL files use `0600`. Existing storage keeps its deployment permissions.
- **Digest algorithm.** Encode canonical JSON with sorted object keys as UTF-8, then hash it with SHA-256. The result is `sha256:<hex>` and is reproducible across processes.
- **Rotation and retention.** Version 1 relies on external log rotation or separate storage directories by session.

## 4. `anchors.jsonl` (`TrustAnchor`)

Each user or policy confirmation appends a record and preserves the history.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schema_version` | `1` | Yes | Anchor schema version |
| `plugin_id` | `string` | Yes | Plugin name |
| `version` | `string` | Yes | Version at confirmation |
| `content_hash` | `string` | Yes | Canonical content hash, `sha256:<hex>` |
| `declared_capabilities` | `DeclaredCapabilities` | Yes | Parsed permission declaration at confirmation |
| `confirmed_at` | `string` | Yes | ISO 8601 timestamp |
| `confirmed_by` | `'user' \| 'policy'` | Yes | Confirmation source |
| `capability_keys` | `string[]` | Yes (extension) | Effective capabilities at confirmation, including declarations set to `true`, detections, scripts, and auto-update |
| `declaration_status` | `string` | Yes (extension) | Declaration status at confirmation |
| `scanner` | `{name, version?, heuristic}` | Yes (extension) | Evidence source |
| `decision_digest` | `string` | Yes (extension) | Canonical digest of the facts used for confirmation |
| `notes` | `string?` | No | Notes |

**Update behavior.** The Broker can skip repeat confirmation when the latest matching historical hash also covers the current capability set. Otherwise it compares capabilities with that matching anchor, or with the latest anchor if no hash matches. The latest anchor is selected chronologically by `confirmed_at`, with later lines breaking ties. Added capabilities produce type B diffs. Both `content_hash` and `decision_digest` require `sha256:` followed by 64 lowercase hexadecimal characters. Storage reports and skips corrupt records so other anchors remain available for inspection; evaluation blocks on any corrupt or unreadable journal record.

## 5. `decisions.jsonl` (CLI decision journal)

Each CLI review, acceptance, or rejection appends one record.

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | `1` | |
| `type` | `'decision'` | |
| `ts` | `string` | |
| `plugin_id` / `plugin_version` | `string` | |
| `content_hash` | `string \| null` | |
| `status` / `action` | `string` | Decision status and recommended action |
| `accepted` | `boolean` | Whether admission succeeded |
| `reason` | `string?` | Reason for an unaccepted decision, such as `confirmation_required`, `blocked_for_review`, `content_changed`, `review_only`, `user_aborted_confirmation`, or `user_declined_anchor` |
| `acknowledged` | `string[]` | Acknowledgement codes supplied |
| `decision_digest` | `string` | Decision digest used by the anchor |
| `confirmations_required` | `string[]` | Required acknowledgement codes |
| `diff_ids` | `string[]` | Diff IDs |
| `error_codes` | `string[]` | Decision error codes |
| `red_lines_count` | `number` | Number of red flags reported by the external scanner |
| `scanner` | `string` | Name of the evidence source |
| `anchor_version` | `string \| null` | Version of the anchor written for this decision, if any |

## 6. Consumer examples

```bash
# Show the 20 most recent audit records and filter by event type.
node bin/trust-broker.mjs audit --lines 20
node bin/trust-broker.mjs audit --json | jq '.records[] | select(.event == "scope_exceeded")'

# Verify the JSONL structure in CI. Problems produce exit code 1.
node bin/trust-broker.mjs audit --verify --json

# List anchors for a plugin.
node bin/trust-broker.mjs anchors my-plugin --json
```

- Correlate pre-execute and post-execute records, including tool-output rewrite events, by `agent_id` and `call_id`. Group by `plugin_id` to inspect scope findings for a plugin. `session_id` is reserved for the actual DSH session supplied by session events.
- `scope: "unattributed"` identifies a missing owner mapping. Configure `tool_owners` to improve attribution.
- Assess `red_lines_count` and `context_write` alongside the rest of the evidence before deciding to block an operation.
- A consumer with a policy that blocks on audit failure can monitor `audit_error` events and apply its own response.

## 7. Versioning and compatibility

- All three logs use `schema_version = 1`.
- New fields and event types can be added. Consumers ignore unknown fields and filter on `event`.
- Increment `schema_version` and document the migration when removing or renaming fields or changing their semantics.
- Capability strings come from `src/core/catalog.ts`. Historical anchors remain readable when the catalog adds keys.

See the [security model](SECURITY-MODEL.en.md) for the limits of audit and admission.
