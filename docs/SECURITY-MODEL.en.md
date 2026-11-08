# Security Model and Boundaries

[简体中文](SECURITY-MODEL.md)

`dsh-plugin-trust-broker` produces reviewable pre-installation findings, differences, and trust anchors, plus runtime audit records.

## 1. Responsibilities

| Layer | Owner | Output |
|---|---|---|
| **Findings** | The Broker and an external scanner explicitly selected by the operator | Capability findings, `file:line` evidence, content hashes, install scripts, and source metadata |
| **Differences** | The Broker | Declaration versus detection (A), current versus last confirmation (B), and source versus content (C) |
| **Policy** | User, profile policy, or integrating loader | Recommended `proceed`, `confirm`, or `block_for_review` action and required acknowledgements |
| **Endorsement** | Outside the Broker's scope | The Broker reports evidence and recommended actions |

DSH's security boundary comes from user approval and trusted sources. Sandboxing helps prevent misuse. The trusted loader obtains and binds user authorization before activation, then loads the verified candidate tree. DSH's `ctx.approval` pipeline decides one-time authorization for tool calls. The loader checks the Broker's recommendations, acknowledgement codes, and local anchors. The Host's `evaluate()` service produces review data from local heuristics and the configured log paths. Installation, activation, and tool approval remain Host responsibilities.

## 2. Capability catalog and `high_privilege`

`src/core/catalog.ts` defines the capability vocabulary. The `high_privilege` flag determines the binary `new_capability` marker on applicable diffs.

| Capability path | High privilege | Meaning |
|---|---|---|
| `network.fetch` / `network.socket` | Yes | Outbound access and potential data transfer |
| `process.child_process` / `process.exec` | Yes | System command execution |
| `filesystem.read` | No | Local file reads appear in diffs but do not independently require confirmation |
| `filesystem.write` | Yes | Local writes and persistence |
| `env.read` | Yes | Environment variables can contain secrets |
| `tool_registry.add` / `.override` / `.intercept` | Yes | Changes to model-visible tools or interception of tool calls |
| `context.prompt_inject` / `.tool_output_rewrite` / `.history_compress` | Yes | Changes to context integrity |
| `lifecycle.preinstall` / `.install` / `.postinstall` / `.prepare` | Yes | Install-time code execution independent of capability declarations |
| `auto_update` | Yes | Retrieval and execution of content after installation |
| `credentials.read` | Yes | Credential or secret access |
| `subagent.spawn` | Yes | Launch of a subagent that can act separately |
| `llm.call` | Yes | Model requests can send data off the machine |
| `dynamic_code.eval` | Yes | Runtime code execution |
| `host_runtime.dependency` | No | Dependency on a DSH Host runtime package. Recorded as a supply chain finding outside the declaration schema |
| `composition.override` | Yes | Overriding or disabling core bundle rows. Recorded as a Host integrity finding outside the declaration schema |
| `composition.insert` | No | Inserting composition rows. Normal bundle behaviour; surfaced as a finding without forcing confirmation |

The catalog is a rule table. Update this document and the tests when changing it.

## 3. Declaration semantics

```json
{
  "process": { "child_process": false }
}
```

- An explicit `false` means the author declares that the plugin does not use the capability. A finding produces a type A diff.
- An omitted slot, such as `process` or `process.child_process`, leaves the capability unspecified. A finding can change the declaration status to `incomplete` and produce a type A diff identifying the missing coverage.
- An omitted declaration yields `unstated`. Detected evidence defines the observed capability surface. The reviewer must acknowledge that the plugin supplied no permission declaration.
- An explicit `env.read: []` has the same meaning as `false`. A nonempty array implies `env.read = true`.

## 4. Diff rules

### Type A. Insufficient declaration (`A_declaration_insufficient`)

| Code | Condition | `new_capability` |
|---|---|---|
| `observed_non_declarable_capability` | A high-privilege fact the declaration schema cannot express (currently `composition.override` from bundle-patch override/disable rows), on first install and not covered by an anchor | `true` (mandatory confirmation; not repeated once anchored) |
| `detected_but_declared_false` | The declaration explicitly says `false` and the scanner finds the capability | `isHighPrivilege(path)` |
| `detected_but_undeclared` | A declaration exists (`declared` or `incomplete`), leaves the slot unspecified, and the scanner finds the capability | `isHighPrivilege(path)` |

Install scripts and `AUTO_UPDATE` are independent findings. They can produce type A diffs for `lifecycle.*` and `auto_update` even when the declaration omits the relevant slots. Both are high privilege.

Bundle-patch composition is covered as well. Every manifest-declared patch path (string or array form) is parsed structurally the way the DSH loader applies it (JSON array or block list): `insert:` entries yield a low-privilege `composition.insert` fact; every non-`insert` top-level entry is an id-targeted mutation of an existing profile row (`config` replacement, `disabled`, case variants, and so on) and yields a non-declarable high-privilege `composition.override` fact and a type-A diff on first install. Missing declarations, non-string array entries, out-of-tree paths, unreadable patch files, and unparsable patch shapes fail closed (`bundle_patch_invalid` / `declared_patch_*` / `patch_unparsed`). Structural parsing matches the loader's standard forms; external-scanner override/disable injection facts supplement it.

### Type B. Capability drift (`B_capability_drift`)

- Compare the current effective capabilities, including declarations set to `true`, detected capabilities, install scripts, and auto-update, with the latest confirmed anchor's `capability_keys`.
- Additions produce diffs. Removed capabilities appear in `reduced_capabilities` for reference.
- When a historical anchor matches the current hash and covers the current capability set, the Broker can skip repeat confirmation for those capabilities. Newly detected capabilities still contribute to diffs and required confirmations. Source mismatches, external scanner red flags, and supply chain policy are evaluated separately.
- Each type B row includes the last confirmed version, confirmation time, and confirmer so reviewers can see what was added between versions.

### Type C. Source and content mismatch (`C_source_content_mismatch`)

| Code | Condition | Effect |
|---|---|---|
| `source_hash_mismatch` | The trusted caller's expected candidate-tree hash differs from the v2 content hash | Defaults to `block_for_review` |
| `repository_mismatch` | `package.json#repository` differs from the repository in the source metadata | Displayed for review |
| `non_registry_dependency` | A dependency uses `git:`, `file:`, a direct URL, `workspace:`, or another non-registry source | Displayed. The policy can require confirmation with `confirm_on_non_registry_dependency=true` |

Type C diffs are handled by the separate source and supply chain rules. The `new_capability` queue applies only to type A and B diffs.

Dependency sources come from `package.json` and `packages[*].resolved` in npm v2 or v3 lockfiles. If both npm lockfiles exist, the Broker reads `npm-shrinkwrap.json`. Public `registry.npmjs.org` resolution URLs count as registry sources. Custom mirrors and direct archive URLs are listed separately. The trusted installation process verifies older or other package manager lockfiles and `.npmrc` registry overrides independently. The content hash includes the original bytes of any such files present in the reviewed tree.

## 5. Required acknowledgements

The default policy defines two acknowledgement types.

1. `unstated_capabilities` applies when the declaration is absent or malformed. The CLI acknowledgement phrase is `我已知悉` (“I acknowledge”).
2. `new_capability` applies to type A or B diffs with `new_capability: true`. The CLI phrase is `确认新增能力` (“Confirm added capabilities”).

The following settings can add acknowledgements.

| Policy setting | Acknowledgement code | CLI phrase |
|---|---|---|
| `confirm_on_non_registry_dependency: true` | `supply_chain_dependency` | `确认供应链差异` (“Confirm supply chain differences”) |
| `external_red_lines: "confirm"` | `red_line` | `确认风险红线` (“Confirm scanner red flags”) |
| `block_on_source_hash_mismatch: false` | `source_mismatch` | `确认来源不一致` (“Confirm source mismatch”) |

`admitDecision` requires complete coverage, an available content hash, every required acknowledgement, and an explicitly submitted full hash. It recalculates the candidate-tree hash before writing and rejects changes. Anchor write failures surface to the caller.

## 6. Fail-closed behavior

| Condition | Decision status | Default action | Reason |
|---|---|---|---|
| Unreadable directory, missing or invalid `package.json`, or an entry point outside the tree | `unscannable` | `block_for_review` | The candidate cannot be identified or bound |
| Incomplete scan, configured scanner failure or timeout, or invalid report | `unscannable` | `block_for_review` | Collected findings remain available for review |
| Unreadable anchor journal, or any line that cannot be parsed or validated | `unscannable` | `block_for_review` | Never skip update review silently when the historical baseline is unreliable |
| Unparseable permission declaration, such as an invalid type | `malformed_manifest` | `confirm` with the unstated-declaration acknowledgement | Treat the declaration as unstated and retain the parse error |
| Content hash unavailable or the candidate tree changed during review | `unscannable` | `block_for_review` | Review a fully readable candidate again |
| Caller aborts or the Host plugin unloads | Promise rejects | End evaluation and clean up temporary resources | An explicit CLI scanner process is terminated on abort or timeout |
| Expected source hash differs | `scanned` with a type C diff | `block_for_review` | Source and content differ |
| Unacknowledged `new_capability: true` | `scanned` | `confirm`, CLI exit 2 | Loading requires acknowledgement |
| Unacknowledged unstated declaration | `scanned` with `declaration.status: unstated` | `confirm`, CLI exit 2 | The reviewer must acknowledge the missing declaration |

The CLI accepts an operator-selected scanner at an absolute path or a report supplied explicitly. The executable starts in its own directory. Its environment contains only a `PATH` pointing to the Node executable directory. Stdout and report files are size-limited, and stderr is discarded. Local heuristics run by default. If a selected scanner or report fails, the Broker preserves heuristic evidence for diagnosis and blocks admission. A successful report supplements local findings for capabilities the report does not cover.

## 7. Content hashes and trust anchors

- **Canonical hash.** The prefix is `dsh-plugin-content-v2\n`. Entries are sorted by path and encoded one per line as a JSON array `[kind, entryHash, posixRelativePath]`. Directory entries use an empty hash string. JSON escaping keeps filenames containing newlines within one record. Keep v1 anchors as history and review and accept the new hash when migrating to v2.
- **Admission coverage.** The candidate tree includes all regular files and subdirectories, including `.git`, `node_modules`, and `.DS_Store`. Strict traversal rejects symlinks, hard links, and special files. A pnpm/npm-materialized tree with links therefore fails closed; review and anchor a clean packed extraction or controlled staging copy (`npm pack` output has no `node_modules`). The Broker reads files from open descriptors and rechecks path and identity. Detectable path or entry changes, exceeded limits, and read failures produce `hash: null` and `complete: false`.
- **Review snapshot.** The Broker hashes and copies the same byte stream. The manifest parser and scanner read the private temporary snapshot, accessible to the current user. The Broker removes it when evaluation ends and rechecks the original tree at the end of review and before anchoring.
- **Anchors.** The Broker appends JSONL records and calls `fsync` after writing. Both `content_hash` and `decision_digest` require `sha256:` followed by 64 lowercase hexadecimal characters. The storage API can report and skip corrupt lines to expose other anchors, but evaluation blocks on any journal read or validation error. `confirmed_at` values are compared chronologically, including ISO 8601 timestamps with timezone offsets, rather than lexicographically.

## 8. Runtime audit boundary

The audit observes network, subprocess, and filesystem intent in tool calls and records observed context changes. Direct filesystem access by a Host plugin uses the Host process's permissions.

- **Append only.** A single `O_APPEND` write adds each JSONL record. Readers report the line number of a partial record and keep the rest of the file.
- **Audit failures.** The Broker reports failures through `logger.warn`. Tool dispatch continues according to DSH's approval and execution results. Unload closes the log writer. A callback already in a waterfall can still return its downstream result.
- **Attribution.** The Broker emits `scope_exceeded` only when the tool owner is known through `tool_owners` or `setToolOwner` and has an anchored capability surface. Unknown owners are recorded as `unattributed`.
- **Context observation.** Observers cover system prompt assembly, post-execute decisions and additional contexts, inbox insertions, and history compaction. Waterfall hooks return `next()` unchanged. Runtime logs contain digests and structured metadata. Warnings omit exception payloads. Displayed dependency and source URLs and install commands redact URL credentials and common token query parameters.

See the [audit schema](AUDIT-SCHEMA.en.md) for fields and examples.

## 9. Policy defaults

The defaults are defined in `src/core/policy.ts`.

| Key | Default | Meaning |
|---|---|---|
| `require_ack_for_unstated` | `true` | Require acknowledgement for an unstated declaration. Setting it to `false` also suppresses detection-derived `new_capability` confirmations for unstated/malformed plugins (no declaration means no type-A diff); this explicit relaxation is recorded in the decision's `policy` field |
| `confirm_on_new_capability` | `true` | Require confirmation for new high-privilege capabilities |
| `block_on_unscannable` | `true` | Admission always blocks incomplete scans |
| `block_on_source_hash_mismatch` | `true` | Block source hash mismatches by default |
| `confirm_on_non_registry_dependency` | `false` | Show non-registry dependencies for review by default |
| `external_red_lines` | `"display"` | Show external scanner red flags as evidence |
| `hash_excludes` | `[]` for admission | Admission includes all regular files and subdirectories in the candidate tree |
| `store_dir` | `$DSH_HOME/trust-broker` or `~/.dsh/trust-broker` | Anchor and audit directory |

## 10. Threat model and residual risk

The Broker binds the bytes it reviewed to a content hash and shows what changed since the last confirmation.

1. **Meaning of `proceed`.** The available evidence and effective policy triggered no required acknowledgement or blocking condition. Review the source and available evidence before granting approval.
2. **Static analysis limits.** Dynamic `import`, string concatenation, and obfuscation can evade heuristics. External scanners can miss behavior too. Diffs reflect detected evidence.
3. **TOCTOU window.** The Broker rehashes after scanning the snapshot and before writing the anchor. Portable Node path checks rely on rechecking identity and paths. The trusted loader needs protected staging and must bind the approved tree to the files actually loaded. Content generated or downloaded after installation depends on the installation flow.
4. **Tool ownership.** The caller supplies `tool_owners`. An incorrect mapping can produce an incorrect `scope_exceeded` or `declared` result.
5. **Same-process interference.** Plugins in the DSH Host process can interfere with auditing and reads in that process. Run the CLI's `review` command outside the Host before installation when the review needs a separate execution environment.
6. **Caller-supplied provenance.** The trusted caller supplies the signature verification result and expected v2 hash. `content_sha256` denotes a candidate-tree hash. The legacy `tarball_sha256` field is also interpreted as a tree hash. `repository` is a package assertion. Signed provenance is reported only when the caller reports a verified signature and the content hash matches. A complete content hash can also be used alone for comparison.
7. **Audit log integrity.** Version 1 provides sequential appends. Tamper resistance requires an external log system.

## 11. Scope of the Broker

- Reports evidence, diffs, and recommendations without scores, rankings, trust levels, or manual endorsements.
- Leaves source allowlists and blocklists to the integrating policy.
- Records external `redLines` as evidence.
- Observes runtime activity while DSH owns dispatch, `danger-full-access`, and sandbox behavior.
- Records prompt and context changes for review.
- Accepts an unstated declaration through an explicit acknowledgement, subject to the other admission checks.

See [Architecture](ARCHITECTURE.en.md) for the loader integration flow.

## 12. Web pre-install review and model-install gate (v0.2.0)

- **Entry**: the Plugins-page "Security review" tab. The built-in install dialog has no plugin slot, so the review is not embedded; after confirmation the resolved `install_spec` is handed to the native install check/progress UI. See [UI-REVIEW.en.md](UI-REVIEW.en.md).
- **Candidate acquisition**: local directories in place; npm registry tarballs (SRI verified), shallow git clones, and tarball archives. Extraction uses only the built-in `node:zlib` tar reader and rejects traversal, absolute paths, NULs, duplicate paths, symlinks, hardlinks, device/FIFO entries, and oversized content.
- **Anchor semantics**: confirmation writes a `TrustAnchor` bound to the reviewed extracted-tree hash. The native flow re-fetches `install_spec`: npm is pinned to an exact version, git is not commit-pinned, and tarball URLs can change; the anchor does **not** guarantee identical future downloaded bytes.
- **Model path**: `plugin_manager install_bundle` is reviewed in `tools/pre-execute`; the native approval prompt shows the summary and installation proceeds only after approval. If review cannot complete, the prompt says so and lets the user decide; a failed review is never presented as safe.
- **Not a loader veto**: the built-in "install third-party plugin" dialog can still bypass the review; full enforcement needs an upstream slot in that dialog.
- **This bundle's own declaration**: the Host now declares `network.fetch: true` (registry metadata/tarballs), alongside the existing `process.child_process` (git clone) and `filesystem.read/write` (candidate cache/anchors); no socket, exec, lifecycle, or credentials capability was added.
