# dsh-plugin-trust-broker · DSH Plugin Trust Broker

[简体中文](README.md) · [Architecture](docs/ARCHITECTURE.en.md) · [Security model](docs/SECURITY-MODEL.en.md) · [Audit schema](docs/AUDIT-SCHEMA.en.md) · [Adversarial review](docs/reviews/structure-review.en.md)

> Before a third-party plugin is loaded into the DeepSeek Harness (DSH) Host process, produce a reviewable trust decision: declared-vs-detected capability diffs, a content-hash trust anchor, and an append-only runtime audit of network, subprocess, and context writes after load.
>
> **It produces facts, diffs, a Boolean `new_capability` marker, and suggested actions. It does not classify plugins as safe or malicious, does not execute plugin code, and does not replace a sandbox.**

---

## 1. What it does

DSH plugins run as Host code inside the Host process. `dsh plugin add` only manages packages: it does not show a permission inventory, verify provenance, or bind a content hash. Existing static scanners such as [`dsh-trust-check`](https://www.npmjs.com/package/dsh-trust-check) can report capability facts, but they do **not** answer:

- Where do the plugin's declared permissions differ from detected facts?
- Which high-privilege capabilities are **new** since the last confirmed version?
- Can the bytes the user confirmed be matched later by content hash?
- Can outbound network intent, subprocess intent, and context writes outside the sandbox be traced after the fact?

This project fills those four gaps. It runs in two modes:

| Mode | Entry point | Use |
|---|---|---|
| **CLI** | `bin/trust-broker.mjs` / `npm run cli` | Pre-install review, confirmation, anchor writes, and audit inspection; copyable `content_hash`; exit codes for CI gates |
| **DSH Host bundle** | `src/plugin/index.ts` (`apply`) | After load, register runtime auditors such as `tools/pre-execute` and `tools/post-execute`; expose `evaluate()` via `ctx.provide('trustBroker', …)` for loaders/orchestrators to consume before `apply` |

Both modes share the same core libraries (`src/core/*`, `src/admission/*`, `src/runtime/*`).

## 2. What it does not do (boundary)

- ❌ No plugin marketplace, scoring, allow/deny lists, or human endorsement.
- ❌ No “safe / malicious” classification. Output is facts, diffs, a Boolean `new_capability` marker, and `proceed` / `confirm` / `block_for_review` suggested actions. Final authorization belongs to the user or an upstream policy.
- ❌ Not a replacement for a static scanner. Built-in heuristic facts run independently and are labeled `heuristic: true`. The CLI can additionally consume an operator-trusted `dsh-trust-check` schema 2 report, or a trusted absolute `trust_check_bin`. External reports only supplement facts.
- ❌ Not a sandbox replacement. The broker reads and writes the selected tree, a private temporary snapshot, and configured journals with Host-process privileges. The trust boundary is the caller-selected source plus user approval. Native tool dispatch remains under DSH control.
- ❌ No author-side code changes required. Undeclared plugins take the `unstated` degradation path (one explicit acknowledgment) instead of a hard reject.
- ❌ No safety filtering of model-visible prompts: context writes are recorded only.
- ❌ v1 has no Web GUI panel: `--json` is the GUI/automation contract; the terminal meets the acceptance checklist in §13.

## 3. Quick start

```bash
cd dsh-plugin-trust-broker
npm ci --ignore-scripts  # Locked development dependencies; zero runtime dependencies
npm run check            # Type checking, tests, and build
```

Review a candidate plugin directory:

```bash
npm run build
node bin/trust-broker.mjs review ./some-plugin --no-external-scanner
# From source: node src/cli/entry.ts review ./some-plugin --no-external-scanner
```

Consume a scanner report from a checked source. Generate the report in a separate trusted environment, then pass it for the matching candidate tree:

```bash
npx dsh-trust-check@0.2.5 --dir ./some-plugin --spec npm:some-plugin@1.2.3 --json > /tmp/report.json
node bin/trust-broker.mjs review ./some-plugin --trust-check-report /tmp/report.json
```

JSON decisions for CI / GUI:

```bash
node bin/trust-broker.mjs review ./some-plugin --json --non-interactive
# Exit codes: 0 = proceed, 2 = confirmation required, 3 = block/unscannable, 1 = usage error or corrupt journal (inspection commands)
```

A standalone review reports a recommendation. Use `admission.accepted: true` to verify explicit confirmation and a successful anchor write.

## 4. Install the DSH Host bundle

This repository is itself an installable bundle: `package.json` declares `dsh.bundle.patch`, and `cordis.patch.yml` inserts the Host entry.

```text
# Path 1: DSH Plugin Manager
plugin_manager(install_bundle, target: "<absolute path to this project>")
# Path 2: CLI
dsh plugin --profile <profile> add <absolute path to this project>
```

Build before install: `npm run build` (`package.json.main` points at `dist/plugin/index.js`; Host plugins need plain ESM JavaScript. `dist/` is gitignored; the published `files` list still includes it).

> The Host service is only for trusted Host callers evaluating a selected directory with the built-in scanner. An install flow that requires pre-load approval must still obtain user confirmation for that candidate tree and bind the loader to the bytes that actually activate.
>
> **Installing this bundle only enables the runtime audit channel and the `trustBroker` service; DSH 0.2.x has no loader-level pre-apply veto, so it does not gate `plugin_manager` installs automatically.** For a pre-install gate, run this project's CLI review/confirmation first (see §15).

## 5. What a terminal review looks like

Interactive prompts and human-readable diagnostics currently use Chinese. The English transcript below mirrors the same fields:

```text
Plugin trust broker v0.1.0  ·  Pre-install review
──────────────────────────────────────────────────────────────────────────────
  Plugin                 demo-plugin@1.2.0
  Plugin directory       /…/examples/demo-plugin
  Runs as Host code      Yes — this plugin runs as Host code: same process and privileges as the DSH Host; DSH does not provide plugin-level process isolation.
  Source trust           Source undeclared · the plugin declares no repository, and the caller supplied no provenance metadata; source cannot be verified.
  Declaration status     Declared · field package.json#dsh.capabilities

Detected capabilities (reviewable facts)  source: dsh-plugin-trust-broker-heuristic@0.1.0
  · Install lifecycle: postinstall script  （package.json#scripts.postinstall）

Detected capabilities (heuristic:true, separate from facts)
  · Network: network access (fetch/http/https)  （lib/index.js:14  const response = await fetch('https://example.com/status');）
  · Process: child_process  （lib/index.js:2 …）
  · Filesystem: write file  （lib/index.js:16  await writeFile('/tmp/demo-plugin.cache', …);）
  · Tool registry: register tool  （lib/index.js:8  ctx.tools.register({）

Install scripts / update mechanisms
  · Install scripts: postinstall —— node scripts/setup.js

  Content hash           sha256:86a6fe7e9e3b841f813a6509a06b9cae6a45dbd1e136bebcaefd807c7fce069d
  Trust anchor           No prior anchor (this confirmation will persist one)

Differences (3)
  [A understated] child_process  new_capability=true
      Declared process.child_process = false, but child_process was detected.
      [A understated] write file  new_capability=true
      [A understated] postinstall script  new_capability=true

Recommended action
  confirm — default action: pause for explicit acknowledgment; do not load without it.

Required acknowledgments (1)
  1. [new_capability] High-privilege capabilities beyond the declaration were detected: child_process, write file, postinstall. Explicit confirmation is required before load.
     Phrase: 「确认新增能力」
```

Copy the hash above and confirm (or enter the displayed Chinese phrase in an interactive terminal). You can admit in one `review` call, or use the separate `confirm` subcommand:

```bash
# Option A: review + admit in one step
node bin/trust-broker.mjs review ./examples/demo-plugin --store-dir /tmp/tb-demo \
  --no-external-scanner --non-interactive \
  --acknowledge-new-capability --accept-hash 'sha256:86a6fe7e9e3b841f813a6509a06b9cae6a45dbd1e136bebcaefd807c7fce069d'
# Wrote trust anchor: demo-plugin@1.2.0

# Option B: review first, then confirm
demo_store="$(mktemp -d)"
node bin/trust-broker.mjs review ./examples/demo-plugin \
  --store-dir "$demo_store" --json --non-interactive --no-external-scanner
node bin/trust-broker.mjs confirm ./examples/demo-plugin \
  --store-dir "$demo_store" --json --non-interactive \
  --acknowledge-new-capability \
  --accept-hash 'sha256:86a6fe7e9e3b841f813a6509a06b9cae6a45dbd1e136bebcaefd807c7fce069d'
```

The example hash is for the current demo tree. A mismatched `--accept-hash`, or a file change after review (TOCTOU recheck), refuses the anchor and exits with code 2. Success returns `admission.accepted: true`.

## 6. Security surfaces and implementation

| Surface | Evidence and controls | Implementation | Tests |
|---|---|---|---|
| Permission transparency and pre-install review | Declaration presence and values, source status, detected capabilities, and a confirmation queue | [Manifest](src/core/manifest.ts), [catalog](src/core/catalog.ts), [decision](src/core/decision.ts), [renderer](src/cli/render.ts) | [Manifest](test/manifest.test.ts), [decision](test/decision.test.ts), [CLI](test/cli.test.ts) |
| Declaration and behavior differences | Declaration gaps, capability drift, and provenance differences with file or metadata evidence | [Diffs](src/core/diff.ts), [detector](src/core/detector.ts), [external scanner](src/core/external-scan.ts), [heuristics](src/core/heuristic.ts), [drift](src/core/drift.ts) | [Detector](test/detector.test.ts), [external scan](test/external-scan.test.ts), [decision](test/decision.test.ts) |
| Supply-chain anchors and updates | Canonical content hash, persistent anchors, install scripts, and continuous-trust signals | [Hash](src/core/hash.ts), [anchor store](src/core/anchor-store.ts), [admission gate](src/admission/gate.ts) | [Hash](test/hash.test.ts), [anchor store](test/anchor-store.test.ts), [drift](test/drift.test.ts), [admission](test/admission.test.ts) |
| Runtime behavior and context integrity | Tool intent and scope, model-visible output changes, context injection and compaction, and append-only JSONL | [Audit observers](src/runtime/audit.ts), [audit log](src/runtime/audit-log.ts), [scope](src/runtime/scope.ts) | [Runtime audit](test/runtime-audit.test.ts), [runtime scope](test/runtime-scope.test.ts), [Host entry](test/plugin.test.ts) |

## 7. Decision format

See the full [TypeScript model](src/types.ts).

| Field | Meaning |
|---|---|
| `host_code` | Always `true`. The plugin runs in the DSH Host process. |
| `source_trust` | Source state of `registry_signature`, `hash_match`, `hash_mismatch`, `unverified`, or `undeclared`. |
| `declaration.status` | `declared`, `unstated`, `incomplete`, or `malformed`. |
| `capabilities.facts` | Evidence from the scanner, manifest, and lifecycle scripts. |
| `capabilities.heuristic_facts` | Built-in scanner findings labeled `heuristic: true`. |
| `capabilities.categories` | Grouped capability summary for display. |
| `diffs[]` | Type A, B, and C differences with evidence, the Boolean `new_capability` marker, and prior confirmation details where applicable. |
| `confirmations_required[]` | Required acknowledgments. The default policy covers `unstated_capabilities` and `new_capability`. |
| `content_hash` | Copyable canonical hash. A null hash blocks admission. |
| `anchor` | Prior anchors and any confirmed version with the same hash. |
| `status` / `action` | Status is `scanned`, `unscannable`, or `malformed_manifest`. Recommended action is `proceed`, `confirm`, or `block_for_review`. |

**Exit codes** — `0` for a proceed recommendation or a successful anchor write, `2` for pending confirmation or changed content, `3` for blocked or unscannable, and `1` for usage or internal errors, or a corrupt journal reported by the JSON inspection commands (`anchors --json` / `audit --json`).

### 7.1 Capability declarations

Declare capabilities in `package.json`. The broker looks for `dsh.capabilities`, `dsh.bundle.capabilities`, `dsh.permissions`, and `permissions` in that order.

```json
{
  "dsh": {
    "capabilities": {
      "network": { "fetch": true, "socket": false, "outbound_domains": ["api.example.com"] },
      "process": { "child_process": false, "exec": false },
      "filesystem": { "read": true, "write": false, "roots": ["/tmp"] },
      "env": { "read": ["DEMO_TOKEN"] },
      "tool_registry": { "add": true, "override": false, "intercept": false },
      "context": { "prompt_inject": false, "tool_output_rewrite": false, "history_compress": false },
      "lifecycle": { "preinstall": false, "install": false, "postinstall": false, "prepare": false },
      "auto_update": false,
      "credentials": { "read": false },
      "subagent": { "spawn": false },
      "llm": { "call": false },
      "dynamic_code": { "eval": false }
    }
  }
}
```

The broker tracks presence separately from the declared value. A detected capability that contradicts an explicit `false` produces `detected_but_declared_false`. A detected capability omitted from an existing declaration produces `detected_but_undeclared` and can make the declaration `incomplete`. An absent declaration produces `unstated` and triggers explicit acknowledgment by default.

## 8. Difference rules

| Type | Trigger | `new_capability` |
|---|---|---|
| **A. Declaration gap** | A detected capability is marked `false` or missing from an existing declaration. Install scripts and auto-update behavior are also tracked independently. | Based on the capability catalog's `high_privilege` flag. |
| **B. Capability drift** | The current effective capability set adds a capability beyond the prior confirmed anchor. | Based on the added capability's privilege. |
| **C. Source or content mismatch** | A trusted expected tree hash differs from the current hash, repository metadata differs, or a dependency resolves outside the public npm registry. | Always `false`. Source hash mismatches block by default. Other Type C checks follow source policy. |

For example, file reads appear in the report as lower privilege. Subprocess execution, network access, filesystem writes, context changes, install scripts, and auto-update can require confirmation as high-privilege capabilities. See the [capability catalog](src/core/catalog.ts) and [security model](docs/SECURITY-MODEL.en.md).

Bundle-patch composition changes are covered too, parsed structurally the way the DSH loader applies them (JSON or block list): `insert:` entries surface as a low-privilege `composition.insert` fact; every non-`insert` top-level entry is an id-targeted mutation of an existing profile row (`config` replacement, `disabled`, case variants, and so on) and surfaces as a non-declarable high-privilege `composition.override` fact, producing a type-A diff and a mandatory first-install confirmation. Every manifest-declared patch path (string or array form) is analysed; a missing, out-of-tree, unreadable or unparsable declaration fails closed.

The summary lists `preinstall`, `install`, `postinstall`, and `prepare` scripts independently of the capability declaration. A detected auto-update or remote-content mechanism flags ongoing trust in whatever content the plugin may retrieve after review.

## 9. Content hashes and trust anchors

- **Canonical hash.** The `dsh-plugin-content-v2` domain and sorted JSON tuples bind directory paths, file paths, and file digests. Admission covers the entire candidate tree, including dependencies already present. Symlinks, hard links, special files, escaping manifest paths, and incomplete coverage block admission. A pnpm/npm-materialized tree that contains symlinks or hard links therefore fails closed as `unscannable`; review and anchor a clean packed extraction or a controlled staging copy instead (for example `npm pack` output, which has no `node_modules`).
- **Evaluation and admission.** The broker copies and hashes the candidate into a private snapshot, scans that snapshot, then rechecks the original tree. Both interactive and JSON admission require the full accepted hash. The gate hashes the original tree again before it writes an anchor. An unavailable hash, changed candidate, or failed write prevents admission.
- **Anchor journal.** The default is `~/.dsh/trust-broker/anchors.jsonl`, or `$DSH_HOME/trust-broker/anchors.jsonl` when `DSH_HOME` is set. Override the directory with `DSH_TRUST_BROKER_STORE` or `--store-dir`. Each append records the version, hash, capabilities, decision digest, confirmer, and timestamp.
- **Updates.** A prior anchor can satisfy capability confirmation when its hash matches and it covers the current capability set. New evidence and source policy still apply. The journal preserves v1 hash records for history. A v2 candidate needs a v2 anchor.

## 10. Runtime audit

| Host event | Recorded evidence |
|---|---|
| `tools/pre-execute` | Tool name, digest of canonical JSON arguments after sensitive keys are redacted, inferred capability intent, and scope verdict. A confirmed scope violation produces `scope_exceeded`. |
| `tools/post-execute` | Model-visible difference between the original result and the downstream `PostToolDecision`, including replacement output, added context, or blocking feedback. |
| `system-prompt/assemble` | Before and after digests. A change produces `context_write(prompt_assembly)`. |
| `agent/inbox/inserted` | Message digest as `context_write(inbox_insert)`. |
| `session/event` for `compaction/*` | History compaction as `context_write(history_compress)`. |

Records append to `<store_dir>/audit.jsonl`. See the [audit schema](docs/AUDIT-SCHEMA.en.md) for fields and examples. Observers preserve DSH decisions and context. An audit write error emits a warning and preserves the dispatch outcome. Unload cancels in-flight evaluations and closes the writer so late callbacks cannot reopen it.

Set tool ownership through `RuntimeAuditConfig.tool_owners` or `service.setToolOwner()`. Calls with unknown ownership are `unattributed`.

## 11. Policy configuration

CLI parameters override policy file settings, which override defaults. Example `policy.json`:

```json
{
  "require_ack_for_unstated": true,
  "confirm_on_new_capability": true,
  "block_on_unscannable": true,
  "block_on_source_hash_mismatch": true,
  "confirm_on_non_registry_dependency": false,
  "external_red_lines": "display",
  "hash_excludes": [],
  "store_dir": "/Users/me/.dsh/trust-broker"
}
```

Pass the file with `--policy ./policy.json`. To run an external scanner, set `trust_check_bin` to a trusted absolute executable path outside the candidate tree. The decision includes the effective policy. Admission always checks the whole candidate tree and blocks incomplete evaluation.

Host runtime configuration supports `store_dir`, `tool_owners`, `tool_capabilities`, `redact_argument_keys`, and `context_audit`.

## 12. Failure modes

| Condition | Decision status | Default action |
|---|---|---|
| Unreadable plugin directory or missing `package.json` | `unscannable` | `block_for_review` |
| Incomplete coverage, unreadable file, scan limit, or external scanner failure | `unscannable` | `block_for_review` |
| Unreadable anchor journal, or any line that cannot be parsed or validated | `unscannable` | `block_for_review` |
| Capability declaration cannot be parsed | `malformed_manifest` | `confirm` through the missing-declaration acknowledgment |
| Existing declaration omits a detected capability | `scanned` with an `incomplete` declaration and Type A difference | `confirm` for new high-privilege capabilities |
| Hash unavailable, manifest cannot be identified, or candidate changes during evaluation | `unscannable` with `content_hash: null` | `block_for_review` |
| Trusted expected hash differs from the candidate hash | `scanned` with a Type C difference | `block_for_review` |
| New high-privilege capability awaits acknowledgment | `scanned` | `confirm` |
| Missing declaration awaits acknowledgment | `scanned` with an `unstated` declaration | `confirm` |

## 13. v1 acceptance checklist

| Requirement | Implementation |
|---|---|
| Disclose that a candidate runs as Host code | The terminal disclosure and `decision.host_code: true`. |
| Distinguish complete, missing, incomplete, and malformed declarations | `declaration.status` and the required acknowledgment for unstated declarations. |
| Show detected categories and applicable differences | `capabilities.categories` and `diffs[]` with evidence pointers. |
| Surface install scripts, auto-update, and remote content | `summary.install_scripts`, `summary.auto_update`, and `continuous_trust_warning`. |
| Provide a copyable hash and persist confirmed content | Terminal and JSON output, explicit acceptance, a recheck, and an append to `anchors.jsonl`. |
| Pause for new high-privilege capabilities | `action: confirm` and exit code 2 until the acknowledgment is supplied. |

## 14. Ecosystem integration

- **`dsh-trust-check`.** The broker consumes schema 2 `--dir --json` reports and maps scanner findings such as shell use, filesystem access, network, credentials, environment access, subagents, LLM calls, and dynamic code to the capability catalog. Local heuristic results remain independent. Explicit scanner startup errors, timeouts, limits, nonzero exits, and invalid reports block evaluation.
- **`dsh-plugin-guard`.** This separate project handles Web client plugin isolation and self-update. The broker has no dependency on it.
- **DSH dispatch.** The Host and the standalone CLI carry out the broker's own filesystem operations. DSH retains tool-call approvals and sandbox decisions.
- **Install and update trust.** Git sources, installation scripts, and automatic updates can introduce bytes outside the reviewed tree. Evaluate the materialized candidate used for activation.

## 15. Known limits

1. **Loader enforcement.** For the DSH 0.2.x integration described here, the loader must consume the CLI gate or trusted Host service and bind approval to the same tree it activates. A new download, dependency installation, generated file, or source replacement after confirmation requires another review.
2. **Tool attribution.** Scope reporting depends on an explicit ownership map. Unknown owners appear as `unattributed`.
3. **Static analysis.** Dynamic imports, string construction, and credential access patterns can evade static rules. Treat findings as positive evidence of observed patterns.
4. **Audit failures.** Audit writes are fail-open for DSH dispatch. A consumer that requires blocking on an audit failure must enforce that policy itself.
5. **User interface.** The CLI provides interactive confirmation and a JSON contract for external clients. Interactive prompts and human-readable diagnostics currently use Chinese.
6. **Provenance.** A trusted caller supplies registry signature evidence and publication metadata. The broker reports a verified signature when the caller marks it verified and supplies a matching extracted-tree `content_sha256`. Verify the archive's SHA-256 or npm SRI before extraction.

## 16. Project layout

```text
dsh-plugin-trust-broker/
├── src/
│   ├── types.ts                 # Decisions, differences, anchors, audit, and policy
│   ├── version.ts               # Version and acknowledgment phrases
│   ├── core/
│   │   ├── catalog.ts           # Capabilities, privilege, and tool mappings
│   │   ├── manifest.ts          # Manifest, declaration, and dependency inventory
│   │   ├── external-scan.ts     # Explicit scanner executable or schema 2 report
│   │   ├── heuristic.ts         # Built-in static scanner
│   │   ├── detector.ts          # Capability evidence and auto-update signals
│   │   ├── diff.ts              # Declaration, drift, and source differences
│   │   ├── hash.ts              # Canonical content hash and snapshot
│   │   ├── tree-files.ts        # Bounded tree reads and path checks
│   │   ├── anchor-store.ts      # Append-only trust anchors
│   │   ├── drift.ts             # Comparison with a prior confirmed anchor
│   │   ├── decision.ts          # Evaluation and confirmation requirements
│   │   ├── policy.ts            # Defaults and policy files
│   │   ├── fs-utils.ts          # Canonical JSON, digests, and redaction
│   │   └── jsonl.ts             # Append-only JSONL storage
│   ├── runtime/                 # Audit observers, logging, and capability scope
│   ├── admission/gate.ts        # Confirmation, final hash check, and anchor write
│   ├── plugin/index.ts          # DSH Host bundle entry
│   ├── cli/                     # review, confirm, anchors, audit, and scan
│   └── index.ts                 # Public library exports
├── bin/trust-broker.mjs         # Packaged CLI entry
├── test/                        # node:test suite and plugin fixtures
├── examples/demo-plugin/        # Demo with capability declaration gaps
├── docs/                        # Architecture, security model, audit schema, and review
├── cordis.patch.yml             # DSH bundle patch
├── locale/                      # Chinese and English bundle metadata
└── package.json / tsconfig*.json
```

## 17. Verification

Run `npm ci --ignore-scripts` and `npm run check` for type checking, regression tests, and the build (**198 tests at the time of writing**). The security regressions cover path escapes, ambiguous hash records, candidate changes, scanner failure and cancellation, bundle-patch composition changes, terminal display, decision forwarding, unload, and the packaged entry point.

**Installation status (2026-11-08)**: installed into the current DSH desktop profile (DSH 0.2.2-rc.1) with `application: "applied"`, no warnings, as a `link:` to the workspace. The runtime audit is live at `~/.dsh/trust-broker/audit.jsonl` (`audit --verify` passes); **loader-side admission is still not wired** (see §15), so installation does not gate `plugin_manager` installs.

See the [adversarial review](docs/reviews/structure-review.en.md) and the [round-2 review and installation verification](docs/reviews/install-readiness-round2.en.md).

## 18. License

[MIT](LICENSE). [`dsh-trust-check`](https://www.npmjs.com/package/dsh-trust-check) is an independent MIT-licensed project.
