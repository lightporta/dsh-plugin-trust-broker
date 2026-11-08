# Pre-install review and installation verification (round 2)

[中文审查记录](install-readiness-round2.zh-CN.md)

- **Date**: 2026-11-08
- **Target**: `/Users/anowell/Documents/Github-Projects/dsh-plugin-trust-broker`
- **Reviewed baseline**: HEAD `b3eeb73`
- **Fix commit**: `980bfd0` ("Cover the bundle-patch composition surface before installation")
- **Installation**: installed into the current DSH desktop profile and verified through the live runtime audit (§5)
- **Method**: two independent read-only reviewers (install readiness / adversarial) plus a Lead self-review and a dogfood review of the packed artifact with this tool's own CLI

## 1. Verdict

**GO for installation: no installation blockers.** Both independent reviewers confirmed the bundle manifest, DSH version compatibility, patch resolution, locale/icon resources, Host `apply()` lifecycle and Cordis unload semantics. The desktop host (DSH 0.2.2-rc.1) reported `application: "applied"`.

The adversarial review did find a **major bypass in the tool's own bundle-patch composition coverage**, contradicting the documented behavior. It does not block installing this bundle (our own patch only inserts our own row), but it would let a future pre-install gate miss realistic patches. It was fixed in the fail-closed direction and re-verified before installation.

## 2. Findings and fixes

| # | Severity | Finding | Fix |
|---|---|---|---|
| M1 | major | `dsh.bundle.patch` was analysed only for the string form and only when the file was named `cordis.patch.yml`, using line regexes. Array form was unvalidated; standard DSH id-targeted `config:` replacement, `disabled: True/TRUE`, multiline booleans, JSON/flow patches all bypassed detection → `proceed` with no diff. | Structural patch parsing (JSON array or block list) that follows DSH loader semantics. Every manifest-declared patch path is validated and parsed; `insert` entries stay low privilege; **every non-insert top-level entry** is an id-targeted profile-row mutation → high-privilege `composition.override` → mandatory first-install confirmation. Missing, binary, out-of-tree or unparsable patches fail closed (`unscannable`). |
| M2 | major | `composition.override` was marked high privilege and non-declarable, but without an anchor no A/B diff was produced, so it never entered the mandatory confirmation queue. | New diff code `observed_non_declarable_capability`: on first install the fact yields a `new_capability: true` type-A diff and a mandatory confirmation; not repeated when an anchor already covers it or the content hash matches. |
| m1 | minor | External-scanner `injections[].detail` was not URL-credential-redacted or length-capped. | Redact URL credentials, collapse whitespace, cap at 200 characters. |
| m2 | minor | `context_audit:false` suppressed only inbox/compaction, not prompt assembly / tool-output rewrite. | Suppress every derived `context_write` channel; `tool_result.rewritten` is still recorded. |
| m3 | minor | `anchors --json` / `audit --json` hid corrupt-journal errors and exited 0. | JSON now carries `errors`; corruption exits 1. |
| m4 | minor | `require_ack_for_unstated:false` also suppressed detection-derived confirmations for unstated/malformed plugins. | Documented as an explicit relaxation recorded in the decision's `policy` field. |
| m5 | minor | Remote-content indicators skipped `preinstall`/`install` scripts. | All five lifecycle scripts are scanned. |
| m6 | minor | Strict hashing rejects symlinks/hardlinks, so pnpm/npm-materialized trees are `unscannable`. | Documented: review/anchor a clean `npm pack` extraction or a controlled staging copy. |
| — | minor | `dist/` is gitignored; packing from a clean checkout would miss build output. | Added `prepack: npm run build` (not an install lifecycle script). |
| — | minor | `engines.dsh` single range is unfriendly to default-semver tooling with prereleases. | `>=0.2.0-rc.2 \|\| >=0.2.1-rc.2 \|\| >=0.2.2-rc.1` (DSH uses `includePrerelease`, both validators pass). |

## 3. Tests and verification

- `npm run check`: typecheck clean, **198 / 198 tests pass**, `dist/` build clean.
- New `test/review-fixes.test.ts` (15 regressions): array-form patches, real DSH patch forms, `disabled: True`, JSON patches, binary/unparsable patches, stray patch files, scanner-detail redaction, `context_audit` gating, corrupt-journal CLI exit codes.
- Re-ran the adversarial reviewer's probes: all eight `r9` bypass forms now `confirm`; `r10` comment/config false positives gone; `r4` stray/out-of-tree/binary/missing patches fail closed; declared patch count capped at 64.
- `npm pack --dry-run`: 69 files including `dist/plugin/index.js`, patch, locale, icon; no `src/test/examples/node_modules` leakage.
- DSH compatibility: the real `@deepseek-ai/dsh-app-boot` `evaluatePluginCompatibility()` returns compatible for 0.2.0-rc.2 / 0.2.1-rc.2 / 0.2.2-rc.1; `loadOverlayPatches()` yields the same insert row; `readPluginMeta()` resolves en/zh titles, descriptions and the SVG icon.
- Real Cordis 4.1.0 in-memory integration: `apply()` provides `trustBroker`, registers all five audit listeners, waterfall listeners return `next()` unchanged, and unload leaves no post-dispose writes.

## 4. Installation

```text
plugin_manager({ action: "install_bundle", target: "/Users/anowell/Documents/Github-Projects/dsh-plugin-trust-broker" })
→ application: "applied"; warnings: []; registries: [null]
→ dependencies: + dsh-plugin-trust-broker 0.1.0 <- ../../Documents/Github-Projects/dsh-plugin-trust-broker
→ profile bundles: dsh-plugin-trust-broker appended
```

- Profile: `/Users/anowell/.dsh/profiles/desktop`; installed as a `link:` dependency to the workspace (`node_modules/dsh-plugin-trust-broker` is a symlink).
- Installation did not modify the repository (`git status --short` is empty).
- `Config.listConfigs {name:"dsh-plugin-trust-broker"}` returns one entry `include:dsh-plugin-trust-broker` (no Config export, so `status: absent` is expected) with `packageDir` pointing into the profile.
- `Service.listService {service:"trustBroker"}` does not list the plain object provided by `ctx.provide` (the inspect directory catalogues Service classes only), so activation is proven by the live runtime audit instead.

## 5. Live runtime evidence

- After installation, tool calls immediately append to `~/.dsh/trust-broker/audit.jsonl` (directory 0700, file 0600):
  - `schema_version: 1`, `event`, monotonic `seq`, `id`, `ts`;
  - `tool_call` with `arguments_digest` (SHA-256 of canonical JSON after redaction), `argument_keys`, inferred capability categories and `scope: unattributed` (expected without `tool_owners`);
  - `tool_result` with `ok`, `result_digest`, `settled_digest` and `rewritten`.
- `node bin/trust-broker.mjs audit --verify --json` → `records: 8, problems: []`.
- The anchor journal is empty (no CLI confirmation/anchor has been performed; installation itself does not write anchors).
- The first record is the install operation's own `tool_result` (the plugin activated during installation); later `cordis_inspect_query` and `bash` calls are recorded normally.

## 6. Residual boundaries (must be stated, none block installation)

1. **Installing this bundle does not gate `plugin_manager` installs.** DSH 0.2.x has no loader-level pre-apply veto; what becomes active is the runtime audit plus the `trustBroker` service. Pre-install review/anchor still requires running the CLI first or wiring the Host service into an admission flow.
2. **GUI rendering is unverified**: title/description/icon were statically validated with the real `readPluginMeta`; rendering in the desktop page needs browser control and was not covered.
3. **Tool attribution**: `scope` defaults to `unattributed`; real `declared / undeclared_scope` verdicts need `tool_owners` or `setToolOwner`.
4. **Audit growth**: `audit.jsonl` is append-only with at least one line per tool call and no rotation in v1; long-term profiles need external rotation.
5. **Self-review noise**: scanning this tool's own packed artifact still produces `confirm` false positives because static scanners match the broker's own rule-table text (`fetch(`, capability names). Recorded as a static self-reference limitation; it does not affect installation.
6. **Anchoring prerequisite**: strict hashing rejects symlinks/hardlinks; anchor a clean packed extraction or controlled staging directory, not a workspace with `node_modules`.

## 7. Rollback

```text
plugin_manager({ action: "remove_bundle", target: "dsh-plugin-trust-broker" })
```

Removal stops the runtime audit; existing `~/.dsh/trust-broker/audit.jsonl` records remain (clean up manually if desired).
