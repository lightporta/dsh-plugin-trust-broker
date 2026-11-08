# dsh-plugin-trust-broker structure, assembly, and lifecycle review

[简体中文](./structure-review.zh-CN.md)

## Adversarial follow-up on 2026-11-08

**The initial decision was `block_for_review`.** The original implementation could admit a candidate after a failed scan, associate review evidence with the wrong content hash, and run a scanner outside the release lockfile during Host evaluation.

The fixes cover the 15 substantive findings below and the three action items from the original structure review. Verification covers the source, build output, release archive, and native components of the local DSH 0.2.1-rc.2 installation. Shipping the plugin as a mandatory admission gate still requires integrating the actual loader and verifying that it uses the same controlled, materialized content from user confirmation through `apply()`. Native `ctx.approval` handles one-time decisions in DSH sessions. The standalone CLI's confirmations and anchors provide evidence for a trusted loader to consume. [Official DSH approval contract](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/approval.md)

## Initial static structure review (historical record)

- `blocker` — 0
- `should-fix` — 3
- `nit` — 0

The Host entry point, bundle patch, and actual exports matched in the static review. The observed assembly was Host-only. Two unload lifecycle gaps and a missing capability declaration required fixes.

The initial review inspected `package.json`, `cordis.patch.yml`, `src/`, the loaded `dist/` output, the README, and related documentation. Its scope was read-only static inspection.

## Initial findings (before fixes)

**[should-fix] Lifecycle**  
`dsh-plugin-trust-broker/src/core/external-scan.ts:277`

### Observed behavior

- `runScannerProcess()` creates the external scanner child process here and sets timeout and SIGKILL timers at `src/core/external-scan.ts:290` and `:300`.
- Host `trustBroker.evaluate()` reaches this path through `src/plugin/index.ts:35`, so the child and timers belong to the plugin Fiber's runtime as well as the standalone CLI.
- Normal completion, errors, and the 30-second timeout trigger cleanup. The disposer at `src/plugin/index.ts:44` only calls `handle.dispose()`. Unloading the Fiber leaves the active scan and both timers running.
- The loaded output contains the same code at `dist/core/external-scan.js:192`, `:205`, and `:216`.

### Why it matters under the DSH contract

Cordis automatically removes listeners and services registered through its APIs. DSH expects the disposer returned by `ctx.effect()` to clean up child processes and timers. The scanner can outlive its Fiber until the timeout, so that timeout leaves a gap in unload cleanup.

### Proposed fix at the time

1. Carry an `AbortSignal` through `EvaluateOptions`, `DetectInput`, and `ExternalScanInput`, and observe it in `runScannerProcess()`.
2. On abort, clear the main timer and `killTimer`, stop the child process, and settle the promise in one cleanup routine. If cleanup escalates from SIGTERM to SIGKILL, sequence those steps in that routine.
3. In `src/plugin/index.ts`, track active scan controllers in `apply()`. Abort them in the existing `ctx.effect()` disposer before closing audit resources. After unload, reject new `evaluate()` scans. For the CLI, retain its in-process timeout cleanup.

---

**[should-fix] Lifecycle**  
`dsh-plugin-trust-broker/src/runtime/audit.ts:199`

### Observed behavior

- `tools/post-execute` and `system-prompt/assemble` await asynchronous `next()` calls at `src/runtime/audit.ts:199` and `:232`, then write audit records.
- At unload, `src/plugin/index.ts:44` calls `handle.dispose()`. The implementation at `src/runtime/audit.ts:394` synchronously calls `auditLog.close()` and leaves the in-flight callbacks pending.
- If unload happens during the await, it closes the handle first. The resumed callback runs `recordDraft()`. At `src/core/jsonl.ts:89-92`, `#fd === null` triggers `openSync()` again. This writes after unload and leaves a descriptor beyond the effect's cleanup lifetime.
- `append()` can reopen a closed `JsonlWriter`. The loaded output behaves the same way at `dist/runtime/audit.js:156`, `:186`, and `:335`, and at `dist/core/jsonl.js:77-80`.

### Why it matters under the DSH contract

Effect disposers own file handle cleanup. The disposer and in-flight listeners run independently, so callbacks can reacquire resources after unload. One disposer needs to enforce the order of cleanup steps.

### Proposed fix at the time

1. In `createRuntimeAudit()`, track in-flight waterfall promises and have `handle.dispose()` return a promise.
2. Use one asynchronous disposer in `src/plugin/index.ts`. Stop accepting audit writes and service calls, await accepted callbacks with `Promise.allSettled()`, and then call `auditLog.close()`.
3. Give `JsonlWriter` an explicit `closed` state. After `close()`, reject `append()` so late callbacks cannot reopen the file.

---

**[should-fix] Capability declaration**  
`dsh-plugin-trust-broker/package.json:42`

### Observed behavior

The `dsh` block contains only `bundle` and `compatibility`. With `dsh.capabilities`, `dsh.permissions`, and top-level `permissions` absent, the declaration status is **`unstated`**. The implementation exercises these capabilities:

- **File reads and writes.** It reads candidate plugin trees, scanner reports, policy, and anchors. It creates and appends to `audit.jsonl`, `anchors.jsonl`, and `decisions.jsonl`. See `src/core/hash.ts:382`, `src/core/external-scan.ts:192`, and `src/core/jsonl.ts:28` and `:91`.
- **Child processes.** Default evaluation can run `dsh-trust-check --dir <root> --json`. The spawn uses `shell: false` and an argument vector. See `src/core/external-scan.ts:277` and `:338`.
- **Environment variables.** It reads `DSH_TRUST_BROKER_STORE`, `DSH_HOME`, and `DSH_TRUST_CHECK_BIN`. See `src/runtime/audit.ts:408-411` and `src/core/policy.ts:12-23`.
- **Host assembly.** It registers five Host listeners and provides `trustBroker` through `ctx.provide()`. See `src/runtime/audit.ts:298-331` and `src/plugin/index.ts:43`.
- **Module loading.** It dynamically imports the fixed module name `dsh-trust-check`. See `src/core/external-scan.ts:222-224`.
- The static scan covered direct networking, `node:vm`, `eval`, and `new Function` without observing their use. Code in `apply()` runs with Host privileges regardless of tool exposure.

### Why it matters under the DSH contract

An undeclared plugin can still run Host code. A pre-install review needs an explicit manifest to compare observed behavior against the author's declaration. The missing declaration matches the project's own `unstated` semantics at `README.md:188`. Its severity in this initial review was `should-fix`.

### Proposed fix at the time

Add a `capabilities` field under `package.json#dsh` using the project's declaration format:

```json
{
  "network": { "fetch": false, "socket": false },
  "process": { "child_process": true, "exec": false },
  "filesystem": { "read": true, "write": true },
  "env": {
    "read": ["DSH_TRUST_BROKER_STORE", "DSH_HOME", "DSH_TRUST_CHECK_BIN"]
  },
  "tool_registry": { "add": false, "override": false, "intercept": true },
  "context": {
    "prompt_inject": false,
    "tool_output_rewrite": false,
    "history_compress": false
  },
  "dynamic_code": { "eval": false }
}
```

`tool_registry.intercept` covers pre- and post-execution observation and calls to the waterfall. `context.tool_output_rewrite` stays `false` because the observer passes through the tool result. Callers configure file roots and scanner paths, so the declaration leaves `roots` unspecified.

## Initial category checks (before fixes)

### 1. Extension point consistency

The static check found consistent Host assembly.

- `package.json:13` points the Host main entry to `dist/plugin/index.js`. It exports `name` and `apply()`, which uses Host events and `ctx.provide()` as declared.
- The package defines only a Host entry and build. It has no `dsh.client` declaration, client entry, or Web dependencies.
- The observed extension points were the Host service and audit listeners. The review also checked for `tools.register`, `systemPrompt`, agent creation, LLMs, HTTP servers, and providers. `agent/inbox/inserted` and `session/event` only observe events for audit.

### 2. Lifecycle pairing

Beyond the two findings above, the observed resources had cleanup paths:

- Cordis automatically removes the five `ctx.on()` listeners and the `ctx.provide()` registration.
- The long-lived audit handle is tied to `ctx.effect()`. In-flight callbacks could still reopen it as described above.
- The one-off JSONL writer closes in `finally` at `src/core/jsonl.ts:29-34`. The hash operation closes file handles at `src/core/hash.ts:399-405`, and the CLI closes readline in `finally` at `src/cli/main.ts:764-765`.
- The scanner process and its timers account for the remaining observed external resources.

### 3. Assembly path verification

The declared and built assembly paths matched in the static check.

- The `./cordis.patch.yml` path at `package.json:44` exists. Its `id: dsh-plugin-trust-broker` and `name: dsh-plugin-trust-broker` match `package.json:2` and the exported name at `src/version.ts:3`.
- The `./dist/plugin/index.js` entry at `package.json:13` exists and retains `apply()`, service registration, and the effect disposer. The publish list at `package.json:32-40` includes `dist/**` and the patch.
- The README requires building before installation, consistent with `dist/` being ignored by Git.
- `/Users/me/...` at `README.md:241` is a policy example. Runtime code and the patch use portable paths.
- Verification relied on the declared bundle patch and built output. A real Profile installation remained outside the initial static check.

### 4. Declared and observed capabilities

The declaration status was **`unstated`**, as detailed above. The static check also looked for execution of external input through `node:vm` and for code that contradicted any explicit `false` declarations.

## Adversarial findings

Line numbers identify the source before the fixes. Paths are relative to `dsh-plugin-trust-broker/`. Confidence reflects the strength of the evidence.

```json
[
  {
    "file": "src/plugin/index.ts",
    "line_start": 35,
    "line_end": 40,
    "category": "approval_bypass",
    "what_can_go_wrong": "A Host caller can turn an evaluation request into a request to run a chosen program. The caller can also choose where reports and anchors come from.",
    "why_this_path_is_vulnerable": "The service forwards EvaluateOptions verbatim, allowing callers to override trust_check_bin, scannerReport, anchorsFile, and admission policy. If the call chain forwards candidate-supplied options, side effects happen before user confirmation.",
    "likely_impact": "The scanner can run with the Host user’s privileges, or the admission baseline can be forged. This path requires a trusted Host integration to forward untrusted input.",
    "concrete_fix": "Accept only the root selected by a trusted Host caller and a cancellation signal. Use fixed journals and the built-in scan. Require the CLI operator to configure any external scanner explicitly.",
    "confidence": 0.99
  },
  {
    "file": "src/admission/gate.ts",
    "line_start": 98,
    "line_end": 128,
    "category": "approval_bypass",
    "what_can_go_wrong": "An old decision can admit a replacement candidate tree, and the gate can report accepted with an empty content hash.",
    "why_this_path_is_vulnerable": "The gate only compares the user’s hash with the old decision. The JSON entry bypasses the CLI-specific recheck. Evaluation scans before hashing, so a caller can scan tree A and anchor its replacement, tree B.",
    "likely_impact": "The confirmed evidence can describe different code from the code the loader will use. Installation orchestration can receive a false success signal.",
    "concrete_fix": "Hash a private snapshot as it is copied, scan those same bytes, and recheck the original tree. Use one gate to require explicit acceptance of the full hash. Return accepted only after a final check and successful persistence.",
    "confidence": 1.0
  },
  {
    "file": "src/cli/render.ts",
    "line_start": 190,
    "line_end": 200,
    "category": "approval_bypass",
    "what_can_go_wrong": "Candidate-supplied control sequences can clear the screen, move the cursor, or forge a confirmation prompt.",
    "why_this_path_is_vulnerable": "The renderer sends plugin versions, evidence, and errors directly to the terminal. The interactive CLI asks for mandatory confirmation before displaying the full decision.",
    "likely_impact": "The operator may miss the actual candidate identity, permissions, or risk before approving it.",
    "concrete_fix": "Display the full decision first and escape untrusted control characters, newlines, and directional controls. Request confirmation in an actual interactive terminal.",
    "confidence": 0.99
  },
  {
    "file": "src/core/external-scan.ts",
    "line_start": 275,
    "line_end": 277,
    "category": "credential",
    "what_can_go_wrong": "The external scanner inherits the entire Host environment. A synthetic token can reach the decision output through stderr.",
    "why_this_path_is_vulnerable": "The spawn omits an explicit env, and lines 347–365 append raw stderr and parsing exceptions. Plugin evaluation has no need for these environment credentials.",
    "likely_impact": "The child can read API keys or login tokens. Logs or the terminal may retain them in plaintext.",
    "concrete_fix": "Construct a minimal child environment, discard stderr, use fixed error codes, and limit output size.",
    "confidence": 1.0
  },
  {
    "file": "src/runtime/audit.ts",
    "line_start": 366,
    "line_end": 374,
    "category": "credential",
    "what_can_go_wrong": "Caller-supplied audit objects can write error text, anchor notes, or extra fields into the log.",
    "why_this_path_is_vulnerable": "The writer appends the complete envelope as provided, spreads draft fields, and uses raw error messages for audit failures.",
    "likely_impact": "A local audit store intended to hold summaries can retain synthetic or real secrets.",
    "concrete_fix": "Rebuild each event from its allowed fields, digest free text, and omit anchor notes and raw exceptions. Give new logs private permissions.",
    "confidence": 1.0
  },
  {
    "file": "src/core/diff.ts",
    "line_start": 493,
    "line_end": 525,
    "category": "credential",
    "what_can_go_wrong": "Git, archive, and repository URLs containing userinfo or access-token parameters can appear in both human-readable and JSON review output.",
    "why_this_path_is_vulnerable": "The code copies dependency specs and repository URLs into facts, evidence, and diff summaries.",
    "likely_impact": "Sharing or archiving a review report can disclose download credentials.",
    "concrete_fix": "Remove URL userinfo and redact common credential query parameters before constructing facts or evidence. Preserve the source type and location.",
    "confidence": 0.99
  },
  {
    "file": "src/core/manifest.ts",
    "line_start": 110,
    "line_end": 119,
    "category": "file_boundary",
    "what_can_go_wrong": "A link from package.json to ../outside.json makes evaluation read identity and declarations from outside the tree.",
    "why_this_path_is_vulnerable": "The manifest reader follows links, while the hash covers only the link text. A path swap is also possible between a normal path check and opening the file.",
    "likely_impact": "External data can enter the review and be replaced without changing the candidate hash.",
    "concrete_fix": "Reject symbolic links, hard links, special files, and paths outside the candidate tree. Check the physical path and file descriptor identity while reading, then scan a private snapshot.",
    "confidence": 1.0
  },
  {
    "file": "src/core/diff.ts",
    "line_start": 40,
    "line_end": 48,
    "category": "failure_path",
    "what_can_go_wrong": "Admission can continue after an explicit scan times out or returns an invalid report or unsupported schema.",
    "why_this_path_is_vulnerable": "The decision checks an error-code list that differs from the scanner’s actual errors. The fallback scan can still be marked complete.",
    "likely_impact": "The caller’s required scan can be skipped, and the CLI can send downstream consumers a proceed signal.",
    "concrete_fix": "Always mark coverage incomplete when an explicit scan fails and return block_for_review. Keep heuristic diagnostics available.",
    "confidence": 1.0
  },
  {
    "file": "src/runtime/audit.ts",
    "line_start": 188,
    "line_end": 246,
    "category": "failure_path",
    "what_can_go_wrong": "A waterfall callback suspended during unload can reopen the log when it resumes.",
    "why_this_path_is_vulnerable": "The original disposer only closes the current descriptor. JsonlWriter treats the closed state as an unopened file, and retained Host service references can keep writing.",
    "likely_impact": "Unloading the plugin can leave audit writes and resource use active.",
    "concrete_fix": "Make the writer terminal immediately at unload, reject new service operations, and cancel and await in-flight evaluations. Let late callbacks pass through downstream results.",
    "confidence": 1.0
  },
  {
    "file": "src/core/external-scan.ts",
    "line_start": 168,
    "line_end": 185,
    "category": "supply_chain",
    "what_can_go_wrong": "The pre-install scan can automatically run a module or PATH executable outside the release lockfile.",
    "why_this_path_is_vulnerable": "Dynamic import executes the module’s top-level code before checking its interface, then attempts to start a PATH executable if the import fails. Both executable sources are independent of the Broker package.",
    "likely_impact": "Read-only evaluation becomes an entry point for unreviewed code. In a temporary test, a module that deliberately threw still wrote a marker first.",
    "concrete_fix": "Remove automatic imports and PATH discovery. Require a trusted absolute path for explicit scanners, reject executables from the candidate tree or snapshot, and bound execution time, output, and process lifetime.",
    "confidence": 1.0
  },
  {
    "file": "src/core/hash.ts",
    "line_start": 342,
    "line_end": 347,
    "category": "supply_chain",
    "what_can_go_wrong": "One filename containing a newline can yield the same normalized input as two files.",
    "why_this_path_is_vulnerable": "The aggregate manifest concatenates raw paths with newline separators.",
    "likely_impact": "A reproduction added fetch code by replacing the tree, while the old hash still matched and confirmation was skipped.",
    "concrete_fix": "Use the v2 domain and unambiguous JSON tuples for paths and content digests. Retain legacy hashes for historical records.",
    "confidence": 1.0
  },
  {
    "file": "src/core/hash.ts",
    "line_start": 43,
    "line_end": 44,
    "category": "supply_chain",
    "what_can_go_wrong": "Replacing only the imported code under node_modules can leave the old hash valid.",
    "why_this_path_is_vulnerable": "The default hash and heuristic scan exclude materialized dependencies. A lock declaration cannot describe the actual dependency bytes that execute locally.",
    "likely_impact": "A reproduction matched the old anchor and recommended proceeding, even though the dependency loaded by Node produced different output.",
    "concrete_fix": "Cover the full materialized tree in the admission hash and built-in scan. Have the loader preserve the link between approved content and the execution source.",
    "confidence": 1.0
  },
  {
    "file": "src/core/decision.ts",
    "line_start": 80,
    "line_end": 84,
    "category": "supply_chain",
    "what_can_go_wrong": "A matching content hash can bypass confirmation for new scan findings, red lines, or changes to supply chain policy.",
    "why_this_path_is_vulnerable": "Any matching anchor clears the full confirmation queue. A successful external report also displaces locally detected capabilities.",
    "likely_impact": "New evidence or stricter risk policy may fail to trigger renewed confirmation.",
    "concrete_fix": "Reuse capability confirmation only when the historical anchor covers the current capability set. Continue evaluating provenance policy and use external reports to supplement evidence.",
    "confidence": 0.99
  },
  {
    "file": "src/core/diff.ts",
    "line_start": 238,
    "line_end": 273,
    "category": "supply_chain",
    "what_can_go_wrong": "An invalid expected hash is ignored, and an input containing only registry_signature=verified can appear to have verified provenance.",
    "why_this_path_is_vulnerable": "A parse failure is treated as a missing hash. The signature status is independent of the actual candidate bytes.",
    "likely_impact": "The approver can see a provenance claim that exceeds the evidence, while a bad integrity setting fails silently.",
    "concrete_fix": "Reject invalid expected hashes. Display signed provenance only if a trusted caller reports successful verification and the extracted tree hash matches.",
    "confidence": 0.99
  },
  {
    "file": "src/runtime/audit.ts",
    "line_start": 188,
    "line_end": 223,
    "category": "context_integrity",
    "what_can_go_wrong": "A plain accept can be recorded as a tool-output rewrite, burying genuine model context changes in false positives.",
    "why_this_path_is_vulnerable": "The code compares a tool result directly to a structurally different PostToolDecision. The original test mocked next with a result object, hiding the actual contract.",
    "likely_impact": "Runtime audit can have trouble separating normal calls from real replacements, blocking feedback, and added context.",
    "concrete_fix": "Compare digests of the native decision’s before-and-after effects visible to the model. Pass through tool decisions, assembly results, and exceptions as received.",
    "confidence": 1.0
  }
]
```

### Final failure states

- Evaluation returns `unscannable / block_for_review` for unreadable candidate roots, manifests or lockfiles, incomplete hashes, unsupported file types, changes to the directory or content during review, or explicitly configured scanners that are missing, time out, exceed limits, exit with a nonzero status, or produce an unparseable report. Evaluation uses the built-in scan when the operator supplies no external scanner.
- A readable manifest identity with a malformed capability declaration defaults to `malformed_manifest / confirm`. A provenance hash mismatch defaults to `block_for_review`. A trusted policy can explicitly downgrade a provenance mismatch, which still requires `source_mismatch` confirmation. An invalid expected hash blocks immediately.
- A refused or missing confirmation, or a content change before anchoring, prevents the gate from writing the anchor. The CLI returns 2 for pending confirmation or changed content, 3 for a block, and 1 for anchor write failures or usage errors. A decision log write failure generates a separate warning.
- Audit classification failures preserve the current dispatch result. Unverifiable attribution is recorded as `unattributed`, and audit write failures generate warnings. Native denials and downstream exceptions propagate as received. Unload cancels pending evaluations and terminates writes. The failure paths stay within the existing sandbox permissions, and the project has no MCP call path.

### Supply chain and context inventory

- The Broker has zero runtime dependencies. `package-lock.json` pins development dependency versions and SRI values, all from the npm registry. The release excludes installation lifecycle scripts, auto-updates, and direct network fetches. The example plugin's `postinstall` belongs to the test candidate, which is outside the release archive.
- Evaluation reads external reports as structured data. The operator independently selects and verifies the code for any explicitly configured CLI scanner. The Broker lockfile covers only the Broker's dependencies. The candidate's `package.json` and npm v2/v3 lockfiles provide provenance inventory, and the admission hash covers the whole materialized tree. The loader still owns later downloads, code generated by installation scripts, external module resolution, and auto-updates.
- `tools/pre-execute` observes the request and returns the native `next()` decision. `tools/post-execute` observes result replacements, blocking feedback, and added context. `system-prompt/assemble` observes assembly before and after. `agent/inbox/inserted` and `session/event` observe inserted messages and completed history compaction. The Broker writes local JSONL summaries. Its declaration covers observer hooks and file access, with prompt injection, tool-output rewriting, and history compaction declared as false. [Official DSH extension conventions](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/cookbook/extension-cookbook.md)
- The Host reads environment variables for journal directory configuration and OS path resolution. The CLI reads the terminal color configuration. The external scanner environment contains only a PATH derived from the current Node executable directory. DSH retains authority over native tool approval. The Host service's exposed surface is limited to its evaluation and audit integration.

### Fixes for the original structure findings

1. The Host evaluation path uses the built-in scan, and the Fiber cancellation signal governs evaluation. The standalone CLI terminates an external scanner and clears its timers on timeout, cancellation, or limit exhaustion.
2. The audit disposer stops writes immediately, and closing the JSONL writer is terminal. In-flight native waterfalls still deliver their eventual results.
3. `package.json#dsh.capabilities` declares file, environment, child-process, and observer-hook capabilities. It declares context mutation, direct networking, and auto-update as false.

### Verification and remaining boundaries

- All 155 baseline tests passed before the fixes. Reproductions used temporary directories, synthetic tokens, and synthetic tools. They covered links to external manifests, newline hash ambiguity, replacement of excluded dependencies, anchoring stale decisions, tree swaps during scans, inherited scanner credentials, and false positives for native `accept`.
- After the fixes, `npm run check` passed type checking, 179 tests, and the `dist/` build. Offline packaging verified 63 archive entries, the Host exports, and the bundle patch. The packaged CLI paused a read-only review for confirmation and wrote one anchor after accepting the full hash. A separate adapter test used `dsh-trust-check@0.2.5`.
- The in-memory integration against native DSH 0.2.1-rc.2 covered loading, passing through denials, plain accept decisions, tool-result replacement, prompt assembly, and Fiber unload. It used temporary logs and synthetic tools. A real profile install, the user approval UI, and the post-install automatic loading gate still need integration testing.
- The private snapshot binds the evaluation evidence and the hash to the same bytes read during inspection. The last race before actual loading, dynamic imports, external dependencies, and adversarial behavior in the same process remain within the trusted loader and source isolation boundary. The loader needs to verify the same approved materialized tree and use `admission.accepted` as evidence of a persisted anchor. A standalone `review` exit code of 0 indicates its review result.

