# Web pre-install security review (v0.2.0)

Status: shipped with `dsh-plugin-trust-broker@0.2.0` and installed into the current DSH desktop profile. Host routes and real reviews are verified; pixel rendering and the confirm-to-native-install click path are not browser-automation verified.

## 1. Why this is not embedded in the built-in install dialog

The built-in **Add plugin** dialog (spec input, install button) is a fixed component in `@deepseek-ai/dsh-client-ui-plugin-manager`. Its live Slot tree exposes **no injectable slot**, so a plugin cannot append review output inside that dialog.

Supported extension points in DSH 0.2.2-rc.1:

| Slot | Purpose | Used here |
|---|---|---|
| `plugins.tab` | Add a tab to the Plugins page; the owner also gives `install(target)`, which opens the native install check/progress UI directly | **Yes**: `trust-broker-review` ("Security review") |
| `plugins.add.actions` | Add rows to the "+" menu | No |
| `plugins.detail.section` | Add sections to a bundle detail page | No |
| `plugins.bundle.config` / `plugins.row.config` | Configuration forms | No (this bundle has no Config) |

The result is an equivalent flow, not a replacement of the shipped dialog:

- entry point: Plugins page → **Security review** tab;
- after confirmation: hand off to the native install check/progress UI;
- model-initiated installs: native approval prompt.

## 2. User flow

1. Open **Plugins → Security review** (after Installed / Discover).
2. Enter an npm spec (`name`, `name@version`, range, tag), a GitHub/git URL, or a local directory. A review starts 700 ms after typing stops; "Review again" / Enter also works.
3. The panel shows, in order: the fixed Host-code notice; source trust and declaration status; detected capabilities (verified facts vs `heuristic:true`); install scripts, AUTO_UPDATE / remote content and continuous-trust warning; copyable content hash and resolved name/version/source/registry/integrity; A/B/C diffs with evidence; suggested action (proceed / confirm / block); per-requirement acknowledgements.
4. **Confirm and install** is enabled only after every required acknowledgement is checked. It:
   1. calls `POST api/trust-broker/confirm` to write the `TrustAnchor`;
   2. calls the owner-provided `install({spec: review.resolved.install_spec, title, version, registry?})`, which opens the native install check/progress UI.
5. Installation is owned by the native flow; the tab only reports that the anchor was written and the install was handed off.

Model path: when the model calls `plugin_manager` `install_bundle`, the Host reviews the target in `tools/pre-execute` and puts the summary into the native approval prompt; installation proceeds only after the user approves.

## 3. Host implementation

- Entry: `createTrustHostServices()` in `src/host/service.ts`.
- Candidate acquisition (`src/host/spec.ts` + `materialize.ts`):
  - local directory: reviewed in place, never copied or deleted;
  - npm: registry metadata → exact version / tag / common range → tarball (60 s, 64 MiB caps) → verify `dist.integrity` (sha512/sha256/sha1) or legacy shasum → built-in tar reader;
  - git: `git clone --depth 1 --single-branch --no-tags` (argv-only, no shell, timeout/abort), remove `.git` before review;
  - tarball URL/local archive: fetch or read, then the same safe extraction.
- The tar reader uses only `node:zlib` and rejects absolute paths, `..`, NULs, duplicate paths, symlinks, hardlinks, device/FIFO entries, PAX path smuggling, and oversized content; it strips the npm tarball `package/` prefix.
- Review: `evaluatePluginTrust({ noExternalScanner: true, ... })`, sharing declaration/diff/hash/confirmation semantics with the CLI.
- Review cache: 30-minute TTL, 32-entry LRU; confirm is single-use and writes the anchor; unknown/expired reviews return `review_expired`; a null content hash is rejected with `blocked_for_review` (never a fabricated anchor).
- Same-origin HTTP routes (mounted by the Host at `/api/trust-broker`):
  - `POST /review` `{spec}` → `{ok:true, review}` / `{ok:false, error}`;
  - `POST /confirm` `{review_id, acknowledgements:[codes]}` → `{ok:true, anchor}` / `{ok:false, error}`;
  - `GET /health` → `{ok:true, version, store_dir}`.
- Candidate directories live under `<store_dir>/candidates/review-*` (0700; files 0600) and are never included in wire JSON; they are removed on failure, eviction, confirmation, or dispose.

## 4. Security semantics and limits

- **The review binds the extracted-tree hash reviewed here**, not future installed bytes. The native flow re-fetches `install_spec`:
  - npm is pinned to an exact version (registry contents are normally immutable);
  - git specs are not commit-pinned;
  - tarball URLs can change.
- **Not a loader veto**: DSH 0.2.x has no pre-apply hook; the built-in "install third-party plugin" dialog can still bypass this review. Full enforcement needs an upstream slot in that dialog.
- **Model install gate**: `plugin_manager install_bundle` first pauses in native approval. When the review cannot complete, the prompt still states that clearly and lets the user decide, matching the CLI rule that a failed review must not be reported as safe.
- **Network capability**: registry metadata/tarball acquisition uses `fetch` on the Host, so `package.json#dsh.capabilities` now declares `network.fetch: true` (previously false); git clone uses the already-declared `process.child_process`.
- **Latency**: npm/git candidates require download/clone; a model install approval appears only after the review finishes (bounded to ~60 s). The UI uses skeletons, abort, and expiry guards.
- **UI review state is not persisted**: switching tabs requires a fresh review; anchors are persistent.

## 5. Verification record (2026-11-09)

- `npm run check`: **226/226 tests pass**, typecheck and build clean; `npm pack --dry-run` lists 84 files including `client.js` and `dist/host/**`.
- Reinstalled 0.2.0: `application: applied`, `warnings: []`, `link:` to the workspace.
- Host live checks:
  - `GET /api/trust-broker/health` → `{"ok":true,"version":"0.2.0","store_dir":"/Users/anowell/.dsh/trust-broker"}`;
  - local directory review → `scanned` / `proceed` / `declared` / content hash `sha256:8aec…`;
  - npm `dsh-context@0.82.2` → tarball fetched in ~2.1 s, `integrity: "verified"`, `declaration: "unstated"`, `unstated_capabilities` acknowledgement required;
  - empty spec → `invalid_spec`.
- Client: live Slot inspection shows `plugins.tab` occupants `discover` and `trust-broker-review` (active).
- Not verified: real pixel rendering and light/dark themes, the native install dialog after clicking Confirm and install, and the real-session rendering of the model-install approval prompt (no browser control; API and slot registration were observed directly).

## 6. Troubleshooting

- **The Security review tab is missing**: refresh the DSH page once (the client module may need a reload after install); confirm the plugin is enabled and version 0.2.0.
- **`registry_unreachable` / timeout**: check network/proxy or switch the npm registry; local-directory reviews need no network.
- **Confirm button disabled**: ensure every required acknowledgement is checked, the review is not expired/stale, `content_hash` is non-null (unscannable cannot be anchored), and the suggested action is not `block_for_review`.
- **Install did not continue**: confirm the anchor was written; if the page lacks an `install` owner prop it shows "anchor only" and asks you to install from the Plugins page.
- **Review route 404**: the new Host version is not active or webServer is unavailable; check that `/api/trust-broker/health` returns 0.2.0.
