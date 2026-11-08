# dsh-plugin-trust-broker · DSH 插件信任代理

[English README](README.en.md) · [架构](docs/ARCHITECTURE.md) · [安全模型](docs/SECURITY-MODEL.md) · [审计 schema](docs/AUDIT-SCHEMA.md) · [对抗性审查](docs/reviews/structure-review.zh-CN.md)

> 在第三方插件被加载进 DeepSeek Harness（DSH）Host 进程**之前**，产出一份可复核的信任决策：
> 权限声明 vs. 检出事实的差异、内容哈希与信任锚点、以及加载后覆盖网络/子进程/上下文写入的只追加审计。
>
> **它产出事实、差异、二元 `new_capability` 标注和建议动作；它不做“安全 / 恶意”裁决，不执行插件代码，不替代沙箱。**

---

## 1. 定位

DSH 插件以 Host 代码在宿主进程内运行，`dsh plugin add` 只做包管理，不展示权限清单、不校验来源、不绑定内容哈希。已有静态扫描器（如 [`dsh-trust-check`](https://www.npmjs.com/package/dsh-trust-check)）能给出能力事实，但**不回答**：

- 插件自己声明的权限与检出事实**差在哪**？
- 这次升级比上一版**新增**了什么高权限能力？
- 用户确认时看到的代码，能否在下次更新时**用哈希对上**？
- 沙箱之外的**网络外联意图、子进程意图、上下文写入**，事后能否追溯？

本项目就补这四层。它分两种形态运行：

| 形态 | 入口 | 用途 |
|---|---|---|
| **CLI**（终端） | `bin/trust-broker.mjs` / `npm run cli` | 安装前审查、确认、写锚点、查审计；输出可复制的 `content_hash`；退出码可做 CI 闸门 |
| **DSH Host bundle** | `src/plugin/index.ts`（`apply`） | 加载后注册 `tools/pre-execute`、`tools/post-execute` 等运行时审计；通过 `ctx.provide('trustBroker', …)` 暴露 `evaluate()` 给加载器/编排方在 `apply` 之前消费 |

两者共用同一套核心库（`src/core/*`、`src/admission/*`、`src/runtime/*`）。

## 2. 不做的事（边界声明）

- ❌ 不实现插件市场、不做评分、不做黑白名单、不做人工背书。
- ❌ 不做“安全 / 恶意”分类。输出只有事实、差异、`new_capability` 布尔标注、`proceed` / `confirm` / `block_for_review` 建议动作；最终授权归用户或上层策略。
- ❌ 不替代静态扫描器。内置启发式事实独立运行，标为 `heuristic: true`。CLI 可额外消费操作者信任的 `dsh-trust-check` schema 2 报告，或显式配置可信绝对路径 `trust_check_bin`。外部报告只能补充事实。
- ❌ 不替代沙箱：Broker 以 Host 进程权限读写指定树、私有临时副本和配置的日志。信任边界是调用者选定的来源与用户审批。原生工具派发继续由 DSH 决定。
- ❌ 不要求插件作者改代码：无声明插件走 `unstated` 降级路径（一次显式确认），而不是拒绝加载。
- ❌ 不做模型可见 prompt 的安全过滤：只记录上下文写入事件。
- ❌ v1 不含 Web GUI 面板：`--json` 输出即 GUI/自动化消费契约；终端满足验收要求（见 §13）。

## 3. 快速开始

```bash
cd dsh-plugin-trust-broker
npm ci --ignore-scripts  # 锁定开发依赖，运行时零依赖
npm run check            # typecheck + tests + build
```

审查一个待安装插件目录（终端）：

```bash
npm run build
node bin/trust-broker.mjs review ./some-plugin --no-external-scanner
# 或开发态：node src/cli/entry.ts review ./some-plugin --no-external-scanner
```

消费已核对来源的扫描器报告。先在独立可信环境生成报告，再传入对应的候选树：

```bash
npx dsh-trust-check@0.2.5 --dir ./some-plugin --spec npm:some-plugin@1.2.3 --json > /tmp/report.json
node bin/trust-broker.mjs review ./some-plugin --trust-check-report /tmp/report.json
```

给 CI / GUI 用的 JSON 决策：

```bash
node bin/trust-broker.mjs review ./some-plugin --json --non-interactive
# 退出码：0 = proceed，2 = 需要显式确认，3 = block/unscannable，1 = 用法错误或日志损坏
```

## 4. 安装为 DSH Host bundle

本仓库本身就是一个可安装的 bundle：`package.json` 声明 `dsh.bundle.patch`，`cordis.patch.yml` 插入 Host 行。

```text
# 方式一：DSH Plugin Manager
plugin_manager(install_bundle, target: "<本项目的绝对路径>")
# 方式二：CLI
dsh plugin --profile <profile> add <本项目的绝对路径>
```

安装前务必先构建：`npm run build`（`package.json.main` 指向 `dist/plugin/index.js`；Host 插件需为普通 ESM JavaScript，`dist/` 已在 `.gitignore` 中，发布包的 `files` 会包含它）。

> Host 服务仅供可信 Host 调用者评估选定目录，使用内置扫描。安装流程仍须在加载前拿到针对这份候选树的用户确认，并由加载器绑定实际加载的内容。
>
> **安装本 bundle 只启用运行时审计与 `trustBroker` 服务；DSH 0.2.x 没有 loader 级 pre-apply veto，因此它不会自动拦截 `plugin_manager` 安装。** 需要装机前闸门时，在安装前运行本项目的 CLI 审查/确认（见 §15）。

## 5. 终端审查长什么样

```text
插件信任代理 v0.1.0  ·  安装前审查
──────────────────────────────────────────────────────────────────────────────
  插件                demo-plugin@1.2.0
  插件目录              /…/examples/demo-plugin
  作为 Host 代码运行      是 —— 该插件将作为 Host 代码运行：与 DSH 宿主同进程、拥有宿主权限；DSH 不提供插件级进程隔离。
  来源可信度             来源未声明 · 插件未声明 repository，调用方也未提供来源元数据；来源不可核验。
  权限声明状态            已声明（declared） · 声明字段 package.json#dsh.capabilities

检出能力面（可复核事实）  source: dsh-plugin-trust-broker-heuristic@0.1.0
  · 安装生命周期：安装后脚本（postinstall）  （package.json#scripts.postinstall）

检出能力面（启发式 heuristic:true，与事实分区）
  · 网络：网络访问（fetch/http/https）  （lib/index.js:14  const response = await fetch('https://example.com/status');）
  · 子进程与命令执行：子进程（child_process）  （lib/index.js:2 …）
  · 文件系统：写入文件  （lib/index.js:16  await writeFile('/tmp/demo-plugin.cache', …);）
  · 工具注册表：注册工具  （lib/index.js:8  ctx.tools.register({）

安装脚本 / 更新机制
  · 安装脚本：postinstall —— node scripts/setup.js

  内容哈希            sha256:86a6fe7e9e3b841f813a6509a06b9cae6a45dbd1e136bebcaefd807c7fce069d
  信任锚点            无历史锚点（本次确认后将持久化为锚点）

差异（3）
  [A 声明不足] 子进程（child_process）  new_capability=true
      声明 process.child_process = false，但检出子进程（child_process）。
      [A 声明不足] 写入文件  new_capability=true
      [A 声明不足] 安装后脚本（postinstall）  new_capability=true

建议动作
  需要确认（confirm） 默认动作：暂停等待显式确认；缺少确认时不得进入加载。

强制确认（1）
  1. [new_capability] 检出声明之外的高权限能力：子进程（child_process）、写入文件、安装后脚本（postinstall）。需明确确认后才能进入加载。
     确认口令：「确认新增能力」
```

复制上面哈希并确认（也可在交互终端中按提示输入口令）：

```bash
node bin/trust-broker.mjs review ./examples/demo-plugin --store-dir /tmp/tb-demo \
  --no-external-scanner --non-interactive \
  --acknowledge-new-capability --accept-hash 'sha256:86a6fe7e9e3b841f813a6509a06b9cae6a45dbd1e136bebcaefd807c7fce069d'
# 已写入信任锚点：demo-plugin@1.2.0
```

`--accept-hash` 与当前内容哈希不一致、或审查后文件又发生变化（TOCTOU 复检），都会拒绝锚定并以退出码 2 结束。

## 6. 四个安全面 → 代码映射

| 面 | 要求 | 实现 | 测试 |
|---|---|---|---|
| **面一：权限透明度与安装前准入** | 解析声明、对齐能力类别、区分“声明值”与“是否存在声明”、输出三字段摘要（来源可信度 / 声明状态 / 检出能力面）、默认 `unstated` | [`src/core/manifest.ts`](src/core/manifest.ts)、[`src/core/catalog.ts`](src/core/catalog.ts)、[`src/core/decision.ts`](src/core/decision.ts)、[`src/cli/render.ts`](src/cli/render.ts) | `manifest.test.ts`、`decision.test.ts`、`cli.test.ts` |
| **面二：声明与事实差异审计** | A 声明不足 / B 声明漂移 / C 来源-内容不一致；每条差异带 `file:line` 或元数据指针；`new_capability` 二元标注；只有 `true` 触发强制确认 | [`src/core/diff.ts`](src/core/diff.ts)、[`src/core/detector.ts`](src/core/detector.ts)、[`src/core/external-scan.ts`](src/core/external-scan.ts)、[`src/core/heuristic.ts`](src/core/heuristic.ts)、[`src/core/drift.ts`](src/core/drift.ts) | `detector.test.ts`、`external-scan.test.ts`、`diff`/`decision.test.ts` |
| **面三：供应链锚定与更新信任** | 规范化 `content_hash`、持久化 `TrustAnchor`、同哈希跳过重复确认、B 类增量展示、安装脚本独立标出、AUTO_UPDATE 持续信任提示 | [`src/core/hash.ts`](src/core/hash.ts)、[`src/core/anchor-store.ts`](src/core/anchor-store.ts)、[`src/admission/gate.ts`](src/admission/gate.ts) | `hash.test.ts`、`anchor-store.test.ts`、`drift.test.ts`、`admission.test.ts` |
| **面四：运行时行为边界与上下文完整性** | `tools/pre-execute` 记录工具名/参数摘要/是否超出声明面（`scope_exceeded`）；`tools/post-execute` 记录输出改写前后摘要；上下文注入/压缩与文件写入同级审计；JSONL 只追加 | [`src/runtime/audit.ts`](src/runtime/audit.ts)、[`src/runtime/audit-log.ts`](src/runtime/audit-log.ts)、[`src/runtime/scope.ts`](src/runtime/scope.ts) | `runtime-audit.test.ts`、`runtime-scope.test.ts`、`plugin.test.ts` |

## 7. 决策对象与语义

`TrustDecision` 的关键字段（完整类型见 [`src/types.ts`](src/types.ts)）：

| 字段 | 含义 |
|---|---|
| `host_code: true` | 固定事实：该插件作为 Host 代码在宿主进程内运行 |
| `source_trust` | `registry_signature` / `hash_match` / `hash_mismatch` / `unverified` / `undeclared` —— **状态，不是分数** |
| `declaration.status` | `declared` / `unstated` / `incomplete` / `malformed` |
| `capabilities.facts` | 可复核事实（扫描器 / manifest / 脚本），每条带证据 |
| `capabilities.heuristic_facts` | 启发式回退事实，恒为 `heuristic: true`，与事实分区 |
| `capabilities.categories` | 供终端展示的能力类别摘要 |
| `diffs[]` | A/B/C 差异，含 `new_capability`、证据、上一确认版本 |
| `confirmations_required[]` | 强制确认队列；默认只有 `unstated_capabilities` 与 `new_capability` 两类（策略可开启额外项） |
| `content_hash` | 可复制的规范化哈希；`null` 时拒绝锚定并显式告知 |
| `anchor` | 是否已有历史锚点、是否与某已确认版本同哈希 |
| `status` / `action` | `scanned` / `unscannable` / `malformed_manifest`；`proceed` / `confirm` / `block_for_review` |

**退出码**：`0` proceed/已锚定 · `2` 需确认/内容变化/确认缺失 · `3` block/unscannable · `1` 用法错误或（`anchors --json` / `audit --json` 检查命令）日志损坏。

### 7.1 权限声明格式

写在 `package.json`（按优先级查找 `dsh.capabilities`、`dsh.bundle.capabilities`、`dsh.permissions`、`permissions`）：

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

语义：**字段缺失 ≠ false**。每个槽位单独记录“是否存在”；显式 `false` 与“没写”走不同路径（前者产生 A 类差异，后者最多把声明判为 `incomplete`）。完全没有声明 → `unstated`：**不默认无权限、也不默认全权限**，检出事实构成实际能力面，并强制一次“我已知悉该插件未提供权限声明”的确认。

## 8. 差异规则（面二）

| 类型 | 触发条件 | `new_capability` |
|---|---|---|
| **A 声明不足** | 声明 `X:false` 或声明中未覆盖 `X`，但检出 `X`；安装脚本/AUTO_UPDATE 独立出现 | 按能力目录 `high_privilege` 二元标注 |
| **B 声明漂移** | 当前有效能力集 − 最近一次确认锚点的能力集非空 | 新增能力是否高权限 |
| **C 来源-内容不一致** | 期望解包树的内容哈希 ≠ 候选树哈希；repository 不一致；依赖来自 `git:`/`file:`/`URL` | 恒 `false`。哈希不匹配默认 `block_for_review`，可信策略可为来源风险设独立确认。 |

`high_privilege` 的能力目录见 [`src/core/catalog.ts`](src/core/catalog.ts) 与 [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md)（例如 `filesystem.read` 是低权限：仍会作为差异展示，但不强制确认；`child_process` / `network` / `filesystem.write` / `context.*` / 安装脚本 / `auto_update` 等高权限能力会进入确认队列）。

安装脚本（`preinstall` / `install` / `postinstall` / `prepare`）**独立于能力声明**，始终出现在摘要中；`auto_update` 或远程内容获取机制会额外标注“运行中可能获取并执行安装时未审查的远程内容，应视为持续信任”。

Bundle patch 的组合变更同样纳入，并按 DSH 加载器语义**结构解析**（JSON 或 block list）：`insert:` 条目作为低权限 `composition.insert` 事实展示；任何非 `insert` 的顶层条目都是对已有 profile row 的 id-targeted 变更（`config` 替换、`disabled`、大小写变体等），作为不可声明的 `composition.override` 高权限事实，在首次安装时生成 A 类差异并强制确认。manifest 声明的 patch 路径（字符串或数组）逐个解析；声明缺失、越界、不可读或无法解析的 patch 一律 fail closed。

## 9. 内容哈希与 TrustAnchor（面三）

- **规范化哈希**：`dsh-plugin-content-v2` 域分隔，排序后的目录与文件 JSON 元组覆盖路径和文件摘要。准入覆盖整棵树（包括已物化的依赖），拒绝符号链接、硬链接、特殊文件、越界声明路径和不完整扫描。因此 pnpm/npm 物化后含 symlink/hardlink 的目录会按 fail-closed 判为 `unscannable`；应审查并锚定干净的打包解压树或受控暂存副本（例如 `npm pack` 解压结果，不含 `node_modules`）。
- **评估与准入**：边读取候选树边生成私有快照，扫描该快照后复核原目录。交互和 JSON/库准入都要求接受完整哈希，闸门写锚前再次复检。哈希为空、候选改变或写锚失败均拒绝。
- **锚点**：`~/.dsh/trust-broker/anchors.jsonl`（可用 `DSH_TRUST_BROKER_STORE` / `--store-dir` 覆盖）。日志只追加，记录版本、内容哈希、能力集、决策摘要、确认人和时间。
- **更新规则**：哈希一致且已有锚点覆盖本次检出的能力时，可复用对应的能力确认。显式来源策略与新增证据仍按本次决策处理。v1 哈希历史可查，v2 候选需要重新锚定。

## 10. 运行时审计（面四）

Host bundle 安装后，在以下事件上注册只追加审计：

| 事件 | 记录内容 |
|---|---|
| `tools/pre-execute` | 工具名、参数摘要（敏感键脱敏后的 canonical JSON sha-256）、意图能力类别、是否落在已锚定能力面子集；越界时追加 `scope_exceeded` |
| `tools/post-execute` | 比较原结果与 `PostToolDecision` 的模型可见效果，记录替换、附加上下文或阻断反馈。原样返回下游决策 |
| `system-prompt/assemble` | 装配前后 digest；变化时 `context_write(prompt_assembly)` |
| `agent/inbox/inserted` | 注入消息摘要（`context_write(inbox_insert)`） |
| `session/event`（`compaction/*`） | 历史压缩事件（`context_write(history_compress)`） |

写入 `<store_dir>/audit.jsonl`，字段结构与消费方式见 [`docs/AUDIT-SCHEMA.md`](docs/AUDIT-SCHEMA.md)。审计观察钩子原样传递工具决策与上下文。写失败时发出警告并保留 DSH 的派发结果。卸载会取消在途评估、关闭日志，迟到回调停止记录。

工具归属（哪个工具来自哪个插件）由 `RuntimeAuditConfig.tool_owners` 或 `service.setToolOwner()` 提供；未知归属记为 `unattributed`，不会伪造 `scope_exceeded`。这是 v1 的诚实限制（见 §12）。

## 11. 策略配置

优先级：默认值 ← 策略文件 ← CLI 参数。示例 `policy.json`：

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

默认策略与 brief 的 fail-closed 规则一致：未声明必须确认、新增高权限能力必须确认、不可扫描一律阻断，来源哈希不匹配默认阻断。决策的 `policy` 字段展示生效策略，准入固定覆盖整个候选树。运行时配置（`RuntimeAuditConfig`）支持 `store_dir` / `tool_owners` / `tool_capabilities` / `redact_argument_keys` / `context_audit`。

## 12. 失败模式（fail-closed 矩阵）

| 条件 | `status` | 默认 `action` |
|---|---|---|
| 插件目录不可读 / `package.json` 缺失 | `unscannable` | `block_for_review` |
| 扫描覆盖不完整、外部扫描器报告损坏、文件不可读、命中扫描上限 | `unscannable` | `block_for_review` |
| 锚点日志不可读，或任一行无法解析、未通过锚点校验 | `unscannable` | `block_for_review` |
| 权限声明存在但无法解析 | `malformed_manifest`（按 `unstated` 处理，保留解析错误） | `confirm`（未声明确认） |
| 声明存在但未覆盖检出能力 | `scanned` + `declaration.status = incomplete` + A 类差异 | 视 `new_capability` 决定 |
| 内容哈希无法计算、清单无法识别或扫描期间发生变更 | `unscannable`，`content_hash: null` | `block_for_review` |
| 期望来源哈希 ≠ 内容哈希 | `scanned` + C 差异 | `block_for_review` |
| `new_capability: true` 且未确认 | `scanned` | `confirm`，**不得进入加载** |
| 未声明插件且未确认 | `unstated` | `confirm`，**不得进入加载** |

## 13. v1 验收对照

| # | 验收要求 | 本实现 |
|---|---|---|
| 1 | 是否作为 Host 代码运行（固定文案） | 终端顶部固定披露 + `decision.host_code: true` + `HOST_CODE_NOTICE_ZH` |
| 2 | 声明状态：已声明 / 未声明 / 不完整 | `declaration.status` 四态（含 malformed），终端中文标签；`unstated` 强制确认 |
| 3 | 检出能力类别 + 至少一条差异 | `capabilities.categories` + A/B/C `diffs[]`（带 `file:line` / 元数据指针） |
| 4 | 安装脚本 / AUTO_UPDATE / 远程内容获取 | `summary.install_scripts` 恒展示 + `summary.auto_update` + `continuous_trust_warning` |
| 5 | 可复制 `content_hash` + 确认后持久化为锚点 | 终端/JSON 输出；`--accept-hash` 或交互确认后写 `anchors.jsonl`，含 TOCTOU 复检 |
| 6 | `new_capability` 时提示新增能力且默认暂停 | 聚合提示“检出声明之外的高权限能力/本次更新新增…”，`action: confirm`，缺少确认时退出码 2 |

只读审查返回建议动作。自动化应以 `admission.accepted: true` 作为已确认并写锚的凭据。单独的 `review` 退出码 0 只表示建议继续。

## 14. 与现有生态件的边界

- **`dsh-trust-check`（消费而非重写）**：本项目优先读取其 `--dir --json`（`schemaVersion: 2`）报告，映射 `shell / fs-read / fs-write / network / credentials / env / subagent / host-runtime / llm / dynamic-code` 到本项目的声明类别；其中文文案契约与红线只**陈列事实**，不重新裁决。内置启发式扫描同时运行。显式配置的扫描器启动失败、超时、超限、非零退出或报告不合法时均阻断。
- **`dsh-plugin-guard`**：该包实际是 Web 客户端插件隔离/自更新工具，不是静态能力扫描器；本项目与它无功能重叠，也不依赖它。
- **沙箱**：本机文件访问发生在 Host 或独立 CLI 进程中。工具调用的沙箱与审批仍由 DSH 派发链路决定。
- **AUTO_UPDATE / `prepare` / Git 来源**：安装时信任 ≠ 运行中信任；这类路径在摘要中单独标注并建议按“持续信任”处理。

## 15. 已知限制（v1，诚实声明）

1. **加载器强制点**：DSH 0.2.x 没有 loader 级 pre-apply veto API。本项目提供三样可消费物：`TrustDecision`（数据结构）、`trustBroker` 服务（`ctx.provide`，供宿主/未来的 loader 钩子调用）、CLI 闸门（`dsh plugin add` 之前执行）。宿主侧仍需接入准入流程，用受控的同一份物化内容完成安装和 apply。确认后若重新下载、补装依赖、执行生成脚本或替换来源，必须先重审。
2. **工具归属**：运行时 `scope_exceeded` 依赖 `tool_owners` 配置或 `setToolOwner`；未知归属只记 `unattributed`，不猜测。
3. **静态分析上限**：启发式规则可被动态 `import`、字符串拼接等绕过；外部扫描器也有既有漏报（如解构后的凭据读取）。本项目的差异层只能基于“已检出事实”，不能证明缺席。
4. **审计是 fail-open 的**：运行时审计写入失败不会阻断工具调用（防审计盘故障拖垮宿主），失败会告警，派发继续使用原有审批与错误结果。若需要“审计失败即阻断”，应在消费方策略中实现。
5. **无 Web GUI 面板**：v1 以 `--json` 为 GUI 契约；CLI 满足验收。
6. **来源签名**：registry 签名/发布时间由可信调用方提供。签名状态须有匹配的解包树 `content_sha256` 才会作为来源状态显示。原始 tarball SHA-256 或 npm SRI 应由调用方在解包前核验。

## 16. 项目结构

```text
dsh-plugin-trust-broker/
├── src/
│   ├── types.ts                 # 共享数据模型（决策、差异、锚点、审计、策略）
│   ├── version.ts               # 固定文案与确认口令
│   ├── core/
│   │   ├── catalog.ts           # 能力目录：声明槽位、高权限标注、工具→能力映射
│   │   ├── manifest.ts          # package.json / 权限声明解析与校验
│   │   ├── external-scan.ts     # dsh-trust-check schema 2 适配器（可信报告 / 显式扫描器）
│   │   ├── heuristic.ts         # 启发式回退扫描（heuristic:true，fail-closed）
│   │   ├── detector.ts          # 事实合成 + auto_update finding
│   │   ├── diff.ts              # A/B/C 差异 + 声明完整性 + 来源可信度
│   │   ├── hash.ts              # 规范化内容哈希
│   │   ├── tree-files.ts        # 有界目录遍历与路径校验
│   │   ├── anchor-store.ts      # 只追加 TrustAnchor 日志
│   │   ├── drift.ts             # B 类漂移（vs. 最近确认锚点）
│   │   ├── decision.ts          # TrustDecision 组装 + 确认队列 + 动作
│   │   ├── policy.ts            # 默认策略与策略文件
│   │   ├── fs-utils.ts          # canonical JSON / digest / 脱敏
│   │   └── jsonl.ts             # 只追加 JSONL 读写
│   ├── runtime/                 # 面四：audit-log / scope / host 监听工厂
│   ├── admission/gate.ts        # 准入闸门 + 锚点写入 + TOCTOU 复检
│   ├── plugin/index.ts          # DSH Host bundle 入口（apply / provide）
│   ├── cli/                     # review / confirm / anchors / audit / scan + 渲染
│   └── index.ts                 # 库导出
├── bin/trust-broker.mjs         # 打包后的可执行入口
├── test/                        # node:test 回归，fixtures 覆盖声明/扫描/漂移/审计
├── examples/demo-plugin/        # 演示“声明不足”的第三方插件
├── docs/                        # 架构、安全模型、审计 schema
├── cordis.patch.yml             # DSH bundle patch
├── locale/{zh,en}.json + icon.svg
└── package.json / tsconfig*.json
```

## 17. 验证

本地使用 `npm ci --ignore-scripts` 安装开发依赖，以 `npm run check` 运行类型检查、回归测试和构建。回归覆盖目录逃逸、哈希记录歧义、内容变更、外部扫描失败和取消、交互显示、审批决策透传、卸载及发布入口。DSH 0.2.1-rc.2 的原生 Cordis、ToolRuntime 和 SystemPrompt 另用合成工具和临时日志完成内存集成验证。真实 profile 的安装和加载器强制准入仍需联调。

[对抗性安全审查报告](docs/reviews/structure-review.zh-CN.md)

## 18. License

MIT。所消费的 `dsh-trust-check` 为独立第三方项目（MIT），本项目不内嵌其代码。
