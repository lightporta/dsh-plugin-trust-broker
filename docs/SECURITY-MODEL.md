# 安全模型与边界（Security Model）

[English edition](SECURITY-MODEL.en.md)

> `dsh-plugin-trust-broker` 提供可复核的安装前事实、差异和锚点，以及运行期审计记录。

## 1. 责任分层

| 层 | 负责方 | 本文档中的体现 |
|---|---|---|
| **事实层** | 本工具与操作员显式指定的外部扫描器 | 能力检出、证据 `file:line`、内容哈希、安装脚本、来源元数据 |
| **差异层** | 本工具 | 声明 vs. 检出（A）、本次 vs. 上次确认（B）、来源 vs. 内容（C） |
| **策略层** | 用户 / profile 策略 / 上层加载器 | `proceed` / `confirm` / `block_for_review` 的建议动作与强制确认队列 |
| **背书层** | 不提供 | 本工具不生成“已验证 / 安全 / 可信”标记，不维护黑白名单 |

DSH 的安全边界来自用户审批和可信来源。沙箱用于防止误用。可信加载器负责在激活前取得并绑定用户的授权，加载经过校验的候选树。工具调用的一次性授权由 DSH `ctx.approval` 流程决定。Broker 的建议动作、确认码和本地锚点供加载器核对。Host 服务 `evaluate()` 仅生成审查数据，使用本地启发式和已配置的日志路径。它没有安装、激活或工具审批入口。

## 2. 能力目录与 `high_privilege`

`src/core/catalog.ts` 定义唯一能力词汇表。`high_privilege` 决定差异的二元标注 `new_capability`：

| 能力路径 | 高权限 | 说明 |
|---|---|---|
| `network.fetch` / `network.socket` | ✅ | 出站访问、数据外发面 |
| `process.child_process` / `process.exec` | ✅ | 系统命令执行 |
| `filesystem.read` | ❌ | 读取本机文件；仍会作为差异展示，但不单独强制确认 |
| `filesystem.write` | ✅ | 本机写入/持久化 |
| `env.read` | ✅ | 环境变量中常含密钥 |
| `tool_registry.add` / `.override` / `.intercept` | ✅ | 改变模型可见工具面或拦截调用 |
| `context.prompt_inject` / `.tool_output_rewrite` / `.history_compress` | ✅ | 上下文完整性 |
| `lifecycle.preinstall` / `.install` / `.postinstall` / `.prepare` | ✅ | 安装期执行代码，独立于能力声明 |
| `auto_update` | ✅ | 安装后获取并执行未审查内容 |
| `credentials.read` | ✅ | 凭据/密钥 |
| `subagent.spawn` | ✅ | 启动子代理（新的行为主体） |
| `llm.call` | ✅ | 数据可经模型请求离开本机 |
| `dynamic_code.eval` | ✅ | 运行时执行代码 |
| `host_runtime.dependency` | ❌ | 依赖 DSH 宿主运行时包（供应链事实，不可声明） |
| `composition.override` | ✅ | 覆盖/禁用核心 bundle 行（宿主完整性事实，不可声明） |
| `composition.insert` | ❌ | 插入新的组合行（bundle 的正常行为；展示为事实，不单独强制确认） |

目录是**规则表**，不是对单个插件风险的判断；修改它需要同步更新本文件与测试。

## 3. 声明语义：缺失 ≠ false

```json
"process": { "child_process": false }
```

- 槽位存在且 `false`：作者明确声称不使用子进程 → 检出即 **A 类差异**。
- 槽位缺失（`process` 整个未写、或 `process.child_process` 未写）：作者没有表态 → 检出时最多把声明状态升级为 `incomplete`，并产生“声明未覆盖”的 A 类差异。
- 整个声明字段缺失：`unstated` → **不默认无权限，也不默认全权限**；检出事实构成实际能力面，强制一次“我已知悉该插件未提供权限声明”的确认。
- 显式 `env.read: []`：明确声明“不读取环境变量”，是 `false` 语义；非空数组则蕴含 `env.read = true`。

## 4. 差异规则

### A 类：声明不足（`A_declaration_insufficient`）

| 代码 | 条件 | `new_capability` |
|---|---|---|
| `detected_but_declared_false` | 声明槽位为 `false`，检出对应能力 | `isHighPrivilege(path)` |
| `detected_but_undeclared` | 声明存在（declared/incomplete）但未覆盖该路径，检出对应能力 | `isHighPrivilege(path)` |
| `observed_non_declarable_capability` | 检出无法用权限声明表达的高权限事实（目前为 `composition.override`：bundle patch 覆盖/禁用 DSH 组合行），首次安装且锚点未覆盖 | `true`（强制确认；锚点已覆盖该能力集时不重复） |

安装脚本与 AUTO_UPDATE 是**独立事实**：即使能力声明里没有任何相关槽位，脚本存在本身就会产生 A 类差异（`lifecycle.*` / `auto_update`），且恒为高权限。

Bundle patch 的组合面同样纳入：manifest 声明的 patch 路径（字符串或数组）会被逐个**结构解析**（JSON 数组或 block list），与 DSH 加载器一致——`insert:` 条目产生低权限 `composition.insert` 事实；任何非 `insert` 的顶层条目都是对已有 profile row 的 id-targeted 变更（`config` 替换、`disabled`、大小写变体等），产生不可声明的 `composition.override` 高权限事实，首次安装时生成 A 类差异。声明缺失、数组元素非字符串、路径越界、patch 文件不可读或形态无法解析（`patch_unparsed`）都会 fail closed。结构解析覆盖加载器的标准形态；外部扫描器报告的 override/disable 注入事实可作为补充。

### B 类：声明漂移（`B_capability_drift`）

- 比较对象：当前**有效能力集**（声明为 true + 检出事实 + 安装脚本 + AUTO_UPDATE） vs. **最近一次确认锚点**的 `capability_keys`。
- 只有新增能力生成差异；能力减少仅进入 `reduced_capabilities`（信息展示，不触发重确认）。
- 若已锚定版本与当前哈希匹配，且当前能力集包含于该锚点的能力集，可跳过对同一能力的重复确认。扫描器新增检出的能力仍进入差异和确认判定。来源不一致、外部红线和供应链策略单独判断。
- 每个 B 行携带上一确认版本号、确认时间、确认人，用于“vX → vY 新增了以下能力”的增量展示。

### C 类：来源-内容不一致（`C_source_content_mismatch`）

| 代码 | 条件 | 动作影响 |
|---|---|---|
| `source_hash_mismatch` | 可信调用方提供的预期候选树哈希与 v2 内容哈希不同 | 默认 `block_for_review` |
| `repository_mismatch` | `package.json#repository` 与来源元数据 repository 不一致 | 展示；默认不阻断 |
| `non_registry_dependency` | 依赖来源为 `git:` / `file:` / `URL` / `workspace:` 等非 registry 范围 | 展示；策略 `confirm_on_non_registry_dependency=true` 时可要求确认 |

C 类**永不**携带 `new_capability: true`，不进入 `new_capability` 强制确认队列。

依赖来源来自 `package.json` 与 npm v2/v3 锁文件的 `packages[*].resolved`。两种 npm 锁文件同时存在时读取 `npm-shrinkwrap.json`。公开的 `registry.npmjs.org` 解析地址归入 registry，自定义镜像和直接归档地址单独显示。旧版或其他包管理器锁文件和 `.npmrc` 的 registry 重写由可信安装流程另行核验。内容哈希覆盖候选树内这些配置文件的原始字节，覆盖范围以实际审查的候选树为准。

## 5. 强制确认队列

默认只有两类（与 brief 一致）：

1. `unstated_capabilities`：插件无声明，或声明 `malformed`（按 unstated 处理）；确认口令「我已知悉」。
2. `new_capability`：存在 `new_capability: true` 的 A/B 差异；确认口令「确认新增能力」。

策略可额外开启（默认关闭）：

| 策略 | 确认码 | 口令 |
|---|---|---|
| `confirm_on_non_registry_dependency: true` | `supply_chain_dependency` | 确认供应链差异 |
| `external_red_lines: "confirm"` | `red_line` | 确认风险红线 |
| `block_on_source_hash_mismatch: false`（降级） | `source_mismatch` | 确认来源不一致 |

`admitDecision` 要求完整覆盖、可用的内容哈希、所有强制确认和显式提交的完整哈希。写入前重新计算候选树哈希，出现变化即拒绝。锚点写入失败会向调用方报错。

## 6. 失败模式（fail-closed）

| 条件 | 决策 `status` | 默认动作 | 依据 |
|---|---|---|---|
| 目录不可读，`package.json` 缺失、无效或入口指向树外 | `unscannable` | `block_for_review` | 无法识别或绑定候选插件 |
| 扫描覆盖不完整、配置的外部扫描器失败、超时或报告无效 | `unscannable` | `block_for_review` | 保留已收集的事实供复核 |
| 锚点日志不可读，或任一行无法解析、未通过锚点校验 | `unscannable` | `block_for_review` | 不得在缺少可靠历史基线时静默跳过更新审查 |
| 权限声明无法解析（类型错误/非对象） | `malformed_manifest` | `confirm`（未声明确认，保留解析错误） | brief：按 unstated 处理并标注解析错误 |
| 内容哈希无法计算或候选树在审查期间变化 | `unscannable` | `block_for_review` | 需要重新审查可完整读取的候选树 |
| 调用取消或 Host 插件卸载 | Promise 拒绝 | 终止评估并清理临时资源 | CLI 外部扫描进程在取消或超时时终止 |
| 期望来源哈希不匹配 | `scanned` + C 差异 | `block_for_review` | 来源与内容不一致 |
| `new_capability: true` 未确认 | `scanned` | `confirm`（CLI 退出码 2） | 未确认不得进入加载 |
| 未声明插件未确认 | `scanned` 且 `declaration.status: unstated` | `confirm`（CLI 退出码 2） | 未声明必须显式知悉 |

CLI 可使用操作员指定的绝对路径扫描器或显式提供的报告。扫描器从自己的目录启动，子进程环境只提供 Node 可执行文件目录的 `PATH`。标准输出和报告文件有大小上限，标准错误直接丢弃。未配置外部扫描器时使用本地启发式。显式选定的扫描器或报告失败后保留启发式证据供排查，评估维持阻断。报告成功也保留它未覆盖的本地能力事实。

## 7. 内容哈希与 TrustAnchor

- **规范化哈希**使用 `dsh-plugin-content-v2\n` 域前缀。按路径排序后，每行编码一个 JSON 数组 `[类型, 条目哈希, POSIX 相对路径]`，目录的条目哈希为空字符串。JSON 转义让文件名里的换行留在同一条记录中。v1 锚点保留作历史记录，首次采用 v2 时重新核对并接受新哈希。
- **准入覆盖**包含候选树内所有普通文件和子目录，包括原来默认跳过的 `.git`、`node_modules` 和 `.DS_Store`。严格遍历拒绝符号链接、硬链接和特殊文件，因此 pnpm/npm 物化后含链接的目录会 fail closed；应审查并锚定干净的打包解压树或受控暂存副本（`npm pack` 解压即不含 `node_modules`）。候选文件以打开的文件描述符读取，并核对路径与文件身份。路径或条目发生可检测的变化、超过上限、不可读时，返回 `hash: null` 和 `complete: false`。
- **审查快照**在哈希时写入同一字节流，供 manifest 与扫描器读取。临时目录限制为当前用户访问，评估结束后清理。评估结束和锚定前分别重新核对原候选树。
- **锚点**以 JSONL 追加，写入后 `fsync`。`content_hash` 与 `decision_digest` 都必须是 `sha256:` 加 64 位小写十六进制摘要；后者记录确认所依据的事实摘要。存储层可报告并跳过损坏行以展示其他锚点，但准入评估遇到任何读取或校验错误都会阻断。`confirmed_at` 按实际时间比较，带时区偏移的 ISO-8601 时间戳不按字符串排序。

## 8. 运行时审计边界

审计观察工具调用的网络、子进程和文件意图，也记录观测到的上下文变化。Host 插件的直接文件系统访问以 Host 进程权限执行。

- **只追加**：JSONL，`O_APPEND` 单次写入；读取端对 torn line 容错（报告行号，不丢整文件）。
- **审计故障**经 `logger.warn` 报告，工具派发仍沿用 DSH 的审批和执行结果。卸载关闭日志，已进入瀑布钩子的回调返回下游结果。
- **归属诚实**：`scope_exceeded` 只在能确定工具归属插件（`tool_owners` / `setToolOwner`）且其锚定能力面存在时产生；未知归属记为 `unattributed`。
- **上下文观察**覆盖系统提示词组装、工具后置决策及其附加上下文、消息进入 inbox 和历史压缩事件。瀑布钩子把 `next()` 的结果原样返回。运行日志记录摘要和结构化元数据，警告省略异常 payload 文本。依赖、来源 URL、安装命令中的 URL 认证信息与常见令牌查询参数会在展示前脱敏。

## 9. 策略默认值

见 `src/core/policy.ts`：

| 键 | 默认 | 含义 |
|---|---|---|
| `require_ack_for_unstated` | `true` | 未声明必须确认；设为 `false` 会同时抑制未声明/malformed 插件由检出事实推导的 `new_capability` 确认（没有声明就没有 A 类差异），属显式放宽，记录在决策 `policy` 中 |
| `confirm_on_new_capability` | `true` | 新增高权限能力必须确认 |
| `block_on_unscannable` | `true` | 准入固定阻断不完整扫描 |
| `block_on_source_hash_mismatch` | `true` | 来源哈希不匹配默认阻断 |
| `confirm_on_non_registry_dependency` | `false` | 非 registry 依赖默认仅展示 |
| `external_red_lines` | `"display"` | 外部扫描器红线只陈列事实 |
| `hash_excludes` | `[]`（准入） | 准入固定纳入候选树内的普通文件和子目录 |
| `store_dir` | `$DSH_HOME/trust-broker` 或 `~/.dsh/trust-broker` | 锚点与审计目录 |

## 10. 威胁模型与残余风险

本工具能做的：让“安装时看到的事实”与“实际代码”通过哈希绑定，并让升级增量可见。

本工具不能做的（明确不承诺）：

1. **不能证明安全**：`proceed` 只表示“没有需要强制确认的新高权限能力”，不表示无风险；“未检出”也不是安全背书。
2. **静态分析上限**：启发式可被动态 `import`、字符串拼接、混淆绕过；外部扫描器也有已知漏报。差异只基于已检出事实。
3. **TOCTOU 窗口**。Broker 在快照扫描后及写入锚点前重算哈希。便携的 Node 路径检查依赖身份与路径复核。可信加载器需要将候选树隔离到受保护的暂存目录，并在最终加载时绑定已审查内容。安装后生成或下载的内容取决于实际安装流程。
4. **工具归属可伪造**：`tool_owners` 由调用方配置，错误的映射会产生错误的 `scope_exceeded`/`declared` 判定。
5. **同进程对抗**：运行在 DSH 宿主进程内的插件可以干扰同进程的审计和读取。安装前应在独立可信进程中运行 `dsh-trust-broker review <目录>`。
6. **来源元数据自述**。可信调用方提供签名验证结果和预期 v2 哈希。`content_sha256` 表示候选树哈希，兼容字段 `tarball_sha256` 也按候选树哈希解释。`repository` 来自包自述。只有调用方报告签名验证完成且内容哈希相符时，标记为签名来源。完整的内容哈希也可以单独作内容比对。
7. **审计日志完整性**：v1 无签名/哈希链，只保证顺序追加；需要防篡改时由外部日志系统处理。

## 11. 不做什么（再次声明）

- 不评分、不排序、不生成“信任等级”。
- 不维护黑白名单、不做人工背书。
- 不做“安全/恶意”二分类；`redLines` 等外部信号只作为事实陈列。
- 不修改 `danger-full-access` 行为、不增强沙箱、不做运行时拦截（v1）。
- 不对模型可见 prompt 做安全过滤，只记录上下文写入事件。
- 不要求插件作者改代码；`unstated` 是降级路径而非拒绝路径。
