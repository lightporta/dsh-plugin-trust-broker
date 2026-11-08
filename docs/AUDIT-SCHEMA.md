# 审计日志 schema（v1）

[English edition](AUDIT-SCHEMA.en.md)

本文件冻结三个只追加 JSONL 文件的字段契约，供 `audit` / `policy` 等消费方解析。
**原则**：每行一个 JSON 对象；字段名稳定；破坏性变更提升 `schema_version`；未知字段的消费方必须忽略。
审计是**事实流**，不是裁决流——不要根据单条事件判定“恶意”。

```text
<store_dir>/audit.jsonl       # 运行时行为审计（Host bundle 写入）
<store_dir>/anchors.jsonl     # TrustAnchor 只追加日志（确认时写入）
<store_dir>/decisions.jsonl   # CLI 决策日志（审查/接受/拒绝时写入）
```

默认 `<store_dir>` 为 `$DSH_HOME/trust-broker`，否则 `~/.dsh/trust-broker`；可用 `DSH_TRUST_BROKER_STORE` 或 `--store-dir` 覆盖。

## 1. 事件信封（所有 `audit.jsonl` 行共有）

| 字段 | 类型 | 必有 | 说明 |
|---|---|---|---|
| `schema_version` | `1` | ✅ | 审计 schema 版本 |
| `event` | `string` | ✅ | 事件类型（见 §2） |
| `seq` | `number` | ✅ | 同一 writer 内单调递增，从 1 开始；跨进程不保证全局序 |
| `id` | `string` | ✅ | 事件唯一 id（测试可注入；运行时用随机 id） |
| `ts` | `string` | ✅ | ISO-8601 时间戳（可注入时钟） |
| `plugin_id` | `string` | – | 归属插件（仅在可归属时出现） |
| `plugin_version` | `string` | – | 归属插件版本 |
| `session_id` | `string` | – | DSH session |
| `agent_id` | `string` | – | agent / session id（来自事件 payload） |

字段顺序固定为信封在前、事件字段在后；解析方不得依赖顺序，只依赖字段名。

## 2. 事件类型

### 2.1 `tool_call`（`tools/pre-execute`，派发前）

| 字段 | 类型 | 说明 |
|---|---|---|
| `tool` | `string` | 工具名 |
| `call_id` | `string?` | 工具调用 id |
| `arguments_digest` | `string` | 脱敏后参数的 canonical JSON sha-256（`sha256:<hex>`） |
| `argument_keys` | `string[]` | 参数顶层键名（不含值） |
| `categories` | `string[]` | 本次调用**意图**的能力类别（来自工具映射 + 参数启发式） |
| `scope` | `'declared' \| 'undeclared_scope' \| 'unattributed'` | 与归属插件锚定能力面的关系 |
| `owner_plugin_id` | `string?` | 工具归属插件（若已知） |

示例：

```json
{"schema_version":1,"event":"tool_call","seq":1,"id":"evt_01","ts":"2026-11-08T05:13:45.178Z","tool":"bash","call_id":"call-1","arguments_digest":"sha256:…","argument_keys":["command"],"categories":["process.exec","process.child_process","filesystem.read","filesystem.write"],"scope":"unattributed"}
```

### 2.2 `tool_result`（`tools/post-execute`，派发后）

| 字段 | 类型 | 说明 |
|---|---|---|
| `tool` | `string` | 工具名 |
| `call_id` | `string?` | 工具调用 id |
| `ok` | `boolean` | `result.isError === false` |
| `result_digest` | `string` | 进入 post-execute 瀑布时的结果摘要 |
| `settled_digest` | `string` | 将 DSH 瀑布决策作用于原始结果后的审计摘要 |
| `rewritten` | `boolean` | 摘要发生变化，表明观测到输出改写、拦截反馈或附加上下文 |

DSH 的默认决策 `{ kind: 'accept' }` 保留原结果。审计投影覆盖显式替换的 `content`、`value`、拦截后的 `feedback` 和 `additionalContexts`。其中 `value` 记录的是替换值的变化，实际输出由 DSH 随后渲染。

### 2.3 `scope_exceeded`（越界事件）

| 字段 | 类型 | 说明 |
|---|---|---|
| `tool` | `string` | 工具名 |
| `call_id` | `string?` | 调用 id |
| `owner_plugin_id` | `string` | 归属插件（必须已知） |
| `exceeded` | `string[]` | 超出锚定能力面的类别 |
| `declared` | `string[]` | 该插件锚定的能力面 |
| `evidence` | `string` | 判定依据（如 `tool-call-outside-anchored-surface`） |

> 仅在能确定工具归属且存在锚点时产生；未知归属不伪造该事件。

### 2.4 `context_write`（上下文完整性）

| 字段 | 类型 | 说明 |
|---|---|---|
| `channel` | `'prompt_inject' \| 'tool_output_rewrite' \| 'history_compress' \| 'prompt_assembly' \| 'inbox_insert'` | 写入渠道 |
| `before_digest` | `string?` | 写入前摘要 |
| `after_digest` | `string?` | 写入后摘要 |
| `chars_before` | `number?` | 写入前字符数（可用时） |
| `chars_after` | `number?` | 写入后字符数（可用时） |
| `detail` | `string?` | 说明（如 `compaction/summary`、消息来源 kind） |

与文件写入同级对待：即使 v1 不拦截，也必须事后可追溯。`tool_output_rewrite` / `prompt_assembly` 由 waterfall 摘要变化触发；`history_compress` 来自 `session/event` 的 `compaction/*`；`inbox_insert` 来自 `agent/inbox/inserted`。

### 2.5 供宿主集成使用的事件

`audit.jsonl` 由运行时监听和 **Host 服务 `service.record()`** 写入。CLI 决策日志单独写入 `decisions.jsonl`。以下事件可供宿主锚点或决策流程使用：

| 事件 | 字段 | 说明 |
|---|---|---|
| `anchor_created` | `anchor: TrustAnchor` | 锚点写入后记录，省略自由文本 `notes` |
| `decision_recorded` | `decision_digest: string`, `action: string` | 决策落定 |
| `audit_error` | `operation: string`, `message: string` | 审计自身失败，`message` 存储摘要 |

Host 服务仅保留已知事件字段。通过该服务写入的 `context_write.detail` 也存储摘要。运行时监听生成的 `detail` 保留事件类型或消息来源标签。

## 3. 写入保证

- **只追加**：fd 以 `O_APPEND` 打开，一行一次 `write(2)`；进程崩溃最多留下 torn 末行，读取端报告行号并跳过。
- **顺序**：writer 生成的 `seq` 单调递增，成功追加才推进。Host 服务接受已有信封的事件，保留其序号。
- **失败不中断派发**：写入或分类失败时，`logger.warn` 输出操作类型。Waterfall 监听透传 `next()` 的值或异常，卸载时关闭 writer 并放弃在途回调尚未写入的审计事件。
- **脱敏**：`arguments_digest` 在计算前将匹配内置敏感键名或其后缀的值替换为 `[redacted]`，包括 `authorization`、`token`、`secret`、`password`、`cookie`、`credential` 和 `apiKey` 等。配置 `redact_argument_keys` 可扩展这一集合，顶层键名仍作为元数据记录。
- **文件权限**：新建存储目录和 JSONL 文件分别使用 `0700` 和 `0600`。已有存储使用部署时设定的权限。
- **摘要算法**：canonical JSON（对象键排序）→ UTF-8 → sha-256，输出 `sha256:<hex>`；跨进程可复现。
- **轮转/保留**：v1 不自动轮转。生产环境应使用外部日志轮转或按会话隔离 store 目录。

## 4. `anchors.jsonl`（`TrustAnchor`）

每次“用户/策略确认”追加一行（历史全部保留）：

| 字段 | 类型 | 必有 | 说明 |
|---|---|---|---|
| `schema_version` | `1` | ✅ | 锚点 schema |
| `plugin_id` | `string` | ✅ | 插件名 |
| `version` | `string` | ✅ | 确认时的版本 |
| `content_hash` | `string` | ✅ | `sha256:<hex>`，规范化内容哈希 |
| `declared_capabilities` | `DeclaredCapabilities` | ✅ | 确认时解析出的权限声明 |
| `confirmed_at` | `string` | ✅ | ISO-8601 |
| `confirmed_by` | `'user' \| 'policy'` | ✅ | 确认来源 |
| `capability_keys` | `string[]` | ✅（扩展） | 确认时的有效能力集（声明 true + 检出 + 脚本 + auto_update） |
| `declaration_status` | `string` | ✅（扩展） | 确认时声明状态 |
| `scanner` | `{name, version?, heuristic}` | ✅（扩展） | 事实来源 |
| `decision_digest` | `string` | ✅（扩展） | 对决策事实的规范化摘要（锚定“确认的是什么”） |
| `notes` | `string?` | – | 备注 |

**更新语义**：内容哈希匹配且历史锚点覆盖当前能力集时，可跳过同一能力的重复确认；否则与匹配锚点或**最近一次**锚点的能力集比较，新增能力产生 B 类差异。最近一次按 `confirmed_at` 的实际时间判定，平局取后写入行。`content_hash` 与 `decision_digest` 均要求 `sha256:` 加 64 位小写十六进制。存储层会报告并跳过损坏行，其他锚点仍可供人工查看；准入评估遇到任何损坏或不可读记录则阻断。

## 5. `decisions.jsonl`（CLI 决策日志）

每次 CLI 审查/接受/拒绝追加一行：

| 字段 | 类型 | 说明 |
|---|---|---|
| `schema_version` | `1` | |
| `type` | `'decision'` | |
| `ts` | `string` | |
| `plugin_id` / `plugin_version` | `string` | |
| `content_hash` | `string \| null` | |
| `status` / `action` | `string` | 决策状态与建议动作 |
| `accepted` | `boolean` | 是否通过准入闸门 |
| `reason` | `string?` | 未接受时的原因（`confirmation_required` / `blocked_for_review` / `content_changed` / `review_only` / `user_aborted_confirmation` / `user_declined_anchor`） |
| `acknowledged` | `string[]` | 已提供的确认码 |
| `decision_digest` | `string` | 与锚点一致的决策摘要 |
| `confirmations_required` | `string[]` | 确认码列表 |
| `diff_ids` | `string[]` | 差异 id 列表 |
| `error_codes` | `string[]` | 决策错误码 |
| `red_lines_count` | `number` | 外部扫描器红线条数（事实陈列） |
| `scanner` | `string` | 事实来源名 |
| `anchor_version` | `string \| null` | 本次写入锚点的版本（若有） |

## 6. 消费示例

```bash
# 最近 20 条审计，按事件过滤
node bin/trust-broker.mjs audit --lines 20
node bin/trust-broker.mjs audit --json | jq '.records[] | select(.event == "scope_exceeded")'

# 校验 JSONL 结构（CI）
node bin/trust-broker.mjs audit --verify --json
# 有问题时退出码 1

# 列出某插件的锚点
node bin/trust-broker.mjs anchors my-plugin --json
```

消费建议：

- 用 `agent_id` + `call_id` 关联 pre/post 两条记录及其工具输出改写事件；用 `plugin_id` 聚合某插件的越界频率。`session_id` 仅用于 session 事件提供的真实 DSH session。
- `scope: "unattributed"` 表示无法归属，不是“安全”；提示部署方补 `tool_owners`。
- `red_lines_count` 与 `context_write` 是事实，不要单独作为拦截依据。
- 需要“审计失败即阻断”时，在消费方监控 `audit_error` 并按自己的策略处置。

## 7. 版本与兼容

- 当前 `schema_version = 1`（三个日志一致）。
- 新增字段：允许，消费方忽略未知字段；新增事件类型：允许，消费方按 `event` 过滤。
- 删除/重命名字段或改变既有语义 → 提升 `schema_version`，并提供迁移说明。
- 能力类别字符串属于能力目录（`src/core/catalog.ts`），目录扩展时旧锚点仍可读（未知 key 容忍）。
