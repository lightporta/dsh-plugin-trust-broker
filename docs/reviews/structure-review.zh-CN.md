# dsh-plugin-trust-broker 结构 / 装配 / 生命周期审查

[English review](structure-review.en.md)

## 2026-11-08 对抗性复审结论

**初始结论为 `block_for_review`。** 原实现可让扫描失败继续准入、错绑审查事实与内容哈希，并在 Host 评估期间执行未绑定到发布锁文件的扫描器。

修复覆盖下列 15 项实质性发现和原结构审查的三项待办。当前验证覆盖源码、构建产物、发布归档和本机 DSH 0.2.1-rc.2 的原生组件。将此插件作为强制准入闸门发布仍需接通真实加载器，并验证从用户确认到 `apply()` 使用同一份受控物化内容。原生 `ctx.approval` 负责 DSH 会话的单次决策。独立 CLI 的确认和锚点是供可信加载器消费的凭据。[DSH 官方审批契约](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/approval.md)

## 首轮静态结构审查（历史记录）

- `blocker`：0
- `should-fix`：3
- `nit`：0

插件的 Host 入口、bundle patch 与实际导出在静态结构上相互匹配，未发现 client/Web 误装配。需要修复的是两个卸载生命周期缺口，以及权限声明完全缺失。

本审查只读取了 `package.json`、`cordis.patch.yml`、`src/`、实际加载的 `dist/`、README 与相关文档；未运行命令、测试或真实 Profile 安装，未修改插件文件。

## 首轮发现（修复前）

[should-fix] 类别：生命周期  
文件：`dsh-plugin-trust-broker/src/core/external-scan.ts:277`

当前行为：

- `runScannerProcess()` 在这里创建外部扫描器子进程，并在 `src/core/external-scan.ts:290`、`:300` 创建超时及 SIGKILL 定时器。
- Host 的 `trustBroker.evaluate()` 经 `src/plugin/index.ts:35` 走到该路径；因此这些资源属于插件 Fiber 的运行期资源，而不只是独立 CLI 的短生命周期资源。
- 现有逻辑只在正常结束、出错或 30 秒超时后清理。`src/plugin/index.ts:44` 的 disposer 只调用 `handle.dispose()`，没有取消正在执行的扫描；卸载 Fiber 不会终止子进程，也不会立即清除两个定时器。
- 实际入口中的对应代码仍存在于 `dist/core/external-scan.js:192`、`:205`、`:216`，不是仅存在于 TypeScript 源码的偏差。

为什么构成问题（引用 DSH 契约）：

Cordis 只自动撤销通过其 API 建立的监听和服务注册，不管理 `child_process` 与定时器。DSH 要求这类资源由 `ctx.effect()` 返回的 disposer 清理。当前卸载后扫描器仍可能继续运行至超时，属于跨 Fiber 生命周期的资源泄漏。超时自清理不能替代卸载清理。

修复方向（具体到代码结构，不给泛化建议）：

1. 给 `EvaluateOptions`、`DetectInput`、`ExternalScanInput` 逐层传递 `AbortSignal`，由 `runScannerProcess()` 监听 abort。
2. abort 时在同一个清理函数中清除主定时器和 `killTimer`、终止子进程并使 Promise 结算；需要 SIGTERM → SIGKILL 升级时，在该清理函数内串行管理，不拆成相互依赖的独立 effect disposer。
3. 在 `src/plugin/index.ts` 的 `apply()` 中维护活动扫描 controller 集合，并在现有 `ctx.effect()` 的 disposer 中先 abort 全部扫描，再关闭审计资源；`evaluate()` 在卸载后应拒绝启动新扫描。CLI 无 Cordis 上下文时继续使用现有的进程内超时清理。

---

[should-fix] 类别：生命周期  
文件：`dsh-plugin-trust-broker/src/runtime/audit.ts:199`

当前行为：

- `tools/post-execute` 和 `system-prompt/assemble` 分别在 `src/runtime/audit.ts:199`、`:232` 等待异步 `next()`，返回后才写审计。
- 卸载时，`src/plugin/index.ts:44` 调用 `handle.dispose()`，而 `src/runtime/audit.ts:394` 仅同步执行 `auditLog.close()`，没有跟踪或等待上述在途回调。
- 如果卸载发生在等待期间，句柄会先关闭；回调恢复后又会执行 `recordDraft()`。`src/core/jsonl.ts:89-92` 看到 `#fd === null` 就重新 `openSync()`，于是插件卸载后仍写文件并留下一个再次打开、却不会再由该 effect 关闭的句柄。
- `JsonlWriter.close()` 不是终态：关闭后再次 `append()` 会重开文件。实际加载的 `dist/runtime/audit.js:156`、`:186`、`:335` 与 `dist/core/jsonl.js:77-80` 保持同样行为。

为什么构成问题（引用 DSH 契约）：

文件句柄不受 Cordis 自动管理，必须由 effect disposer 完整收尾。当前 disposer 与在途异步监听之间没有串行关系，导致“已卸载”之后重新获取资源，卸载不能形成最终资源边界。这正是顺序相关清理必须在同一个 effect disposer 中等待完成的情形。

修复方向（具体到代码结构，不给泛化建议）：

1. 在 `createRuntimeAudit()` 内维护在途 waterfall Promise 集合，并让 `handle.dispose()` 返回 Promise。
2. 将 `src/plugin/index.ts` 的 effect 改为单个异步 disposer：先禁止新的审计写入和服务调用，再 `await Promise.allSettled()` 等待已经接纳的回调，最后调用 `auditLog.close()`；不要把这些步骤分散到多个可能并发执行的 disposer。
3. 给 `JsonlWriter` 增加独立的 `closed` 状态，使 `close()` 之后的 `append()` 失败而不再打开文件，作为防止卸载后重开的最终不变量。

---

[should-fix] 类别：权限声明  
文件：`dsh-plugin-trust-broker/package.json:42`

当前行为：

`dsh` 块只有 `bundle` 和 `compatibility`，没有 `dsh.capabilities`、`dsh.permissions` 或顶层 `permissions`，因此状态为 **`unstated`**，不能解释为“无权限”。从代码可观察到的实际能力面包括：

- **文件系统读写**：读取待审插件树、扫描报告、策略和锚点；创建并追加 `audit.jsonl`、`anchors.jsonl`、`decisions.jsonl`。证据包括 `src/core/hash.ts:382`、`src/core/external-scan.ts:192`、`src/core/jsonl.ts:28`、`:91`。
- **子进程**：默认评估路径可执行 `dsh-trust-check --dir <root> --json`，见 `src/core/external-scan.ts:277`、`:338`；`shell: false`，未发现 shell 命令拼接执行。
- **环境变量**：读取 `DSH_TRUST_BROKER_STORE`、`DSH_HOME`、`DSH_TRUST_CHECK_BIN`，见 `src/runtime/audit.ts:408-411`、`src/core/policy.ts:12-23`。
- **Host 装配能力**：注册五个 Host 事件监听并提供 `trustBroker` 服务，见 `src/runtime/audit.ts:298-331`、`src/plugin/index.ts:43`；未调用 `ctx.tools.register()`。
- **模块加载**：会动态导入固定模块名 `dsh-trust-check`，见 `src/core/external-scan.ts:222-224`。
- 未发现直接网络访问、`node:vm`、`eval` 或 `new Function`。插件虽未注册 Tool，其 `apply()` 内代码仍以 Host 全权限运行；工具隐藏不构成授权边界。

为什么构成问题（引用 DSH 契约）：

DSH 中未声明不等于无能力；Host 代码是否执行也不取决于它是否暴露 Tool。当前 manifest 无法让安装前审查区分“声明与事实一致”和“作者未作任何声明”，这与本项目自身在 `README.md:188` 定义的 `unstated` 语义一致，属于声明缺失而非显式权限矛盾，因此不是 blocker。

修复方向（具体到代码结构，不给泛化建议）：

在现有 `package.json#dsh` 下增加与项目自身声明格式一致的 `capabilities`，至少覆盖：

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

`tool_registry.intercept` 对应 pre/post-execute 观察与瀑布调用；当前代码不修改工具结果，所以 `context.tool_output_rewrite` 保持 `false`。文件根目录和扫描器路径可由调用方配置，不应虚构固定的 `roots` 限制。

## 首轮分类核对（修复前）

### 1. 扩展点一致性

**未发现该类问题。**

- `package.json:13` 将 Host 主入口指向 `dist/plugin/index.js`，实际导出 `name` 与 `apply()`；`apply()` 使用 Host 事件和 `ctx.provide()`，与声明一致。
- 未声明 `dsh.client`，没有 client 入口、Web 依赖或 client bundle 构建需求。
- 未发现 `tools.register`、`systemPrompt`、agent 创建、LLM、HTTP server、provider 等额外扩展点使用。`agent/inbox/inserted` 和 `session/event` 只是审计监听，不是额外的 agent/provider 装配。

### 2. 生命周期配对

除上述两条发现外，其余已观察资源具有清理路径：

- 五个 `ctx.on()` 监听及 `ctx.provide()` 属于 Cordis 自动撤销范围。
- 长生命周期审计句柄已接入 `ctx.effect()`，但存在上述在途回调重开问题。
- 单次 JSONL 追加在 `src/core/jsonl.ts:29-34` 使用 `finally` 关闭；哈希文件句柄在 `src/core/hash.ts:399-405` 关闭；CLI readline 在 `src/cli/main.ts:764-765` 的 `finally` 中关闭。
- 未发现 `setInterval`、网络连接、watcher 或其他子进程创建点。

### 3. 装配路径真实性

**未发现该类问题（静态核对）。**

- `package.json:44` 的 `./cordis.patch.yml` 存在；patch 中的 `id: dsh-plugin-trust-broker`、`name: dsh-plugin-trust-broker` 与 `package.json:2` 及 `src/version.ts:3` 的导出名一致。
- `package.json:13` 的 `./dist/plugin/index.js` 存在，且该实际入口保留 `apply()`、服务注册和 effect disposer。`package.json:32-40` 的发布文件列表包含 `dist/**` 与 patch。
- README 要求安装前先构建，与入口位于被 `.gitignore` 排除的 `dist/` 这一事实一致。
- 未发现运行代码或 patch 中硬编码的本机绝对路径。`README.md:241` 的 `/Users/me/...` 只是策略示例，不参与装配。
- 项目没有 `preset.patch.yml` 或 `INSTALLATION.md`，无额外装配文档可交叉核对；未进行真实 Profile 安装验证。

### 4. 权限声明与代码实际能力的一致性

状态为 **`unstated`**，详见上述权限声明发现。未发现 `node:vm` 执行外部输入的高危路径，也不存在显式声明 `false` 与代码事实直接矛盾的情况。

## 对抗性发现

行号均指修复前的源文件，路径相对于 `dsh-plugin-trust-broker/`。置信度反映证据强度。

```json
[
  {
    "file": "src/plugin/index.ts",
    "line_start": 35,
    "line_end": 40,
    "category": "approval_bypass",
    "what_can_go_wrong": "Host 调用方可把评估请求变成运行指定程序的请求，也能指定报告和锚点来源。",
    "why_this_path_is_vulnerable": "服务原样转发 EvaluateOptions，允许调用方覆盖 trust_check_bin、scannerReport、anchorsFile 和准入策略。调用链若转发候选提供的选项，副作用发生在用户确认前。",
    "likely_impact": "扫描器以 Host 用户权限执行，或准入基线被伪造。触发面是可信 Host 集成错误转发输入。",
    "concrete_fix": "Host 仅接受可信调用者选定的 root 和取消信号，固定日志和内置扫描。CLI 外部扫描只能由操作者显式配置。",
    "confidence": 0.99
  },
  {
    "file": "src/admission/gate.ts",
    "line_start": 98,
    "line_end": 128,
    "category": "approval_bypass",
    "what_can_go_wrong": "可用旧决策接受已被替换的候选树，或者在内容哈希为空时拿到 accepted。",
    "why_this_path_is_vulnerable": "闸门只对比用户哈希与旧决策，JSON 入口绕过 CLI 专有复检。评估先扫描后计算哈希，也允许扫描 A 后锚定被替换的 B。",
    "likely_impact": "已确认的事实和随后能加载的代码脱钩，安装编排可收到错误的成功信号。",
    "concrete_fix": "边复制边哈希私有快照并扫描同一份字节，复核原树。统一闸门要求明确接受完整哈希，再次复核并持久化成功后才返回 accepted。",
    "confidence": 1.0
  },
  {
    "file": "src/cli/render.ts",
    "line_start": 190,
    "line_end": 200,
    "category": "approval_bypass",
    "what_can_go_wrong": "候选提供的控制序列可清屏、移动光标或伪造确认提示。",
    "why_this_path_is_vulnerable": "插件版本、证据和错误原样进入终端。交互 CLI 在展示完整决策之前询问强制确认。",
    "likely_impact": "操作者可能在批准前看不到真实候选身份、权限或风险。",
    "concrete_fix": "先输出完整决策，转义非可信控制字符、换行与方向控制字符，再在真实交互终端请求确认。",
    "confidence": 0.99
  },
  {
    "file": "src/core/external-scan.ts",
    "line_start": 275,
    "line_end": 277,
    "category": "credential",
    "what_can_go_wrong": "外部扫描器继承整个 Host 环境，合成令牌可经 stderr 进入决策输出。",
    "why_this_path_is_vulnerable": "spawn 没有显式 env，347–365 行还拼接原始 stderr 和解析异常。评估插件不需要读取这些环境凭据。",
    "likely_impact": "子进程可读取 API 密钥或登录令牌，日志或终端可能保留明文。",
    "concrete_fix": "构造最小子进程环境，丢弃 stderr，以固定错误码报告失败并限制输出大小。",
    "confidence": 1.0
  },
  {
    "file": "src/runtime/audit.ts",
    "line_start": 366,
    "line_end": 374,
    "category": "credential",
    "what_can_go_wrong": "调用者提供的审计对象可将错误文本、锚点备注或额外字段写入日志。",
    "why_this_path_is_vulnerable": "完整 envelope 被原样追加，draft 也会被展开，审计异常会使用原始错误消息。",
    "likely_impact": "原本只应记录摘要的本机审计存储可保留合成或真实秘密。",
    "concrete_fix": "按事件重建允许的字段，对自由文本取摘要，省略锚点备注与原始异常。新日志使用私有权限。",
    "confidence": 1.0
  },
  {
    "file": "src/core/diff.ts",
    "line_start": 493,
    "line_end": 525,
    "category": "credential",
    "what_can_go_wrong": "含 URL 用户信息或访问令牌参数的 Git、归档和仓库来源会出现在人类及 JSON 审查结果。",
    "why_this_path_is_vulnerable": "依赖 spec 和仓库 URL 同时被复制进事实、证据和差异摘要。",
    "likely_impact": "转存审查报告时可能传播下载凭据。",
    "concrete_fix": "构建事实和证据前移除 URL 用户信息，遮盖常见凭据查询参数并保留来源类型和位置。",
    "confidence": 0.99
  },
  {
    "file": "src/core/manifest.ts",
    "line_start": 110,
    "line_end": 119,
    "category": "file_boundary",
    "what_can_go_wrong": "package.json -> ../outside.json 使评估读取树外身份和声明。",
    "why_this_path_is_vulnerable": "清单读取跟随链接，哈希只覆盖链接文本。普通路径检查与后续打开之间也可发生路径交换。",
    "likely_impact": "树外数据会进入审查，且可在候选哈希不变的情况下替换。",
    "concrete_fix": "拒绝候选树中的符号链接、硬链接、特殊文件和越界入口。读取时检查物理路径与文件描述符身份，并扫描私有快照。",
    "confidence": 1.0
  },
  {
    "file": "src/core/diff.ts",
    "line_start": 40,
    "line_end": 48,
    "category": "failure_path",
    "what_can_go_wrong": "显式扫描超时、无效报告或不支持 schema 后仍可能继续准入。",
    "why_this_path_is_vulnerable": "判定使用与实际扫描器错误码不一致的列表，回退扫描仍可能标为完整。",
    "likely_impact": "调用方依赖的显式检查被跳过，CLI 可向下游返回继续信号。",
    "concrete_fix": "显式扫描失败一律标记覆盖不完整，返回 block_for_review，保留启发式诊断。",
    "confidence": 1.0
  },
  {
    "file": "src/runtime/audit.ts",
    "line_start": 188,
    "line_end": 246,
    "category": "failure_path",
    "what_can_go_wrong": "卸载期间暂停的瀑布回调恢复后会重开日志文件。",
    "why_this_path_is_vulnerable": "旧 dispose 只关闭当前描述符，JsonlWriter 会把关闭误当成尚未打开。已经捕获的 Host 服务引用也能继续写入。",
    "likely_impact": "插件卸载无法终止其审计写入和资源使用。",
    "concrete_fix": "卸载时立即终止写入器状态并拒绝新服务操作，取消并等待在途评估。迟到回调继续透传下游结果。",
    "confidence": 1.0
  },
  {
    "file": "src/core/external-scan.ts",
    "line_start": 168,
    "line_end": 185,
    "category": "supply_chain",
    "what_can_go_wrong": "安装前扫描自动执行发布锁文件之外的模块和 PATH 程序。",
    "why_this_path_is_vulnerable": "动态导入在检查接口前执行模块顶层，失败后还会尝试启动 PATH 程序。两份实际运行的代码都独立于 Broker 发布包。",
    "likely_impact": "只读评估变成未审查代码的执行入口。临时测试中，故意抛异常的模块仍先写入标记。",
    "concrete_fix": "删除自动 import 和 PATH 发现。显式扫描器使用可信绝对路径，拒绝来自待审树及其快照的可执行文件，并限制时间、输出和生命周期。",
    "confidence": 1.0
  },
  {
    "file": "src/core/hash.ts",
    "line_start": 342,
    "line_end": 347,
    "category": "supply_chain",
    "what_can_go_wrong": "带换行的单个文件名可产生与两个文件相同的规范化输入。",
    "why_this_path_is_vulnerable": "未经编码的路径直接拼入以换行分隔的聚合清单。",
    "likely_impact": "已复现换树后新增 fetch 代码，却复用旧哈希并跳过确认。",
    "concrete_fix": "使用 v2 域和无歧义的 JSON 元组聚合路径与内容摘要。旧哈希保留历史用途。",
    "confidence": 1.0
  },
  {
    "file": "src/core/hash.ts",
    "line_start": 43,
    "line_end": 44,
    "category": "supply_chain",
    "what_can_go_wrong": "只替换 node_modules 下实际被 import 的代码，旧哈希仍匹配。",
    "why_this_path_is_vulnerable": "默认哈希和启发式扫描排除了已物化依赖，锁定声明无法代表本机执行的依赖字节。",
    "likely_impact": "已复现锚点匹配、准入建议继续，但实际 Node 加载的依赖输出改变。",
    "concrete_fix": "准入哈希和内置扫描覆盖整棵已物化树。由加载器维持批准内容和执行来源的一致性。",
    "confidence": 1.0
  },
  {
    "file": "src/core/decision.ts",
    "line_start": 80,
    "line_end": 84,
    "category": "supply_chain",
    "what_can_go_wrong": "同一内容哈希可跳过新增扫描事实、风险红线或更新后的供应链确认。",
    "why_this_path_is_vulnerable": "任一匹配锚点即清空整个确认队列。外部报告成功时还会丢弃本地检出的能力。",
    "likely_impact": "新证据或收紧的风险策略可能无法触发重新确认。",
    "concrete_fix": "只在历史锚点覆盖当前能力集时复用能力确认，来源策略照常评估。外部报告只补充证据。",
    "confidence": 0.99
  },
  {
    "file": "src/core/diff.ts",
    "line_start": 238,
    "line_end": 273,
    "category": "supply_chain",
    "what_can_go_wrong": "无效期望哈希被忽略，只含 registry_signature=verified 的输入也可显示为已验证来源。",
    "why_this_path_is_vulnerable": "解析失败被折叠成缺失。签名状态未与任何实际候选字节绑定。",
    "likely_impact": "批准者可看到超出实际证据的来源背书，错误的完整性配置静默失效。",
    "concrete_fix": "拒绝无效期望哈希。仅在可信调用方报告已核验且其解包树哈希匹配时显示签名来源。",
    "confidence": 0.99
  },
  {
    "file": "src/runtime/audit.ts",
    "line_start": 188,
    "line_end": 223,
    "category": "context_integrity",
    "what_can_go_wrong": "普通 accept 被记录成工具输出改写，真实模型上下文变化混入误报。",
    "why_this_path_is_vulnerable": "工具结果被直接与结构不同的 PostToolDecision 比较。原测试用结果对象模拟 next，掩盖了真实契约。",
    "likely_impact": "运行审计难以分辨正常调用和真实的替换、阻断反馈、附加上下文。",
    "concrete_fix": "按原生决策的模型可见效果计算前后摘要。原样传递工具决策、装配结果和异常。",
    "confidence": 1.0
  }
]
```

### 失败最终状态

- 候选根路径、清单和锁文件不可读，哈希不完整，遇到不支持的文件类型，目录或内容在审查中变化，或显式扫描缺失、超时、超限、非零退出、报告解析失败，评估返回 `unscannable / block_for_review`。没有配置外部扫描时使用内置扫描。
- 清单身份可读但权限声明格式错误，默认 `malformed_manifest / confirm`。来源哈希不匹配默认 `block_for_review`。可信策略显式降级来源不一致时，仍要求 `source_mismatch` 确认。格式无效的期望哈希直接阻断。
- 确认拒绝、缺少确认或写锚前内容改变，闸门拒绝写锚。CLI 对待确认或内容变化返回 2，对阻断返回 3，对锚点写入失败和用法错误返回 1。决策日志写失败单独告警。
- 审计分类失败保留现有派发结果，归属不可核验时记为 `unattributed`。审计写入失败告警。原生拒绝或下游异常保持原样。卸载取消待处理评估并终止写入。项目没有 MCP 调用，也没有回退到扩大沙箱权限的分支。

### 供应链与上下文清单

- Broker 自身无运行时依赖，开发依赖由 `package-lock.json` 固定版本和 SRI，均来自 npm registry。发布包无安装生命周期脚本、自动更新或直接网络获取。示例插件的 `postinstall` 是测试用候选，未进入发布包。
- 外部报告按结构读取。显式 CLI 扫描器的实际代码由操作者独立选择和核验，独立于 Broker 锁文件。候选树的 `package.json` 和 npm v2/v3 锁文件提供来源清单，整棵已物化树参加准入哈希。后续下载、安装期脚本生成内容、外部模块解析和自动更新仍需加载器管理。
- `tools/pre-execute` 观察请求并返回原生 `next()` 决策。`tools/post-execute` 观察结果替换、阻断反馈和附加上下文。`system-prompt/assemble` 只观察装配前后。`agent/inbox/inserted` 与 `session/event` 观察已插入消息及已发生的历史压缩。Broker 写入本机 JSONL 摘要，声明覆盖观察钩子和文件访问。提示词注入、工具输出改写与历史压缩声明为 false。[DSH 官方扩展约定](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/cookbook/extension-cookbook.md)
- Host 读取日志目录配置与 OS 路径解析所需环境变量。CLI 读取终端颜色配置。外部扫描进程的环境只包含由当前 Node 可执行目录生成的 PATH。原生工具审批仍走 DSH，Host 服务没有对模型注册自建工具、审批答复者或 HTTP 路由。

### 原结构待办的修复

1. Host 移除外部扫描器执行路径。评估受 Fiber 取消信号管理。独立 CLI 扫描器遇超时、取消或超限会终止子进程并清理计时器。
2. 审计 disposer 立即停止写入，JSONL close 成为终态。原生在途瀑布完成后照常交付结果。
3. `package.json#dsh.capabilities` 补充文件、环境、子进程及观察钩子的真实声明，并标明上下文变更、直接网络及自动更新为 false。

### 验证与剩余边界

- 修复前基线 155 项全过。复现使用临时目录、合成令牌和合成工具。覆盖外部清单链接、换行哈希歧义、排除依赖替换、旧决策写锚、扫描中换树、扫描器环境泄漏和原生 `accept` 误报。
- 修复后 `npm run check` 通过类型检查、179 项测试和 `dist/` 构建。离线打包验证了 63 个归档条目、Host 导出与 bundle patch。打包 CLI 的只读审查暂停等待确认，接受完整哈希后写入一条锚点。独立适配器验证使用了 `dsh-trust-check@0.2.5`。
- 原生 DSH 0.2.1-rc.2 内存集成覆盖加载、拒绝透传、正常 accept、工具结果替换、提示词装配和 Fiber 卸载。使用临时日志与合成工具。真实 profile 安装、用户审批 UI 和安装后自动加载闸门仍待联调。
- 私有快照把评估事实和哈希绑定到同一组已读取字节。实际加载前的最后一次竞态、动态导入、外部依赖和同进程对抗仍属于可信加载器和来源隔离的边界。真实加载流程应核对同一份已确认物化树，且将独立 `review` 的退出码 0 与已写锚的 `admission.accepted` 区分。

