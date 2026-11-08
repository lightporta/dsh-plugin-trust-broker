# Web 安装前安全审查（v0.2.0）

状态：已随 `dsh-plugin-trust-broker@0.2.0` 安装进当前 DSH desktop profile；Host 接口与审查真实跑通，浏览器内的像素渲染和“确认 → 原生安装”点击路径尚未由浏览器自动化验证。

## 1. 为什么不是“在原安装弹窗里内嵌”

DSH 内置的「添加插件」弹窗（输入包名 / GitHub 地址 / 本地目录，然后点“安装”）是 `@deepseek-ai/dsh-client-ui-plugin-manager` 的固定组件。实时 Slot 目录显示它**没有向插件开放可注入的 slot**，因此插件无法在那个输入框下面直接追加审查结果。

DSH 0.2.2-rc.1 中可用的官方扩展点是：

| Slot | 用途 | 本实现 |
|---|---|---|
| `plugins.tab` | 插件页新增标签页；owner 还提供 `install(target)`，可把已确认的 spec 直接送进原生安装的检查/进度界面 | **使用**：`trust-broker-review`（安全审查） |
| `plugins.add.actions` | “+” 菜单追加操作行 | 未使用 |
| `plugins.detail.section` | 已安装插件详情页追加区块 | 未使用 |
| `plugins.bundle.config` / `plugins.row.config` | 配置表单 | 未使用（本插件无 Config） |

因此本实现是**等价流程，而不是对原弹窗的替换**：

- 审查入口：左侧栏「插件 → 安全审查」标签页；
- 审查确认后：交给原生安装弹窗的**检查/进度界面**，不再重复输入 spec；
- 模型自行安装：走原生审批弹窗。

## 2. 用户流程

1. 打开「插件」页，切到「安全审查」（在「已安装」「发现」之后）。
2. 输入 npm spec（`name`、`name@version`、range、tag）、GitHub/git 地址或本地目录。停止输入 700 ms 后自动开始审查；也可点「重新审查」或按 Enter。
3. 面板依次展示：
   - 固定 Host 代码披露（与 CLI 同一句话）；
   - 来源可信度、声明状态（`declared` / `unstated` / `malformed` 等）；
   - 检出能力面：可复核事实与 `heuristic: true` 分区，附能力路径；
   - 安装脚本、AUTO_UPDATE / 远程内容、持续信任警告；
   - 可复制的内容哈希、解析后的包名/版本/来源、registry 与 tarball 完整性；
   - A/B/C 差异（含 `file:line` 或元数据指针）、建议动作（proceed / confirm / block）；
   - 逐项强制确认（勾选框 + 「确认口令」）。
4. 勾选全部强制确认后，「确认并安装」才可用。点击后：
   1. `POST api/trust-broker/confirm` 写入 `TrustAnchor`；
   2. 用 `review.resolved.install_spec` 调 owner 提供的 `install(target)`，进入原生安装检查/进度界面。
5. 安装由 DSH 原生流程完成；本页面只显示「已写入信任锚点并交给 DSH 安装流程」，不宣称安装成功。

模型路径：模型调用 `plugin_manager` 的 `install_bundle` 时，Host 在 `tools/pre-execute` 阶段先完成同一套审查，然后把摘要放进原生审批弹窗；用户批准后才执行安装。

## 3. Host 端实现

- 入口：`src/host/service.ts` 的 `createTrustHostServices()`。
- 候选获取（`src/host/spec.ts` + `materialize.ts`）：
  - 本地目录：原地审查，不复制、不删除；
  - npm：registry 元数据 → 精确版本 / tag / 常见 range → tarball（60 s、64 MiB 上限）→ 校验 `dist.integrity`（sha512/sha256/sha1）或 legacy shasum → 内置 tar 读取器解压；
  - git：`git clone --depth 1 --single-branch --no-tags`（argv 调用、无 shell、超时可取消），审查前移除 `.git`；
  - tarball URL/本地归档：下载或读取后同样安全解压。
- tar 读取器只用 `node:zlib`：拒绝绝对路径、`..`、NUL、重复路径、符号链接、硬链接、设备/FIFO、PAX 路径走私和超限内容；剥离 npm tarball 的 `package/` 前缀。
- 审查：`evaluatePluginTrust({ noExternalScanner: true, ... })`，与 CLI 使用同一套声明/差异/哈希/确认逻辑。
- 审查缓存：30 分钟、最多 32 条 LRU；确认是单次操作，成功后写锚；未知/过期 review 返回 `review_expired`；内容哈希为 null 时确认会被 `blocked_for_review` 拒绝，不会伪造锚点。
- 同源 HTTP 接口（Host 挂在 `/api/trust-broker` 前缀）：
  - `POST /review` `{spec}` → `{ok:true, review}` / `{ok:false, error}`；
  - `POST /confirm` `{review_id, acknowledgements:[codes]}` → `{ok:true, anchor}` / `{ok:false, error}`；
  - `GET /health` → `{ok:true, version, store_dir}`。
- 候选目录位于 `<store_dir>/candidates/review-*`（0700；文件 0600），不会出现在返回给客户端的 JSON 中；失败/淘汰/确认/dispose 时清理。

## 4. 安全语义与限制

- **审查绑定的是本次解包内容哈希**，不是未来安装的字节。交给原生流程时按 `install_spec` 重新获取：
  - npm 固定到精确版本（registry 通常不可变）；
  - git 地址未固定 commit；
  - tarball URL 内容可能变化。
- **不是 loader 级强制点**：DSH 0.2.x 没有 pre-apply veto；内置「安装第三方插件」弹窗仍可绕过审查直接安装。要彻底强制需 DSH 上游在该弹窗增加 slot。
- **模型安装门禁**：`plugin_manager install_bundle` 会先走原生审批；审查失败时仍会弹出“无法完成安装前审查”的警示并允许用户决定（与 CLI “审查失败不冒充安全”原则一致）。
- **网络能力**：Host 端为获取 registry 元数据/tarball 使用 `fetch`，因此 `package.json#dsh.capabilities` 已从 `network.fetch: false` 更新为 `true`；git clone 使用已声明的 `process.child_process`。
- **耗时**：npm/git 候选需要下载/克隆；模型安装的审批会在审查完成后才出现（上限约 60 s）。UI 用骨架屏/取消/过期保护处理慢请求。
- **不持久化 UI 审查状态**：切换标签页后需要重新输入/审查；锚点写入是持久的。

## 5. 验证记录（2026-11-09）

- `npm run check`：**226 项测试全过**，类型检查与构建干净；`npm pack --dry-run` 84 个文件，包含 `client.js` 与 `dist/host/**`。
- 重新安装 0.2.0：`application: applied`、`warnings: []`、`link:` 指向 workspace。
- Host 实测：
  - `GET /api/trust-broker/health` → `{"ok":true,"version":"0.2.0","store_dir":"/Users/anowell/.dsh/trust-broker"}`；
  - 本地目录审查 → `scanned` / `proceed` / `declared` / 内容哈希 `sha256:8aec…`；
  - npm `dsh-context@0.82.2` → tarball 下载约 2.1 s，`integrity: "verified"`，`declaration: "unstated"`，要求 `unstated_capabilities` 确认；
  - 空 spec → `invalid_spec`。
- Client：实时 Slot 查询显示 `plugins.tab` 的占用者为 `discover` 与 `trust-broker-review`（active）。
- 未验证：浏览器实际像素/明暗主题、点击「确认并安装」后的原生安装弹窗、模型安装审批弹窗在真实会话中的呈现（受限于无浏览器控制；上述 API 与 Slot 已实测）。

## 6. 故障排查

- **看不到「安全审查」标签页**：刷新 DSH 页面一次（客户端模块在安装后可能需要重新加载）；确认插件已启用且版本为 0.2.0。
- **审查报 `registry_unreachable` / 超时**：检查网络/代理或换 npm 镜像；本地目录审查不依赖网络。
- **确认按钮灰**：检查是否勾选全部强制确认、review 是否过期/输入是否被改过、`content_hash` 是否为空（unscannable 禁止写锚）、建议动作是否为 `block_for_review`。
- **安装没有继续**：确认已写入锚点；若 `install` 入口缺失（非插件页 owner），页面会提示先写锚但需从插件页安装。
- **审查路由 404**：Host 侧未加载新版本或 webServer 不可用；确认 `/api/trust-broker/health` 返回 0.2.0。
