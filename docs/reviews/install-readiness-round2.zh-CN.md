# 安装前审查与安装验证（第二轮）

[English review](install-readiness-round2.en.md)

- **日期**：2026-11-08
- **审查对象**：`/Users/anowell/Documents/Github-Projects/dsh-plugin-trust-broker`
- **审查基线**：HEAD `b3eeb73`
- **修复提交**：`980bfd0`（"Cover the bundle-patch composition surface before installation"）
- **安装结果**：已在当前 DSH desktop profile 安装并验证运行时审计（见 §5）
- **审查方式**：两个独立只读 reviewer（安装就绪性 / 对抗性）+ Lead 自审 + 用本工具的 CLI 自审打包产物

## 1. 结论

**安装可用（GO）：无安装阻断项。** 两个独立 reviewer 均确认 bundle manifest、DSH 版本兼容、patch 解析、locale/icon、Host `apply()` 生命周期与 Cordis 卸载语义正常；在 DSH 0.2.2-rc.1（desktop host）上 `application: applied`。

但在安装前的对抗性复审中发现，**工具自身的 bundle-patch 组合面检测存在可绕过的 major 缺口**，与文档声称不一致。该缺口不阻止安装本插件（本插件自己的 patch 只插入自身 row），但会让未来的安装前闸门漏检。已按 fail-closed 方向修复并回归验证。

## 2. 发现与修复

| # | 级别 | 发现 | 修复 |
|---|---|---|---|
| M1 | major | `dsh.bundle.patch` 只对字符串形式、且文件名为 `cordis.patch.yml` 时做行级正则检测；数组形式不校验/不分析，标准 DSH id-targeted `config:` 覆盖、`disabled: True/TRUE`、多行布尔、JSON/flow patch 均可绕过 → `proceed` 且无差异 | 新增结构化 patch 解析（JSON 数组或 block list，与 DSH loader 语义一致）：manifest 声明的每个 patch 路径都校验并解析；`insert` 条目保持低权限；**任何非 insert 顶层条目**视为对 profile row 的 id-targeted 变更 → 高权限 `composition.override` → 首次安装强制确认；无法解析/二进制/越界/缺失 patch 一律 `unscannable` |
| M2 | major | `composition.override` 虽标记高权限且不可声明，但首次安装时没有锚点就不会产生 A/B 差异，因此从不进入强制确认队列 | 新增差异码 `observed_non_declarable_capability`：首次安装检出该事实即生成 `new_capability: true` 的 A 类差异；锚点已覆盖或同哈希跳过时不重复 |
| m1 | minor | 外部扫描器 `injections[].detail` 未做 URL 凭据脱敏和长度上限 | `redactUrlCredentials` + 空白折叠 + 200 字符上限 |
| m2 | minor | `context_audit:false` 只抑制 inbox/compaction，prompt_assembly 与 tool_output_rewrite 仍写入 | 统一抑制全部派生 `context_write` 渠道；`tool_result.rewritten` 仍保留 |
| m3 | minor | `anchors --json` / `audit --json` 对损坏日志静默返回 0，JSON 中无 errors | JSON 增加 `errors` 且损坏时退出码 1 |
| m4 | minor | `require_ack_for_unstated:false` 会连带抑制未声明/malformed 插件由检出事实推导的强制确认 | 记录到文档与 policy 说明（显式放宽，保留在决策 `policy` 字段） |
| m5 | minor | 远程内容指示器只看 `prepublish/prepare/postinstall`，漏 `preinstall/install` | 五个生命周期脚本全部纳入 |
| m6 | minor | 严格哈希拒绝 symlink/hardlink，pnpm/npm 物化目录会被判 `unscannable` | 文档明确：应审查/锚定干净的 `npm pack` 解压树或受控暂存副本 |
| — | minor | `dist/` 被 gitignore，干净 checkout 打包会缺产物 | 增加 `prepack: npm run build`（非安装生命周期脚本） |
| — | minor | `engines.dsh` 单区间在默认 semver 工具下对 prerelease 不友好 | 改为 `>=0.2.0-rc.2 \|\| >=0.2.1-rc.2 \|\| >=0.2.2-rc.1`（DSH 自身用 `includePrerelease`，两者均满足） |

## 3. 测验与验证

- `npm run check`：typecheck 通过、**198 / 198 tests pass**、`dist/` 构建通过。
- 新增 `test/review-fixes.test.ts`（15 项回归）：数组 patch、真实 DSH patch 形态、`disabled: True`、JSON patch、二进制/不可解析 patch、stray patch、扫描器 detail 脱敏、context_audit、损坏日志 CLI 退出码等。
- 使用对抗性 reviewer 的探针脚本复测：`r9` 的 8 种绕过形态现在全部 `confirm`；`r10` 的注释/config 误报消失；`r4` 的 stray patch / 越界 / 二进制 / 缺失 patch 全部 fail closed；声明 patch 数量上限 64。
- `npm pack --dry-run`：69 个文件，含 `dist/plugin/index.js`、patch、locale、icon；无 `src/test/examples/node_modules` 泄漏。
- DSH 兼容性：用真实 `@deepseek-ai/dsh-app-boot` 的 `evaluatePluginCompatibility()` 对 0.2.0-rc.2 / 0.2.1-rc.2 / 0.2.2-rc.1 全部返回兼容；`loadOverlayPatches()` 解析出相同的 insert row；`readPluginMeta()` 解析出 en/zh 标题、描述和 SVG icon。
- 真实 Cordis 4.1.0 内存集成：`apply()` 提供 `trustBroker`、注册五个审计监听、waterfall 原样返回 `next()`、卸载后无写入。

## 4. 安装

```text
plugin_manager({ action: "install_bundle", target: "/Users/anowell/Documents/Github-Projects/dsh-plugin-trust-broker" })
→ application: "applied"; warnings: []; registries: [null]
→ dependencies: + dsh-plugin-trust-broker 0.1.0 <- ../../Documents/Github-Projects/dsh-plugin-trust-broker
→ profile bundles 追加 dsh-plugin-trust-broker
```

- profile：`/Users/anowell/.dsh/profiles/desktop`，bundle 通过 `link:` 指向 workspace（`node_modules/dsh-plugin-trust-broker` 为符号链接）。
- 安装未改写仓库：`git status --short` 为空。
- `Config.listConfigs {name:"dsh-plugin-trust-broker"}` → 1 个 entry `include:dsh-plugin-trust-broker`（无 Config export，`status: absent` 属预期），`packageDir` 指向 profile node_modules。
- `Service.listService {service:"trustBroker"}` 不列出该服务（inspect 目录只收录可编目的 Service；`ctx.provide` 的普通对象不入目录），因此以运行时证据确认激活。

## 5. 安装后运行时证据

- 安装后工具调用立即写入 `~/.dsh/trust-broker/audit.jsonl`（目录 0700、文件 0600）：
  - `schema_version: 1`、`event`、单调 `seq`、`id`、`ts`；
  - `tool_call` 含 `arguments_digest`（脱敏后 canonical JSON 的 sha-256）、`argument_keys`、意图能力类别、`scope: unattributed`（未配置 `tool_owners` 时的预期值）；
  - `tool_result` 含 `ok`、`result_digest`、`settled_digest`、`rewritten`。
- `node bin/trust-broker.mjs audit --verify --json` → `records: 8, problems: []`。
- `anchor` 日志为空（尚未通过 CLI 确认锚定；安装本身不写锚点）。
- 探测到的首条记录是安装操作自身的 `tool_result`（插件在安装过程中激活），随后正常记录 `cordis_inspect_query` 与 `bash` 调用。

## 6. 剩余边界（不阻断安装，但必须如实告知）

1. **安装本 bundle 不等于接管 `plugin_manager` 准入。** DSH 0.2.x 没有 loader 级 pre-apply veto；安装后生效的是运行时审计 + `trustBroker` 服务。安装前审查/锚定仍需在安装前运行 CLI，或由宿主接入该服务。
2. **GUI 渲染未验证**：title/description/icon 已用真实 `readPluginMeta` 静态验证；桌面页面中的实际渲染需要浏览器控制，本次未覆盖。
3. **工具归属**：`scope` 默认 `unattributed`；配置 `tool_owners` 或 `setToolOwner` 后才有真实的 `declared / undeclared_scope` 判定。
4. **审计增长**：`audit.jsonl` 只追加、每工具调用一行以上，v1 不轮转；长期使用需外部轮转。
5. **自审噪声**：用本工具审自己的打包产物时，静态扫描器/启发式会命中工具自身的规则表文本（如 `fetch(`、能力名），产生 `confirm` 的误报；这是静态扫描自指限制，已记录，不影响安装。
6. **锚定前提**：严格哈希拒绝 symlink/hardlink；锚定应针对干净打包解压树或受控暂存目录，而非带 `node_modules` 的工作目录。

## 7. 回滚

```text
plugin_manager({ action: "remove_bundle", target: "dsh-plugin-trust-broker" })
```

移除后运行时审计停止；已写入的 `~/.dsh/trust-broker/audit.jsonl` 保留（如需清理请手动处理）。
