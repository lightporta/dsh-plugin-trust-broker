/**
 * Web Client half of the plugin trust broker: a "Security review" tab on the
 * DSH Plugins page.
 *
 * This file is a plain browser module for the DSH Client module loader: no
 * build step, no imports beyond the module table's `react`. It registers two
 * locale dictionaries and one `plugins.tab` occupant (a list slot declared by
 * the Plugins page owner), then talks to the Host review service over the
 * same-origin routes `api/trust-broker/review` and `api/trust-broker/confirm`.
 *
 * Contract notes:
 * - The Host route projection is `UiReview` / `UiDecision` from
 *   `src/host/protocol.ts`; the client never evaluates trust on its own.
 * - Confirming writes the content-hash trust anchor on the Host and then
 *   hands the exact resolved install spec to the owner-provided `install`
 *   prop, which opens the native install check/progress UI. The tab never
 *   claims the installation itself succeeded.
 * - All visible UI text comes from the `dsh-trust-broker-client` namespace.
 */
window.__ModuleLoader__.load({
  id: 'dsh-plugin-trust-broker',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const useState = React.useState;
    const useEffect = React.useEffect;
    const useRef = React.useRef;
    const useCallback = React.useCallback;

    /** Locale namespace owned by this client half. */
    const NS = 'dsh-trust-broker-client';
    /** `plugins.tab` list entry id. */
    const SLOT_ID = 'trust-broker-review';
    /** Host review route, relative to the application base (same origin). */
    const REVIEW_ROUTE = 'api/trust-broker/review';
    /** Host confirm route, relative to the application base (same origin). */
    const CONFIRM_ROUTE = 'api/trust-broker/confirm';
    /** Idle time after typing before an automatic review starts. */
    const AUTO_REVIEW_DELAY_MS = 700;
    /** How long the "copied" / "copy failed" label stays. */
    const COPY_RESET_MS = 1600;

    // ---------------------------------------------------------------------
    // Theme tokens. Only host `--dsw-alias-*` tokens (with light-mode
    // fallbacks for degraded hosts) style the tab; the `<style>` element
    // below only adds interaction states that inline styles cannot express.
    // ---------------------------------------------------------------------

    const COLORS = {
      text: 'var(--dsw-alias-label-primary, #1f2329)',
      secondary: 'var(--dsw-alias-label-secondary, #61666b)',
      muted: 'var(--dsw-alias-label-tertiary, #81858c)',
      caption: 'var(--dsw-alias-label-caption, #adb2b8)',
      border: 'var(--dsw-alias-border-l3, #0000001f)',
      borderStrong: 'var(--dsw-alias-border-l4, #00000029)',
      card: 'var(--dsw-alias-bg-layer-1, #ffffff)',
      input: 'var(--dsw-alias-bg-base, #ffffff)',
      hover: 'var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06))',
      code: 'var(--dsw-alias-markdown-code-block, #f9fafb)',
      skeleton: 'var(--dsw-alias-bg-skeleton, rgba(0, 0, 0, 0.04))',
      brand: 'var(--dsw-alias-brand-primary, #0f1115)',
      onBrand: 'var(--dsw-alias-label-primary-foreground, #ffffff)',
      brandHover: 'var(--dsw-alias-button-primary-hover, #4b5057)',
      success: 'var(--dsw-alias-state-success-primary, #22c55e)',
      successBg: 'var(--dsw-alias-state-success-tertiary, #e6faed)',
      warn: 'var(--dsw-alias-state-warn-primary, #f59e0b)',
      warnLabel: 'var(--dsw-alias-state-warn-label, #dd8629)',
      warnBg: 'var(--dsw-alias-state-warn-tertiary, #fef5e7)',
      error: 'var(--dsw-alias-state-error-primary, #ec1313)',
      business: 'var(--dsw-alias-state-business-primary, #4176e6)',
      radiusSm: 'var(--dsw-radius-sm, 8px)',
      radiusMd: 'var(--dsw-radius-md, 12px)',
      radiusLg: 'var(--dsw-radius-lg, 16px)',
      mono: 'var(--ds-font-family-code, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace)',
    };

    const STYLE_TEXT = [
      '.dsh-tb-input:focus-visible{outline:2px solid var(--dsw-alias-brand-primary,#0f1115);outline-offset:1px}',
      '.dsh-tb-btn{font-family:inherit;transition:background-color .12s ease,opacity .12s ease}',
      '.dsh-tb-btn:focus-visible{outline:2px solid var(--dsw-alias-brand-primary,#0f1115);outline-offset:2px}',
      '.dsh-tb-btn-primary:not(:disabled):hover{background:var(--dsw-alias-button-primary-hover,#4b5057)}',
      '.dsh-tb-btn-secondary:not(:disabled):hover{background:var(--dsw-alias-interactive-bg-hover,rgba(38,49,72,.06))}',
      '.dsh-tb-checkbox{accent-color:var(--dsw-alias-brand-primary,#0f1115);flex:0 0 auto;width:15px;height:15px;margin:1px 0 0;cursor:pointer}',
      '@keyframes dsh-tb-pulse{0%,100%{opacity:.55}50%{opacity:1}}',
      '.dsh-tb-skeleton{animation:dsh-tb-pulse 1.4s ease-in-out infinite}',
      '@media (prefers-reduced-motion:reduce){.dsh-tb-skeleton{animation:none}}',
    ].join('\n');

    const STYLES = {
      root: {
        display: 'flex',
        flexDirection: 'column',
        gap: '18px',
        width: '100%',
        maxWidth: '860px',
        margin: '0 auto',
        paddingBottom: '24px',
        boxSizing: 'border-box',
        color: COLORS.text,
        fontFamily: 'inherit',
        fontSize: '13px',
        lineHeight: '20px',
      },
      reviewBody: { display: 'flex', flexDirection: 'column', gap: '16px', minWidth: 0 },
      header: { display: 'flex', flexDirection: 'column', gap: '4px' },
      title: { margin: 0, fontSize: '18px', lineHeight: '26px', fontWeight: 600, color: COLORS.text },
      subtitle: { margin: 0, fontSize: '13px', lineHeight: '20px', color: COLORS.muted },
      specSection: { display: 'flex', flexDirection: 'column', gap: '6px' },
      inputLabel: { fontSize: '12px', lineHeight: '18px', fontWeight: 500, color: COLORS.secondary },
      specRow: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' },
      input: {
        flex: '1 1 240px',
        minWidth: '200px',
        boxSizing: 'border-box',
        height: '34px',
        padding: '0 10px',
        border: '1px solid ' + COLORS.border,
        borderRadius: COLORS.radiusSm,
        background: COLORS.input,
        color: COLORS.text,
        fontFamily: 'inherit',
        fontSize: '13px',
        outline: 'none',
      },
      primaryButton: {
        flex: '0 0 auto',
        padding: '7px 14px',
        border: '1px solid transparent',
        borderRadius: COLORS.radiusSm,
        background: COLORS.brand,
        color: COLORS.onBrand,
        fontSize: '13px',
        fontWeight: 500,
        lineHeight: '18px',
        cursor: 'pointer',
      },
      secondaryButton: {
        flex: '0 0 auto',
        padding: '7px 14px',
        border: '1px solid ' + COLORS.border,
        borderRadius: COLORS.radiusSm,
        background: 'transparent',
        color: COLORS.text,
        fontSize: '13px',
        fontWeight: 500,
        lineHeight: '18px',
        cursor: 'pointer',
      },
      smallButton: {
        flex: '0 0 auto',
        padding: '3px 10px',
        border: '1px solid ' + COLORS.border,
        borderRadius: COLORS.radiusSm,
        background: 'transparent',
        color: COLORS.secondary,
        fontSize: '12px',
        fontWeight: 500,
        lineHeight: '18px',
        cursor: 'pointer',
      },
      buttonDisabled: { opacity: 0.45, cursor: 'not-allowed' },
      card: {
        border: '1px solid ' + COLORS.border,
        borderRadius: COLORS.radiusLg,
        background: COLORS.card,
        padding: '14px 16px',
        minWidth: 0,
        boxSizing: 'border-box',
      },
      cardTitle: { margin: '0 0 10px', fontSize: '13.5px', lineHeight: '20px', fontWeight: 600, color: COLORS.text },
      cardBody: { display: 'flex', flexDirection: 'column', gap: '8px', minWidth: 0 },
      row: { display: 'flex', alignItems: 'flex-start', gap: '10px', minWidth: 0 },
      rowLabel: { flex: '0 0 112px', fontSize: '12.5px', lineHeight: '19px', color: COLORS.muted },
      rowValue: { flex: '1 1 auto', minWidth: 0, fontSize: '13px', lineHeight: '19px', color: COLORS.text, overflowWrap: 'anywhere' },
      valueStack: { display: 'flex', flexDirection: 'column', gap: '2px', minWidth: 0 },
      detail: { fontSize: '12px', lineHeight: '18px', color: COLORS.muted, overflowWrap: 'anywhere' },
      subTitle: { margin: 0, fontSize: '12.5px', lineHeight: '19px', fontWeight: 600, color: COLORS.secondary },
      captionText: { fontSize: '12px', lineHeight: '18px', color: COLORS.muted },
      badgeRow: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', minWidth: 0 },
      chipRow: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', minWidth: 0 },
      badge: {
        display: 'inline-flex',
        alignItems: 'center',
        height: '19px',
        padding: '0 7px',
        borderRadius: '999px',
        border: '1px solid transparent',
        fontSize: '11px',
        fontWeight: 600,
        lineHeight: '1',
        whiteSpace: 'nowrap',
        letterSpacing: '0.01em',
      },
      chip: {
        display: 'inline-block',
        maxWidth: '100%',
        padding: '1px 6px',
        border: '1px solid ' + COLORS.border,
        borderRadius: COLORS.radiusSm,
        background: COLORS.code,
        color: COLORS.secondary,
        fontFamily: COLORS.mono,
        fontSize: '11.5px',
        lineHeight: '18px',
        overflowWrap: 'anywhere',
      },
      mono: {
        fontFamily: COLORS.mono,
        fontSize: '12px',
        lineHeight: '18px',
        color: COLORS.text,
        overflowWrap: 'anywhere',
        wordBreak: 'break-word',
      },
      list: { margin: 0, padding: '0 0 0 16px', display: 'flex', flexDirection: 'column', gap: '3px', fontSize: '12.5px', lineHeight: '19px', color: COLORS.text, overflowWrap: 'anywhere' },
      group: { display: 'flex', flexDirection: 'column', gap: '6px', minWidth: 0 },
      groupTitle: { fontSize: '12px', lineHeight: '18px', fontWeight: 500, color: COLORS.muted },
      category: { display: 'flex', flexDirection: 'column', gap: '4px', padding: '8px 10px', borderRadius: COLORS.radiusMd, border: '1px solid ' + COLORS.border, minWidth: 0 },
      categoryHead: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', minWidth: 0 },
      categoryLabel: { fontSize: '12.5px', lineHeight: '19px', fontWeight: 500, color: COLORS.text, overflowWrap: 'anywhere' },
      inlineWrap: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', minWidth: 0 },
      noticeTitle: { fontSize: '12.5px', lineHeight: '19px', fontWeight: 600, color: COLORS.text },
      noticeText: { margin: 0, fontSize: '12.5px', lineHeight: '19px', color: COLORS.text, overflowWrap: 'anywhere' },
      hint: { margin: 0, fontSize: '12px', lineHeight: '18px', color: COLORS.muted, overflowWrap: 'anywhere' },
      warnBox: {
        display: 'flex',
        flexDirection: 'column',
        gap: '4px',
        padding: '10px 12px',
        border: '1px solid ' + COLORS.warn,
        borderRadius: COLORS.radiusMd,
        background: COLORS.warnBg,
        minWidth: 0,
        boxSizing: 'border-box',
      },
      errorBox: {
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        padding: '10px 12px',
        border: '1px solid ' + COLORS.error,
        borderRadius: COLORS.radiusMd,
        background: COLORS.card,
        minWidth: 0,
        boxSizing: 'border-box',
      },
      successBox: {
        display: 'flex',
        flexDirection: 'column',
        gap: '4px',
        padding: '10px 12px',
        border: '1px solid ' + COLORS.success,
        borderRadius: COLORS.radiusMd,
        background: COLORS.successBg,
        minWidth: 0,
        boxSizing: 'border-box',
      },
      errorLine: { display: 'flex', alignItems: 'flex-start', gap: '8px', flexWrap: 'wrap', minWidth: 0 },
      errorRow: { display: 'flex', alignItems: 'flex-start', gap: '8px', flexWrap: 'wrap', minWidth: 0 },
      hashBlock: { display: 'flex', flexDirection: 'column', gap: '6px', paddingTop: '8px', borderTop: '1px solid ' + COLORS.border, minWidth: 0 },
      hashLabel: { fontSize: '12.5px', lineHeight: '19px', fontWeight: 600, color: COLORS.secondary },
      hashRow: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', minWidth: 0 },
      hashValue: {
        flex: '1 1 240px',
        minWidth: '200px',
        padding: '8px 10px',
        border: '1px solid ' + COLORS.border,
        borderRadius: COLORS.radiusSm,
        background: COLORS.code,
        color: COLORS.text,
        fontFamily: COLORS.mono,
        fontSize: '12px',
        lineHeight: '18px',
        overflowWrap: 'anywhere',
        wordBreak: 'break-all',
      },
      diffList: { display: 'flex', flexDirection: 'column', gap: '8px', minWidth: 0 },
      diffRow: {
        display: 'flex',
        flexDirection: 'column',
        gap: '5px',
        padding: '9px 10px',
        border: '1px solid ' + COLORS.border,
        borderRadius: COLORS.radiusMd,
        minWidth: 0,
      },
      diffHead: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', minWidth: 0 },
      diffSummary: { margin: 0, fontSize: '12.5px', lineHeight: '19px', color: COLORS.text, overflowWrap: 'anywhere' },
      evidenceRow: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', minWidth: 0 },
      confirmList: { display: 'flex', flexDirection: 'column', gap: '10px', minWidth: 0 },
      confirmRow: { display: 'flex', alignItems: 'flex-start', gap: '8px', cursor: 'pointer', minWidth: 0 },
      confirmText: { display: 'flex', flexDirection: 'column', gap: '2px', minWidth: 0 },
      confirmMessage: { fontSize: '12.5px', lineHeight: '19px', color: COLORS.text, overflowWrap: 'anywhere' },
      ackLine: { fontSize: '12px', lineHeight: '18px', color: COLORS.muted, overflowWrap: 'anywhere' },
      actionRow: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', minWidth: 0 },
      loadingCard: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        padding: '14px 16px',
        border: '1px solid ' + COLORS.border,
        borderRadius: COLORS.radiusLg,
        background: COLORS.card,
        minWidth: 0,
      },
      loadingTitle: { margin: 0, fontSize: '13px', lineHeight: '20px', fontWeight: 500, color: COLORS.secondary },
      skeletonStack: { display: 'flex', flexDirection: 'column', gap: '8px', paddingTop: '4px' },
      skeletonBar: { display: 'block', height: '12px', borderRadius: COLORS.radiusSm, background: COLORS.skeleton },
      skeletonBarWide: { display: 'block', height: '12px', width: '100%', borderRadius: COLORS.radiusSm, background: COLORS.skeleton },
      skeletonBarMid: { display: 'block', height: '12px', width: '72%', borderRadius: COLORS.radiusSm, background: COLORS.skeleton },
      skeletonBarShort: { display: 'block', height: '12px', width: '46%', borderRadius: COLORS.radiusSm, background: COLORS.skeleton },
      skeletonCard: { display: 'block', height: '52px', width: '100%', borderRadius: COLORS.radiusMd, background: COLORS.skeleton },
    };

    const BADGE_TONES = {
      neutral: { color: COLORS.secondary, background: 'transparent', border: '1px solid ' + COLORS.border },
      info: { color: COLORS.text, background: 'transparent', border: '1px solid ' + COLORS.business },
      success: { color: COLORS.text, background: COLORS.successBg, border: '1px solid ' + COLORS.success },
      warn: { color: COLORS.text, background: COLORS.warnBg, border: '1px solid ' + COLORS.warn },
      error: { color: COLORS.error, background: 'transparent', border: '1px solid ' + COLORS.error },
    };

    // ---------------------------------------------------------------------
    // English / Chinese dictionaries for the `dsh-trust-broker-client`
    // namespace. Every visible label goes through one of these entries.
    // ---------------------------------------------------------------------

    const EN = {
      tab: 'Security review',
      title: 'Review before install',
      subtitle:
        'Inspect the plugin source, its declarations, and detected capability differences before installing. A confirmed review writes a content-hash trust anchor, then hands off to the native DSH install flow.',
      specLabel: 'Plugin source',
      specPlaceholder: 'e.g. dsh-plugin-whale-pet, or an absolute local directory path',
      reviewNow: 'Review again',
      reviewing: 'Reviewing…',
      reviewingHint: 'Downloading and scanning the plugin can take a few seconds.',
      emptyHint: 'Enter a plugin name or a local path. The review starts automatically about 0.7s after you stop typing.',
      retry: 'Retry',
      reviewFailedTitle: 'Review failed',
      invalidResponse: 'The host returned an unrecognized review response.',
      transportUnavailable: 'This page cannot send review requests.',
      networkError: 'Could not reach the host review service.',
      unknownError: 'Unknown error',
      hostCodeTitle: 'This plugin runs as Host code',
      hostCodeWarning:
        'This plugin runs as Host code: it shares the DSH host process and host privileges; DSH provides no plugin-level process isolation.',
      sourceCardTitle: 'Source, declarations, and detected capabilities',
      sourceTrustLabel: 'Source trust',
      declarationLabel: 'Capability declaration',
      declaredAt: 'Declared at',
      categoriesLabel: 'Detected capability surface',
      noCategories: 'No capability surface detected.',
      factsGroupLabel: 'Verifiable facts',
      heuristicGroupLabel: 'Heuristic (separate from facts)',
      factsCount: 'Facts: {count}',
      heuristicCount: 'Heuristic: {count}',
      heuristicBadge: 'heuristic',
      installCardTitle: 'Install scripts and update mechanism',
      installScriptsLabel: 'Install scripts',
      noInstallScripts: 'No install scripts detected.',
      autoUpdateLabel: 'AUTO_UPDATE / remote content',
      autoUpdateDetected: 'Detected',
      autoUpdateNotDetected: 'Not detected',
      autoUpdateDeclared: 'Declared',
      autoUpdateUndeclared: 'Not declared',
      autoUpdateReasonsLabel: 'Reasons',
      noReasons: 'None',
      continuousTrustWarning:
        'This plugin fetches remote content or updates itself: after this confirmation, later content changes bypass this review.',
      hashCardTitle: 'Content hash and resolution',
      contentHashLabel: 'Content hash',
      noContentHash: 'None (a content hash is required to write a trust anchor)',
      copy: 'Copy',
      copied: 'Copied',
      copyFailed: 'Copy failed',
      resolvedLabel: 'Plugin',
      kindLabel: 'Kind',
      installSpecLabel: 'Install spec',
      registryLabel: 'Registry',
      tarballShaLabel: 'Tarball SHA-256',
      integrityLabel: 'Transport integrity',
      integrityVerified: 'verified',
      integrityUnavailable: 'unavailable',
      resolutionNoteLabel: 'Resolution note',
      createdAtLabel: 'Review created',
      expiresAtLabel: 'Review expires',
      decisionCardTitle: 'Diffs and suggested action',
      decisionStatusLabel: 'Review status:',
      diffsTitle: 'Diffs ({count})',
      noDiffs: 'No differences between declarations and detected facts.',
      newCapabilityBadge: 'new capability',
      evidenceLabel: 'Evidence:',
      evidenceMore: 'More evidence: {count}',
      proceedBanner: 'Review passed: confirm to continue to installation.',
      confirmBanner: 'Explicit confirmation required: check every item below.',
      blockedBanner: 'The review blocks installation. Fix the source or policy, then review again.',
      confirmCardTitle: 'Required confirmations',
      noConfirmations: 'No mandatory confirmation.',
      ackPhraseLabel: 'Acknowledgement phrase:',
      ackHint: 'Check every confirmation before installing.',
      confirmAndInstall: 'Confirm and install',
      confirming: 'Writing trust anchor…',
      confirmFailedTitle: 'Confirmation failed',
      handoffDone: 'Trust anchor written; the plugin was handed off to the DSH install flow.',
      handoffAnchorOnly: 'Trust anchor written, but this page has no install entry; install it again from the Plugins page.',
      expiredHint: 'This review expired; review again before confirming.',
      staleHint: 'The plugin source changed; waiting for the new review to finish.',
      blockedHint: 'The review blocks installation.',
      noHashHint: 'A content hash is required to write a trust anchor.',
      anchorWritten: 'Trust anchor:',
      errorsCardTitle: 'Review errors',
      redLinesCardTitle: 'Red-line risks (facts only)',
      coverageLabel: 'Scan coverage',
      coverageIncomplete:
        'Scan coverage is incomplete: some files or capabilities could not be checked, so this conclusion may be incomplete.',
      coverageComplete: 'Scan coverage is complete.',
      statusScanned: 'scanned',
      statusUnscannable: 'unscannable',
      statusMalformed: 'malformed manifest',
      actionProceed: 'proceed',
      actionConfirm: 'confirm',
      actionBlock: 'block',
      declarationDeclared: 'declared',
      declarationUnstated: 'unstated',
      declarationIncomplete: 'incomplete',
      declarationMalformed: 'malformed',
      sourceRegistrySignature: 'registry signature',
      sourceHashMatch: 'hash match',
      sourceHashMismatch: 'hash mismatch',
      sourceUnverified: 'unverified',
      sourceUndeclared: 'undeclared',
      kindLocal: 'local directory',
      kindNpm: 'npm package',
      kindGit: 'git repository',
      kindTarball: 'tarball',
      diffTypeA: 'A declaration insufficient',
      diffTypeB: 'B capability drift',
      diffTypeC: 'C source-content mismatch',
    };

    const ZH = {
      tab: '安全审查',
      title: '安全审查后安装',
      subtitle: '安装前检查插件来源、权限声明与检出能力差异；确认后写入内容哈希信任锚点，再交给 DSH 原生安装流程。',
      specLabel: '插件来源',
      specPlaceholder: '例如 dsh-plugin-whale-pet，或本地目录绝对路径',
      reviewNow: '重新审查',
      reviewing: '正在审查…',
      reviewingHint: '下载并扫描插件可能需要数秒，请稍候。',
      emptyHint: '输入插件名称或本地路径，停止输入约 0.7 秒后自动开始审查。',
      retry: '重试',
      reviewFailedTitle: '审查失败',
      invalidResponse: '宿主返回了无法识别的审查结果。',
      transportUnavailable: '当前页面无法发起审查请求。',
      networkError: '无法连接到宿主审查服务。',
      unknownError: '未知错误',
      hostCodeTitle: '该插件将作为 Host 代码运行',
      hostCodeWarning: '该插件将作为 Host 代码运行：与 DSH 宿主同进程、拥有宿主权限；DSH 不提供插件级进程隔离。',
      sourceCardTitle: '来源、声明与检出能力',
      sourceTrustLabel: '来源可信度',
      declarationLabel: '权限声明状态',
      declaredAt: '声明字段',
      categoriesLabel: '检出能力面',
      noCategories: '未检出能力面。',
      factsGroupLabel: '可复核事实',
      heuristicGroupLabel: '启发式（与事实分区）',
      factsCount: '事实：{count} 项',
      heuristicCount: '启发式：{count} 项',
      heuristicBadge: '启发式',
      installCardTitle: '安装脚本与更新机制',
      installScriptsLabel: '安装脚本',
      noInstallScripts: '未检出安装脚本。',
      autoUpdateLabel: 'AUTO_UPDATE / 远程内容',
      autoUpdateDetected: '已检出',
      autoUpdateNotDetected: '未检出',
      autoUpdateDeclared: '已声明',
      autoUpdateUndeclared: '未声明',
      autoUpdateReasonsLabel: '依据',
      noReasons: '无',
      continuousTrustWarning: '该插件会持续获取远程内容或自动更新：首次确认之后，后续内容变化不再经过本次审查。',
      hashCardTitle: '内容哈希与解析结果',
      contentHashLabel: '内容哈希',
      noContentHash: '无（缺少内容哈希，无法写入信任锚点）',
      copy: '复制',
      copied: '已复制',
      copyFailed: '复制失败',
      resolvedLabel: '插件',
      kindLabel: '类型',
      installSpecLabel: '安装参数',
      registryLabel: '注册表',
      tarballShaLabel: '包哈希',
      integrityLabel: '传输完整性',
      integrityVerified: '已校验',
      integrityUnavailable: '不可用',
      resolutionNoteLabel: '解析说明',
      createdAtLabel: '审查生成时间',
      expiresAtLabel: '审查有效期',
      decisionCardTitle: '差异与建议动作',
      decisionStatusLabel: '审查状态：',
      diffsTitle: '差异（{count}）',
      noDiffs: '未发现声明与检出事实的差异。',
      newCapabilityBadge: '新增能力',
      evidenceLabel: '证据：',
      evidenceMore: '另有 {count} 条证据',
      proceedBanner: '审查通过：确认后即可进入安装流程。',
      confirmBanner: '需要显式确认：请逐项勾选下方确认项。',
      blockedBanner: '审查结论为阻断，不能进入安装流程；请先修正来源或策略后重新审查。',
      confirmCardTitle: '强制确认',
      noConfirmations: '无需强制确认。',
      ackPhraseLabel: '确认口令：',
      ackHint: '勾选全部确认项后才能安装。',
      confirmAndInstall: '确认并安装',
      confirming: '正在写入信任锚点…',
      confirmFailedTitle: '确认失败',
      handoffDone: '已写入信任锚点并交给 DSH 安装流程。',
      handoffAnchorOnly: '已写入信任锚点，但当前页面没有安装入口，请从插件页重新发起安装。',
      expiredHint: '审查已过期，请重新审查后再确认。',
      staleHint: '插件来源已修改，正在等待新的审查结果。',
      blockedHint: '审查结论为阻断，不能安装。',
      noHashHint: '缺少内容哈希，无法写入信任锚点。',
      anchorWritten: '信任锚点：',
      errorsCardTitle: '审查错误',
      redLinesCardTitle: '风险红线（仅陈列事实）',
      coverageLabel: '扫描覆盖',
      coverageIncomplete: '扫描覆盖不完整：部分文件或能力未能检查，结论可能不完整。',
      coverageComplete: '扫描覆盖完整。',
      statusScanned: '已扫描',
      statusUnscannable: '无法完整扫描',
      statusMalformed: '清单格式错误',
      actionProceed: '通过',
      actionConfirm: '需要确认',
      actionBlock: '阻断',
      declarationDeclared: '已声明',
      declarationUnstated: '未声明',
      declarationIncomplete: '声明不完整',
      declarationMalformed: '声明格式错误',
      sourceRegistrySignature: '注册表签名',
      sourceHashMatch: '内容哈希匹配',
      sourceHashMismatch: '内容哈希不匹配',
      sourceUnverified: '未验证来源',
      sourceUndeclared: '来源未声明',
      kindLocal: '本地目录',
      kindNpm: 'npm 包',
      kindGit: 'Git 仓库',
      kindTarball: '归档包',
      diffTypeA: 'A 声明不足',
      diffTypeB: 'B 能力漂移',
      diffTypeC: 'C 来源-内容不一致',
    };

    // ---------------------------------------------------------------------
    // Small pure helpers. None of them touch the DOM or the network.
    // ---------------------------------------------------------------------

    function passthroughText(key) {
      return key;
    }

    function asArray(value) {
      return Array.isArray(value) ? value : [];
    }

    function textOr(value, fallback) {
      if (typeof value === 'string' && value.trim() !== '') return value;
      return typeof fallback === 'string' ? fallback : '';
    }

    function formatEvidenceRef(evidence) {
      if (!evidence || typeof evidence !== 'object') return '';
      if (typeof evidence.file === 'string' && evidence.file !== '') {
        return typeof evidence.line === 'number' && evidence.line > 0 ? evidence.file + ':' + evidence.line : evidence.file;
      }
      if (typeof evidence.field === 'string' && evidence.field !== '') return evidence.field;
      return '';
    }

    function firstEvidenceLabel(evidenceList) {
      for (const evidence of asArray(evidenceList)) {
        const label = formatEvidenceRef(evidence);
        if (label !== '') return label;
      }
      return '';
    }

    function formatTimestamp(value) {
      if (typeof value !== 'string' || value.trim() === '') return '';
      const parsed = Date.parse(value);
      if (!Number.isFinite(parsed)) return value;
      try {
        return new Date(parsed).toLocaleString();
      } catch (_error) {
        return value;
      }
    }

    function isExpired(value) {
      if (typeof value !== 'string' || value.trim() === '') return false;
      const parsed = Date.parse(value);
      if (!Number.isFinite(parsed)) return false;
      return Date.now() > parsed;
    }

    function hasContentHash(review) {
      return Boolean(
        review &&
          review.decision &&
          typeof review.decision.content_hash === 'string' &&
          review.decision.content_hash.trim() !== '',
      );
    }

    function pluginLabel(review) {
      const resolved = review && review.resolved ? review.resolved : {};
      const plugin = review && review.decision && review.decision.plugin ? review.decision.plugin : {};
      const name = textOr(resolved.name, textOr(plugin.id, ''));
      const version = textOr(resolved.version, textOr(plugin.version, ''));
      if (name === '' && version === '') return '';
      return version === '' ? name : name + '@' + version;
    }

    function actionTone(action) {
      if (action === 'proceed') return 'success';
      if (action === 'confirm') return 'warn';
      if (action === 'block_for_review') return 'error';
      return 'neutral';
    }

    function sourceTrustTone(kind) {
      if (kind === 'registry_signature' || kind === 'hash_match') return 'success';
      if (kind === 'hash_mismatch') return 'error';
      if (kind === 'unverified' || kind === 'undeclared') return 'warn';
      return 'neutral';
    }

    function declarationTone(status) {
      if (status === 'declared') return 'neutral';
      if (status === 'malformed') return 'error';
      if (status === 'unstated' || status === 'incomplete') return 'warn';
      return 'neutral';
    }

    function integrityTone(integrity) {
      if (integrity === 'verified') return 'success';
      if (integrity === 'unavailable') return 'warn';
      return 'neutral';
    }

    function actionLabel(t, action) {
      if (action === 'proceed') return t('actionProceed');
      if (action === 'confirm') return t('actionConfirm');
      if (action === 'block_for_review') return t('actionBlock');
      return textOr(action, '');
    }

    function statusLabel(t, status) {
      if (status === 'scanned') return t('statusScanned');
      if (status === 'unscannable') return t('statusUnscannable');
      if (status === 'malformed_manifest') return t('statusMalformed');
      return textOr(status, '');
    }

    function declarationStatusLabel(t, status) {
      if (status === 'declared') return t('declarationDeclared');
      if (status === 'unstated') return t('declarationUnstated');
      if (status === 'incomplete') return t('declarationIncomplete');
      if (status === 'malformed') return t('declarationMalformed');
      return textOr(status, '');
    }

    function sourceTrustKindLabel(t, kind) {
      if (kind === 'registry_signature') return t('sourceRegistrySignature');
      if (kind === 'hash_match') return t('sourceHashMatch');
      if (kind === 'hash_mismatch') return t('sourceHashMismatch');
      if (kind === 'unverified') return t('sourceUnverified');
      if (kind === 'undeclared') return t('sourceUndeclared');
      return textOr(kind, '');
    }

    function candidateKindLabel(t, kind) {
      if (kind === 'local') return t('kindLocal');
      if (kind === 'npm') return t('kindNpm');
      if (kind === 'git') return t('kindGit');
      if (kind === 'tarball') return t('kindTarball');
      return textOr(kind, '');
    }

    function diffTypeLabel(t, type) {
      if (type === 'A_declaration_insufficient') return t('diffTypeA');
      if (type === 'B_capability_drift') return t('diffTypeB');
      if (type === 'C_source_content_mismatch') return t('diffTypeC');
      return textOr(type, '');
    }

    function integrityLabel(t, integrity) {
      if (integrity === 'verified') return t('integrityVerified');
      if (integrity === 'unavailable') return t('integrityUnavailable');
      return textOr(integrity, '');
    }

    /** Localize a `{code, message}` pair produced by this client. */
    function errorText(t, info) {
      const code = info && typeof info.code === 'string' && info.code !== '' ? info.code : 'unknown';
      let message = info && typeof info.message === 'string' ? info.message : '';
      if (message === '') {
        if (code === 'transport_unavailable') message = t('transportUnavailable');
        else if (code === 'invalid_response') message = t('invalidResponse');
        else if (code === 'network_error') message = t('networkError');
        else if (code === 'stale_review') message = t('staleHint');
        else if (code === 'expired_review') message = t('expiredHint');
        else if (code === 'blocked_review') message = t('blockedHint');
        else if (code === 'missing_hash') message = t('noHashHint');
        else message = t('unknownError');
      }
      return { code, message };
    }

    /** Wrap a failed value into the tab's `{code, message}` error shape. */
    function toErrorInfo(error) {
      if (error && typeof error === 'object') {
        const code = typeof error.code === 'string' && error.code !== '' ? error.code : '';
        const message = typeof error.message === 'string' ? error.message : '';
        if (code !== '' || message !== '') return { code: code === '' ? 'unknown' : code, message };
      }
      return { code: 'unknown', message: typeof error === 'string' ? error : '' };
    }

    function isAbortError(error) {
      return Boolean(error && (error.name === 'AbortError' || error.code === 'ABORT_ERR'));
    }

    function createAbortController() {
      try {
        if (typeof AbortController === 'function') return new AbortController();
      } catch (_error) {
        /* fall through: the request simply cannot be aborted */
      }
      return null;
    }

    function abortRef(ref) {
      const controller = ref.current;
      ref.current = null;
      if (!controller) return;
      try {
        controller.abort();
      } catch (_error) {
        /* abort is best-effort */
      }
    }

    function getFetch() {
      try {
        if (typeof fetch === 'function') return fetch.bind(globalThis);
        if (typeof window !== 'undefined' && window && typeof window.fetch === 'function') {
          return window.fetch.bind(window);
        }
      } catch (_error) {
        /* fall through */
      }
      return null;
    }

    function clientError(code, message) {
      const error = new Error(typeof message === 'string' ? message : '');
      error.code = code;
      return error;
    }

    /**
     * POST JSON to a same-origin Host route and normalize the wire contract:
     * `{ok:true, ...}` resolves, `{ok:false,error:{code,message}}` and any
     * transport/parse failure rejects with a `{code, message}`-capable Error.
     */
    async function postJson(route, body, signal) {
      const fetchImpl = getFetch();
      if (fetchImpl === null) throw clientError('transport_unavailable');
      let response;
      try {
        response = await fetchImpl(route, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
          credentials: 'same-origin',
          signal,
        });
      } catch (error) {
        if (isAbortError(error)) throw error;
        throw clientError('network_error');
      }
      let payload = null;
      try {
        payload = await response.json();
      } catch (_error) {
        payload = null;
      }
      if (payload && typeof payload === 'object' && payload.ok === true) return payload;
      const hostError =
        payload && typeof payload === 'object' && payload.error && typeof payload.error === 'object'
          ? payload.error
          : null;
      if (hostError && typeof hostError.code === 'string') {
        const error = new Error(typeof hostError.message === 'string' ? hostError.message : '');
        error.code = hostError.code;
        throw error;
      }
      throw clientError('invalid_response');
    }

    function copyToClipboard(text) {
      try {
        if (
          typeof navigator !== 'undefined' &&
          navigator &&
          navigator.clipboard &&
          typeof navigator.clipboard.writeText === 'function'
        ) {
          return navigator.clipboard.writeText(String(text)).then(
            () => true,
            () => false,
          );
        }
      } catch (_error) {
        /* fall through to reported failure */
      }
      return Promise.resolve(false);
    }

    // ---------------------------------------------------------------------
    // Presentational primitives. They are plain functions, not components,
    // so they never introduce hook identity into the tab body.
    // ---------------------------------------------------------------------

    function Badge(text, tone, key) {
      const toneStyle = BADGE_TONES[tone] || BADGE_TONES.neutral;
      return h('span', { key, style: Object.assign({}, STYLES.badge, toneStyle) }, text);
    }

    function Chip(text, key) {
      return h('code', { key, style: STYLES.chip }, text);
    }

    function InfoRow(label, value, key) {
      return h(
        'div',
        { key, style: STYLES.row },
        h('span', { style: STYLES.rowLabel }, label),
        h('span', { style: STYLES.rowValue }, value),
      );
    }

    function Card(title, children, key) {
      return h(
        'section',
        { key, style: STYLES.card, 'aria-label': title },
        h('h3', { style: STYLES.cardTitle }, title),
        h('div', { style: STYLES.cardBody }, children),
      );
    }

    function notice(tone, title, message, key) {
      const boxStyle = tone === 'error' ? STYLES.errorBox : tone === 'success' ? STYLES.successBox : STYLES.warnBox;
      return h(
        'div',
        { key, style: boxStyle },
        title === '' ? null : h('strong', { style: STYLES.noticeTitle }, title),
        h('p', { style: STYLES.noticeText }, message),
      );
    }

    // ---------------------------------------------------------------------
    // Section renderers.
    // ---------------------------------------------------------------------

    function renderHostCodeWarning(t) {
      return notice('warn', t('hostCodeTitle'), t('hostCodeWarning'), 'host-code-warning');
    }

    function renderCategory(t, category, key) {
      const paths = asArray(category.capability_paths).filter((path) => typeof path === 'string' && path !== '');
      const label = textOr(category.label, textOr(category.family, ''));
      return h(
        'div',
        { key, style: STYLES.category },
        h(
          'div',
          { style: STYLES.categoryHead },
          h('span', { style: STYLES.categoryLabel }, label),
          category.family && category.label ? Chip(category.family, 'family') : null,
          category.heuristic === true ? Badge(t('heuristicBadge'), 'warn', 'heuristic') : null,
        ),
        paths.length > 0
          ? h(
              'div',
              { style: STYLES.chipRow },
              paths.map((path, index) => Chip(path, 'path-' + index)),
            )
          : null,
      );
    }

    function renderSourceCard(t, decision) {
      const categories = asArray(decision.categories);
      const facts = categories.filter((category) => category && category.heuristic !== true);
      const heuristics = categories.filter((category) => category && category.heuristic === true);
      const sourceTrust = decision.source_trust && typeof decision.source_trust === 'object' ? decision.source_trust : {};
      const declaration = decision.declaration && typeof decision.declaration === 'object' ? decision.declaration : {};
      const counts = [];
      if (typeof decision.facts_count === 'number') {
        counts.push(Badge(t('factsCount', { count: decision.facts_count }), 'neutral', 'facts-count'));
      }
      if (typeof decision.heuristic_count === 'number') {
        counts.push(Badge(t('heuristicCount', { count: decision.heuristic_count }), 'neutral', 'heuristic-count'));
      }
      const children = [
        InfoRow(
          t('sourceTrustLabel'),
          h(
            'span',
            { style: STYLES.valueStack },
            h(
              'span',
              { style: STYLES.badgeRow },
              Badge(sourceTrustKindLabel(t, sourceTrust.kind), sourceTrustTone(sourceTrust.kind), 'trust-kind'),
            ),
            textOr(sourceTrust.detail, '') === ''
              ? null
              : h('span', { style: STYLES.detail }, textOr(sourceTrust.detail, '')),
          ),
          'source-trust',
        ),
        InfoRow(
          t('declarationLabel'),
          h(
            'span',
            { style: STYLES.valueStack },
            h(
              'span',
              { style: STYLES.badgeRow },
              Badge(declarationStatusLabel(t, declaration.status), declarationTone(declaration.status), 'decl-status'),
            ),
            textOr(declaration.source_field, '') === ''
              ? null
              : h('span', { style: STYLES.detail }, t('declaredAt') + ' ' + declaration.source_field),
          ),
          'declaration',
        ),
        counts.length > 0 ? h('div', { key: 'counts', style: STYLES.badgeRow }, counts) : null,
        h('div', { key: 'categories-heading', style: STYLES.subTitle }, t('categoriesLabel')),
      ];
      if (categories.length === 0) {
        children.push(h('p', { key: 'no-categories', style: STYLES.hint }, t('noCategories')));
      }
      if (facts.length > 0) {
        children.push(
          h(
            'div',
            { key: 'facts-group', style: STYLES.group },
            h('div', { style: STYLES.groupTitle }, t('factsGroupLabel')),
            facts.map((category, index) => renderCategory(t, category, 'fact-' + index)),
          ),
        );
      }
      if (heuristics.length > 0) {
        children.push(
          h(
            'div',
            { key: 'heuristic-group', style: STYLES.group },
            h('div', { style: STYLES.groupTitle }, t('heuristicGroupLabel')),
            heuristics.map((category, index) => renderCategory(t, category, 'heuristic-' + index)),
          ),
        );
      }
      return Card(t('sourceCardTitle'), children, 'card-source');
    }

    function renderInstallCard(t, decision) {
      const scripts = asArray(decision.install_scripts).filter((script) => script && typeof script === 'object');
      const autoUpdate = decision.auto_update && typeof decision.auto_update === 'object' ? decision.auto_update : {};
      const reasons = asArray(autoUpdate.reasons).filter((reason) => typeof reason === 'string' && reason !== '');
      const children = [h('div', { key: 'scripts-heading', style: STYLES.subTitle }, t('installScriptsLabel'))];
      if (scripts.length === 0) {
        children.push(h('p', { key: 'no-scripts', style: STYLES.hint }, t('noInstallScripts')));
      } else {
        children.push(
          h(
            'ul',
            { key: 'scripts', style: STYLES.list },
            scripts.map((script, index) =>
              h(
                'li',
                { key: 'script-' + index },
                h('span', { style: STYLES.categoryLabel }, textOr(script.name, '')),
                textOr(script.command, '') === '' ? null : h('code', { style: STYLES.mono }, ' ' + script.command),
              ),
            ),
          ),
        );
      }
      children.push(
        h(
          'div',
          { key: 'auto-update', style: STYLES.inlineWrap },
          h('span', { style: STYLES.subTitle }, t('autoUpdateLabel')),
          Badge(
            autoUpdate.detected === true ? t('autoUpdateDetected') : t('autoUpdateNotDetected'),
            autoUpdate.detected === true ? 'warn' : 'neutral',
            'auto-detected',
          ),
          Badge(
            autoUpdate.declared === true ? t('autoUpdateDeclared') : t('autoUpdateUndeclared'),
            autoUpdate.declared === true ? 'neutral' : 'warn',
            'auto-declared',
          ),
        ),
      );
      if (reasons.length > 0) {
        children.push(h('div', { key: 'reasons-heading', style: STYLES.captionText }, t('autoUpdateReasonsLabel')));
        children.push(
          h(
            'ul',
            { key: 'reasons', style: STYLES.list },
            reasons.map((reason, index) => h('li', { key: 'reason-' + index }, reason)),
          ),
        );
      } else if (autoUpdate.detected === true) {
        children.push(h('p', { key: 'no-reasons', style: STYLES.hint }, t('noReasons')));
      }
      if (decision.continuous_trust_warning === true) {
        children.push(notice('warn', '', t('continuousTrustWarning'), 'continuous-warning'));
      }
      return Card(t('installCardTitle'), children, 'card-install');
    }

    function renderResolvedCard(t, review, copyState, onCopy) {
      const decision = review.decision || {};
      const resolved = review.resolved && typeof review.resolved === 'object' ? review.resolved : {};
      const created = formatTimestamp(review.created_at);
      const expires = formatTimestamp(review.expires_at);
      const hash = hasContentHash(review) ? review.decision.content_hash : null;
      const children = [
        InfoRow(t('resolvedLabel'), pluginLabel(review) || '—', 'resolved-plugin'),
        InfoRow(
          t('kindLabel'),
          Badge(candidateKindLabel(t, resolved.kind), 'neutral', 'resolved-kind'),
          'resolved-kind-row',
        ),
        InfoRow(
          t('installSpecLabel'),
          textOr(resolved.install_spec, '') === ''
            ? h('span', { style: STYLES.hint }, '—')
            : h('code', { style: STYLES.mono }, resolved.install_spec),
          'resolved-spec',
        ),
      ];
      if (textOr(resolved.registry, '') !== '') {
        children.push(InfoRow(t('registryLabel'), h('code', { style: STYLES.mono }, resolved.registry), 'resolved-registry'));
      }
      if (textOr(resolved.tarball_sha256, '') !== '') {
        children.push(
          InfoRow(t('tarballShaLabel'), h('code', { style: STYLES.mono }, resolved.tarball_sha256), 'resolved-tarball'),
        );
      }
      if (textOr(resolved.integrity, '') !== '') {
        children.push(
          InfoRow(
            t('integrityLabel'),
            Badge(integrityLabel(t, resolved.integrity), integrityTone(resolved.integrity), 'resolved-integrity'),
            'resolved-integrity-row',
          ),
        );
      }
      if (textOr(resolved.note, '') !== '') {
        children.push(InfoRow(t('resolutionNoteLabel'), h('span', { style: STYLES.detail }, resolved.note), 'resolved-note'));
      }
      children.push(
        h(
          'div',
          { key: 'content-hash', style: STYLES.hashBlock },
          h('span', { style: STYLES.hashLabel }, t('contentHashLabel')),
          hash === null
            ? h('p', { style: STYLES.hint }, t('noContentHash'))
            : h(
                'div',
                { style: STYLES.hashRow },
                h('code', { style: STYLES.hashValue }, hash),
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'dsh-tb-btn dsh-tb-btn-secondary',
                    style: STYLES.smallButton,
                    onClick: onCopy,
                  },
                  copyState === 'copied' ? t('copied') : copyState === 'failed' ? t('copyFailed') : t('copy'),
                ),
              ),
        ),
      );
      if (created !== '' || expires !== '') {
        children.push(
          h(
            'p',
            { key: 'review-times', style: STYLES.hint },
            [created === '' ? '' : t('createdAtLabel') + ' ' + created, expires === '' ? '' : t('expiresAtLabel') + ' ' + expires]
              .filter((line) => line !== '')
              .join(' · '),
          ),
        );
      }
      return Card(t('hashCardTitle'), children, 'card-resolved');
    }

    function renderDecisionBanner(t, decision) {
      const action = decision.action;
      const tone = actionTone(action);
      const color = tone === 'success' ? COLORS.success : tone === 'warn' ? COLORS.warn : tone === 'error' ? COLORS.error : COLORS.borderStrong;
      const background = tone === 'success' ? COLORS.successBg : tone === 'warn' ? COLORS.warnBg : 'transparent';
      const message =
        action === 'proceed' ? t('proceedBanner') : action === 'confirm' ? t('confirmBanner') : action === 'block_for_review' ? t('blockedBanner') : '';
      return h(
        'div',
        {
          key: 'decision-banner',
          style: {
            display: 'flex',
            flexDirection: 'column',
            gap: '4px',
            padding: '10px 12px',
            border: '1px solid ' + color,
            borderRadius: COLORS.radiusMd,
            background,
            minWidth: 0,
          },
        },
        h(
          'div',
          { style: STYLES.badgeRow },
          Badge(actionLabel(t, action), tone, 'decision-action'),
          h('span', { style: STYLES.captionText }, t('decisionStatusLabel') + ' ' + statusLabel(t, decision.status)),
        ),
        message === '' ? null : h('p', { style: STYLES.noticeText }, message),
      );
    }

    function renderDiff(t, diff, index) {
      const evidence = asArray(diff.evidence);
      const evidenceLabelText = firstEvidenceLabel(evidence);
      const head = [
        Badge(diffTypeLabel(t, diff.type), 'neutral', 'diff-type'),
        textOr(diff.code, '') === '' ? null : Chip(diff.code, 'diff-code'),
        textOr(diff.capability, '') === '' ? null : Chip(diff.capability, 'diff-capability'),
        diff.new_capability === true ? Badge(t('newCapabilityBadge'), 'warn', 'diff-new') : null,
        diff.heuristic === true ? Badge(t('heuristicBadge'), 'neutral', 'diff-heuristic') : null,
      ];
      return h(
        'div',
        { key: textOr(diff.id, 'diff-' + index), style: STYLES.diffRow },
        h('div', { style: STYLES.diffHead }, head),
        textOr(diff.summary, '') === '' ? null : h('p', { style: STYLES.diffSummary }, diff.summary),
        evidenceLabelText === ''
          ? null
          : h(
              'div',
              { style: STYLES.evidenceRow },
              h('span', { style: STYLES.captionText }, t('evidenceLabel')),
              h('code', { style: STYLES.mono }, evidenceLabelText),
              evidence.length > 1
                ? h('span', { style: STYLES.captionText }, t('evidenceMore', { count: evidence.length - 1 }))
                : null,
            ),
      );
    }

    function renderDecisionCard(t, decision) {
      const diffs = asArray(decision.diffs);
      const children = [
        renderDecisionBanner(t, decision),
        h('div', { key: 'diffs-heading', style: STYLES.subTitle }, t('diffsTitle', { count: diffs.length })),
      ];
      if (diffs.length === 0) {
        children.push(h('p', { key: 'no-diffs', style: STYLES.hint }, t('noDiffs')));
      } else {
        children.push(
          h(
            'div',
            { key: 'diffs', style: STYLES.diffList },
            diffs.map((diff, index) => renderDiff(t, diff, index)),
          ),
        );
      }
      return Card(t('decisionCardTitle'), children, 'card-decision');
    }

    function renderConfirmCard(t, review, options) {
      const decision = review.decision || {};
      const requirements = asArray(decision.confirmations_required).filter((item) => item && typeof item === 'object');
      const allChecked = requirements.every((item) => options.acked[item.code] === true);
      const expired = isExpired(review.expires_at);
      const blocked = decision.action === 'block_for_review';
      const hashPresent = hasContentHash(review);
      const canConfirm =
        !options.confirming &&
        options.handoff === null &&
        !blocked &&
        hashPresent &&
        !expired &&
        !options.stale &&
        allChecked;
      const children = [];
      if (requirements.length === 0) {
        children.push(h('p', { key: 'no-confirmations', style: STYLES.hint }, t('noConfirmations')));
      } else {
        children.push(
          h(
            'div',
            { key: 'confirmations', style: STYLES.confirmList },
            requirements.map((item, index) => {
              const code = textOr(item.code, '');
              const checked = options.acked[code] === true;
              const disabled = options.confirming || options.handoff !== null;
              return h(
                'label',
                { key: code === '' ? 'confirmation-' + index : code, style: STYLES.confirmRow },
                h('input', {
                  type: 'checkbox',
                  className: 'dsh-tb-checkbox',
                  checked,
                  disabled,
                  onChange: options.onToggleAck(code),
                  style: { cursor: disabled ? 'not-allowed' : 'pointer' },
                }),
                h(
                  'span',
                  { style: STYLES.confirmText },
                  h('span', { style: STYLES.confirmMessage }, textOr(item.message, '')),
                  h(
                    'span',
                    { style: STYLES.ackLine },
                    t('ackPhraseLabel') + ' ',
                    h('code', { style: STYLES.mono }, textOr(item.ack_token, '—')),
                  ),
                ),
              );
            }),
          ),
        );
      }
      if (options.handoff === null) {
        if (options.stale) children.push(notice('warn', '', t('staleHint'), 'stale-hint'));
        else if (expired) children.push(notice('warn', '', t('expiredHint'), 'expired-hint'));
        else if (blocked) children.push(notice('error', '', t('blockedHint'), 'blocked-hint'));
        else if (!hashPresent) children.push(notice('warn', '', t('noHashHint'), 'no-hash-hint'));
        else if (!allChecked) children.push(h('p', { key: 'ack-hint', style: STYLES.hint }, t('ackHint')));
      }
      if (options.confirmError) {
        const detail = errorText(t, options.confirmError);
        children.push(
          h(
            'div',
            { key: 'confirm-error', role: 'alert', style: STYLES.errorBox },
            h('strong', { style: STYLES.noticeTitle }, t('confirmFailedTitle')),
            h(
              'div',
              { style: STYLES.errorLine },
              Chip(detail.code, 'confirm-error-code'),
              h('span', { style: STYLES.noticeText }, detail.message),
            ),
          ),
        );
      }
      if (options.handoff === 'done') {
        const anchor = options.anchor && typeof options.anchor === 'object' ? options.anchor : null;
        const anchorLabel =
          anchor === null
            ? ''
            : t('anchorWritten') + ' ' + textOr(anchor.plugin_id, '') + (textOr(anchor.version, '') === '' ? '' : '@' + anchor.version);
        children.push(
          h(
            'div',
            { key: 'handoff-done', role: 'status', style: STYLES.successBox },
            h('p', { style: STYLES.noticeText }, t('handoffDone')),
            anchorLabel === '' ? null : h('p', { style: STYLES.hint }, anchorLabel),
          ),
        );
      } else if (options.handoff === 'anchor_only') {
        children.push(notice('warn', '', t('handoffAnchorOnly'), 'handoff-anchor-only'));
      } else {
        children.push(
          h(
            'div',
            { key: 'confirm-actions', style: STYLES.actionRow },
            h(
              'button',
              {
                type: 'button',
                className: 'dsh-tb-btn dsh-tb-btn-primary',
                style: Object.assign({}, STYLES.primaryButton, canConfirm ? {} : STYLES.buttonDisabled),
                disabled: !canConfirm,
                'aria-busy': options.confirming ? true : undefined,
                onClick: options.onConfirm,
              },
              options.confirming ? t('confirming') : t('confirmAndInstall'),
            ),
          ),
        );
      }
      return Card(t('confirmCardTitle'), children, 'card-confirm');
    }

    function renderExtras(t, decision) {
      const cards = [];
      const errors = asArray(decision.errors).filter((error) => error && typeof error === 'object');
      if (errors.length > 0) {
        cards.push(
          Card(
            t('errorsCardTitle'),
            errors.map((error, index) =>
              h(
                'div',
                { key: 'error-' + index, style: STYLES.errorRow },
                textOr(error.code, '') === '' ? null : Chip(error.code, 'error-code'),
                h('span', { style: STYLES.rowValue }, textOr(error.message, '')),
              ),
            ),
            'card-errors',
          ),
        );
      }
      const redLines = asArray(decision.red_lines).filter((line) => typeof line === 'string' && line !== '');
      if (redLines.length > 0) {
        cards.push(
          Card(
            t('redLinesCardTitle'),
            h(
              'ul',
              { style: STYLES.list },
              redLines.map((line, index) => h('li', { key: 'red-line-' + index }, line)),
            ),
            'card-red-lines',
          ),
        );
      }
      if (decision.coverage_complete === false) {
        cards.push(notice('warn', t('coverageLabel'), t('coverageIncomplete'), 'coverage'));
      } else if (decision.coverage_complete === true) {
        cards.push(h('p', { key: 'coverage-ok', style: STYLES.hint }, t('coverageComplete')));
      }
      return cards;
    }

    function renderLoading(t) {
      return h(
        'div',
        { key: 'loading', role: 'status', 'aria-live': 'polite', style: STYLES.loadingCard },
        h('p', { style: STYLES.loadingTitle }, t('reviewing')),
        h('p', { style: STYLES.hint }, t('reviewingHint')),
        h(
          'div',
          { style: STYLES.skeletonStack },
          h('span', { key: 'line-1', className: 'dsh-tb-skeleton', style: STYLES.skeletonBarMid }),
          h('span', { key: 'line-2', className: 'dsh-tb-skeleton', style: STYLES.skeletonBarWide }),
          h('span', { key: 'line-3', className: 'dsh-tb-skeleton', style: STYLES.skeletonBarShort }),
          h('span', { key: 'card-1', className: 'dsh-tb-skeleton', style: STYLES.skeletonCard }),
        ),
      );
    }

    function renderReviewError(t, info, onRetry, canRetry) {
      const detail = errorText(t, info);
      return h(
        'div',
        { key: 'review-error', role: 'alert', style: STYLES.errorBox },
        h('strong', { style: STYLES.noticeTitle }, t('reviewFailedTitle')),
        h(
          'div',
          { style: STYLES.errorLine },
          Chip(detail.code, 'review-error-code'),
          h('span', { style: STYLES.noticeText }, detail.message),
        ),
        canRetry
          ? h(
              'div',
              { style: STYLES.actionRow },
              h(
                'button',
                { type: 'button', className: 'dsh-tb-btn dsh-tb-btn-secondary', style: STYLES.secondaryButton, onClick: onRetry },
                t('retry'),
              ),
            )
          : null,
      );
    }

    function renderEmpty(t) {
      return h('p', { key: 'empty', style: STYLES.hint }, t('emptyHint'));
    }

    // ---------------------------------------------------------------------
    // The tab component. It owns every piece of state for one Plugins-page
    // tab occupant and never throws from render or from an event handler.
    // ---------------------------------------------------------------------

    function TrustBrokerTab(props) {
      const ownerProps = props && typeof props === 'object' ? props : {};
      const t = typeof ownerProps.t === 'function' ? ownerProps.t : passthroughText;
      const install = typeof ownerProps.install === 'function' ? ownerProps.install : null;

      const [spec, setSpec] = useState('');
      const [phase, setPhase] = useState('idle');
      const [review, setReview] = useState(null);
      const [reviewedSpec, setReviewedSpec] = useState('');
      const [reviewError, setReviewError] = useState(null);
      const [acked, setAcked] = useState({});
      const [confirming, setConfirming] = useState(false);
      const [confirmError, setConfirmError] = useState(null);
      const [handoff, setHandoff] = useState(null);
      const [anchor, setAnchor] = useState(null);
      const [copyState, setCopyState] = useState(null);

      const aliveRef = useRef(true);
      const reviewAbortRef = useRef(null);
      const confirmAbortRef = useRef(null);
      const confirmingRef = useRef(false);
      const seqRef = useRef(0);
      const reviewIdRef = useRef(null);
      const lastReviewSpecRef = useRef('');
      const copyTimerRef = useRef(null);

      useEffect(() => {
        aliveRef.current = true;
        return () => {
          aliveRef.current = false;
          confirmingRef.current = false;
          abortRef(reviewAbortRef);
          abortRef(confirmAbortRef);
          const timer = copyTimerRef.current;
          copyTimerRef.current = null;
          if (timer !== null) clearTimeout(timer);
        };
      }, []);

      const clearReviewState = useCallback(() => {
        reviewIdRef.current = null;
        lastReviewSpecRef.current = '';
        confirmingRef.current = false;
        setReviewedSpec('');
        setReview(null);
        setReviewError(null);
        setAcked({});
        setConfirming(false);
        setConfirmError(null);
        setHandoff(null);
        setAnchor(null);
        setCopyState(null);
      }, []);

      const runReview = useCallback((rawSpec) => {
        const trimmed = typeof rawSpec === 'string' ? rawSpec.trim() : '';
        if (trimmed === '') return;
        abortRef(reviewAbortRef);
        abortRef(confirmAbortRef);
        const controller = createAbortController();
        reviewAbortRef.current = controller;
        const seq = seqRef.current + 1;
        seqRef.current = seq;
        reviewIdRef.current = null;
        lastReviewSpecRef.current = trimmed;
        confirmingRef.current = false;
        setPhase('reviewing');
        setReviewedSpec('');
        setReview(null);
        setReviewError(null);
        setAcked({});
        setConfirming(false);
        setConfirmError(null);
        setHandoff(null);
        setAnchor(null);
        setCopyState(null);
        postJson(REVIEW_ROUTE, { spec: trimmed }, controller ? controller.signal : undefined)
          .then((payload) => {
            if (!aliveRef.current || seq !== seqRef.current) return;
            if (reviewAbortRef.current === controller) reviewAbortRef.current = null;
            const nextReview = payload && payload.review;
            if (!nextReview || typeof nextReview !== 'object') {
              setPhase('error');
              setReviewError({ code: 'invalid_response', message: '' });
              return;
            }
            reviewIdRef.current = textOr(nextReview.review_id, '');
            setReviewedSpec(trimmed);
            setReview(nextReview);
            setPhase('ready');
          })
          .catch((error) => {
            if (!aliveRef.current || seq !== seqRef.current) return;
            if (reviewAbortRef.current === controller) reviewAbortRef.current = null;
            if (isAbortError(error)) return;
            setPhase('error');
            setReviewError(toErrorInfo(error));
          });
      }, []);

      // Automatic review 700 ms after typing stops. A stale request is aborted
      // as soon as the user edits the spec again; an in-flight confirmation is
      // abandoned too, so a late anchor never installs a spec the input no
      // longer shows.
      useEffect(() => {
        const trimmed = spec.trim();
        if (trimmed === '') {
          abortRef(reviewAbortRef);
          abortRef(confirmAbortRef);
          seqRef.current += 1;
          setPhase('idle');
          clearReviewState();
          return undefined;
        }
        if (lastReviewSpecRef.current !== trimmed) {
          if (reviewAbortRef.current !== null) {
            abortRef(reviewAbortRef);
            // The aborted request never settles a review: forget it so typing
            // back to the same text starts a fresh request instead of waiting
            // for a review that no longer exists.
            lastReviewSpecRef.current = '';
          }
          if (confirmAbortRef.current !== null) {
            abortRef(confirmAbortRef);
            confirmingRef.current = false;
            setConfirming(false);
          }
        }
        const timer = setTimeout(() => {
          // A manual "Review again" (or Enter) for the same text already
          // started this review; do not pay for the same download twice.
          if (lastReviewSpecRef.current !== trimmed) runReview(trimmed);
        }, AUTO_REVIEW_DELAY_MS);
        return () => {
          clearTimeout(timer);
        };
      }, [spec, runReview, clearReviewState]);

      const trimmedSpec = spec.trim();
      const reviewing = phase === 'reviewing';
      const stale = review !== null && reviewedSpec !== trimmedSpec;
      const canReviewNow = trimmedSpec !== '' && !reviewing;

      const onSpecChange = useCallback((event) => {
        const value = event && event.target ? event.target.value : '';
        setSpec(typeof value === 'string' ? value : '');
      }, []);

      const reviewNow = useCallback(() => {
        if (phase === 'reviewing') return;
        const trimmed = spec.trim();
        if (trimmed !== '') runReview(trimmed);
      }, [phase, spec, runReview]);

      const onSpecKeyDown = useCallback(
        (event) => {
          if (event && event.key === 'Enter') {
            try {
              event.preventDefault();
            } catch (_error) {
              /* ignore */
            }
            reviewNow();
          }
        },
        [reviewNow],
      );

      const onToggleAck = useCallback(
        (code) => (event) => {
          const checked = Boolean(event && event.target && event.target.checked);
          setAcked((current) => {
            const next = Object.assign({}, current);
            next[code] = checked;
            return next;
          });
        },
        [],
      );

      const onCopyHash = useCallback(() => {
        const hash =
          review && review.decision && typeof review.decision.content_hash === 'string' ? review.decision.content_hash : '';
        if (hash === '') return;
        copyToClipboard(hash).then((ok) => {
          if (!aliveRef.current) return;
          setCopyState(ok ? 'copied' : 'failed');
          const previous = copyTimerRef.current;
          if (previous !== null) clearTimeout(previous);
          copyTimerRef.current = setTimeout(() => {
            copyTimerRef.current = null;
            if (aliveRef.current) setCopyState(null);
          }, COPY_RESET_MS);
        });
      }, [review]);

      const onConfirm = useCallback(() => {
        const currentReview = review;
        if (!currentReview || !currentReview.decision) return;
        if (confirming || confirmingRef.current || handoff !== null) return;
        const decision = currentReview.decision;
        const trimmed = spec.trim();
        const reject = (code) => {
          setConfirmError({ code, message: '' });
        };
        if (reviewedSpec !== trimmed) return reject('stale_review');
        if (isExpired(currentReview.expires_at)) return reject('expired_review');
        if (decision.action === 'block_for_review') return reject('blocked_review');
        if (!hasContentHash(currentReview)) return reject('missing_hash');
        const requirements = asArray(decision.confirmations_required).filter((item) => item && typeof item === 'object');
        const allChecked = requirements.every((item) => acked[item.code] === true);
        if (!allChecked) return undefined;
        const acknowledgements = requirements
          .map((item) => (typeof item.code === 'string' ? item.code : ''))
          .filter((code) => code !== '');
        const reviewId = textOr(currentReview.review_id, '');
        confirmingRef.current = true;
        setConfirming(true);
        setConfirmError(null);
        setHandoff(null);
        const controller = createAbortController();
        confirmAbortRef.current = controller;
        postJson(CONFIRM_ROUTE, { review_id: reviewId, acknowledgements }, controller ? controller.signal : undefined)
          .then((payload) => {
            if (!aliveRef.current) return;
            if (confirmAbortRef.current === controller) confirmAbortRef.current = null;
            confirmingRef.current = false;
            setConfirming(false);
            if (reviewIdRef.current !== reviewId) return;
            const nextAnchor = payload && payload.anchor && typeof payload.anchor === 'object' ? payload.anchor : null;
            setAnchor(nextAnchor);
            let handedOff = false;
            if (install !== null) {
              try {
                const installArgs = {
                  spec: currentReview.resolved.install_spec,
                  title: currentReview.decision.plugin.id,
                  version: currentReview.decision.plugin.version,
                };
                if (currentReview.resolved.registry) installArgs.registry = currentReview.resolved.registry;
                install(installArgs);
                handedOff = true;
              } catch (_error) {
                handedOff = false;
              }
            }
            setHandoff(handedOff ? 'done' : 'anchor_only');
          })
          .catch((error) => {
            if (!aliveRef.current) return;
            if (confirmAbortRef.current === controller) confirmAbortRef.current = null;
            confirmingRef.current = false;
            setConfirming(false);
            if (isAbortError(error)) return;
            setConfirmError(toErrorInfo(error));
          });
        return undefined;
      }, [review, reviewedSpec, spec, acked, confirming, handoff, install]);

      const children = [
        h(
          'div',
          { key: 'header', style: STYLES.header },
          h('h2', { style: STYLES.title }, t('title')),
          h('p', { style: STYLES.subtitle }, t('subtitle')),
        ),
        h(
          'div',
          { key: 'spec', style: STYLES.specSection },
          h('label', { htmlFor: 'dsh-tb-spec-input', style: STYLES.inputLabel }, t('specLabel')),
          h(
            'div',
            { style: STYLES.specRow },
            h('input', {
              id: 'dsh-tb-spec-input',
              type: 'text',
              className: 'dsh-tb-input',
              style: STYLES.input,
              value: spec,
              placeholder: t('specPlaceholder'),
              'aria-label': t('specLabel'),
              autoComplete: 'off',
              spellCheck: false,
              onChange: onSpecChange,
              onKeyDown: onSpecKeyDown,
            }),
            h(
              'button',
              {
                type: 'button',
                className: 'dsh-tb-btn dsh-tb-btn-secondary',
                style: Object.assign({}, STYLES.secondaryButton, canReviewNow ? {} : STYLES.buttonDisabled),
                disabled: !canReviewNow,
                onClick: reviewNow,
              },
              t('reviewNow'),
            ),
          ),
        ),
      ];

      if (reviewing) {
        children.push(renderLoading(t));
      } else if (phase === 'error') {
        children.push(renderReviewError(t, reviewError, reviewNow, trimmedSpec !== ''));
      } else if (review && review.decision) {
        const decision = review.decision;
        const reviewSections = [
          renderHostCodeWarning(t),
          renderSourceCard(t, decision),
          renderInstallCard(t, decision),
          renderResolvedCard(t, review, copyState, onCopyHash),
          renderDecisionCard(t, decision),
          renderConfirmCard(t, review, {
            acked,
            confirming,
            handoff,
            anchor,
            confirmError,
            stale,
            onToggleAck,
            onConfirm,
          }),
        ];
        const extras = renderExtras(t, decision);
        for (const extra of extras) reviewSections.push(extra);
        children.push(h('div', { key: 'review', style: STYLES.reviewBody }, reviewSections));
      } else {
        children.push(renderEmpty(t));
      }

      return h(
        'div',
        {
          style: STYLES.root,
          'data-plugin-tab': SLOT_ID,
          'data-trust-broker-phase': phase,
        },
        h('style', { key: 'trust-broker-styles' }, STYLE_TEXT),
        children,
      );
    }

    // ---------------------------------------------------------------------
    // Plugin entry: register dictionaries + the `plugins.tab` occupant.
    // `ctx.slots.inject` is required because `plugins.tab` is declared by the
    // Plugins page owner (a parent entry's children table), not by this plugin.
    // ---------------------------------------------------------------------

    function apply(ctx) {
      ctx.effect(
        () => ctx.locale.register(NS, { en: EN, zh: ZH }),
        'trust-broker: client dictionaries',
      );
      const t = ctx.locale.bind(NS);
      const contribute = () =>
        ctx.slots.register(
          {
            name: 'plugins.tab',
            id: SLOT_ID,
            order: 20,
            label: () => t('tab'),
            locale: NS,
          },
          TrustBrokerTab,
        );
      try {
        if (ctx.slots && typeof ctx.slots.inject === 'function') {
          ctx.slots.inject('plugins.tab', contribute);
        } else {
          contribute();
        }
      } catch (error) {
        try {
          if (typeof console !== 'undefined' && console && typeof console.warn === 'function') {
            console.warn('[trust-broker] the security review tab could not be registered:', error);
          }
        } catch (_ignored) {
          /* console is best-effort */
        }
      }
    }

    return {
      inject: ['slots', 'locale'],
      apply,
    };
  },
});
