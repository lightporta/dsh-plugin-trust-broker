/** Static identity of this bundle. Kept dependency-free; imported everywhere. */

export const TRUST_BROKER_NAME = 'dsh-plugin-trust-broker';
export const TRUST_BROKER_VERSION = '0.1.0';
export const TRUST_BROKER_LABEL_ZH = '插件信任代理';
export const TRUST_BROKER_LABEL_EN = 'Plugin trust broker';

/**
 * Fixed disclosure shown for every third-party DSH plugin. The brief requires
 * this sentence verbatim in the install-time summary, so it lives in one place.
 */
export const HOST_CODE_NOTICE_ZH =
  '该插件将作为 Host 代码运行：与 DSH 宿主同进程、拥有宿主权限；DSH 不提供插件级进程隔离。';

/** Acknowledgement tokens used by the interactive CLI and the admission gate. */
export const ACK_UNSTATED_TOKEN = '我已知悉';
export const ACK_NEW_CAPABILITY_TOKEN = '确认新增能力';
export const ACK_SUPPLY_CHAIN_TOKEN = '确认供应链差异';
export const ACK_RED_LINE_TOKEN = '确认风险红线';
export const ACK_SCAN_INCOMPLETE_TOKEN = '确认扫描不完整';
export const ACK_SOURCE_MISMATCH_TOKEN = '确认来源不一致';
