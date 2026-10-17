import { invoke } from '@tauri-apps/api/core';
import type { WindsurfAccount, DiagnosticsResult } from '../types/windsurf';
export interface WindsurfOAuthLoginStartResponse {loginId:string; expiresIn:number; intervalSeconds:number; verificationUri:string;}
export const listWindsurfAccounts = () => invoke<WindsurfAccount[]>('list_windsurf_accounts');
export const deleteWindsurfAccount = (accountId:string) => invoke<void>('delete_windsurf_account',{accountId});
export const importWindsurfFromJson = (jsonContent:string) => invoke<WindsurfAccount[]>('import_windsurf_from_json',{jsonContent});
export const importWindsurfFromLocal = () => invoke<WindsurfAccount[]>('import_windsurf_from_local');
export const refreshWindsurfToken = (accountId:string) => invoke<WindsurfAccount>('refresh_windsurf_token',{accountId});
export const addWindsurfAccountWithToken = (githubAccessToken:string) => invoke<WindsurfAccount>('add_windsurf_account_with_token',{githubAccessToken});
export const addWindsurfAccountWithPassword = (email:string, password:string) => invoke<WindsurfAccount>('add_windsurf_account_with_password',{email,password});
export const startWindsurfOAuthLogin = () => invoke<WindsurfOAuthLoginStartResponse>('windsurf_oauth_login_start');
export const pollWindsurfOAuthLogin = (loginId:string) => invoke<WindsurfAccount|null>('windsurf_oauth_login_poll',{loginId});
export const cancelWindsurfOAuthLogin = (loginId:string) => invoke<void>('windsurf_oauth_login_cancel',{loginId});

// ---- Quota rotation monitor (read-only; execution gated server-side) ----
export type RotationMode = 'off' | 'notify_only' | 'smart_confirm' | 'auto';
export interface RotationConfig {
 mode: RotationMode;
 enabledPool: string[];
 thresholdPercent: number;
 pollIntervalSecs: number;
 snapshotMaxAgeSecs: number;
 lowConfirmGapMs: number;
 candidateMarginPoints: number;
 minSwitchIntervalSecs: number;
 cooldownSecs: number;
 maxConsecutiveFailures: number;
 sortMode: 'min_remaining_desc' | 'priority_first' | 'earliest_reset' | 'longest_idle';
 priorities: Record<string, number>;
}
export interface RotationDecision {
 kind: 'no_action' | 'warning' | 'recommendation' | 'blocked';
 reasons: string[];
 target?: { accountId: string; orgId?: string; minApplicablePercent: number; crossOrg: boolean };
 suggestionId?: string; expiresAtMs?: number; requiresConfirmation: boolean;
 resolution?: string;
}
export interface RotationStatus {
 config: RotationConfig;
 mode: RotationMode; paused: boolean; pauseReason?: string;
 thresholdPercent: number; pollIntervalSecs: number; enabledPool: string[];
 scanning: boolean; monitoringActive: boolean; consecutiveFailures: number;
 recoveredFromBackup?: boolean;
 lastScanAtMs?: number;
 lastDecision?: RotationDecision;
 snapshots: {accountId:string;orgId?:string;planName?:string;minApplicablePercent?:number;queriedAtMs:number;confidence:'verified'|'unverified_mapping';healthy:boolean;failureKind?:string}[];
}
export interface SwitchOutcome {
 targetAccountId: string; adapter?: string; restartRequired: boolean;
 localMatch: string; clientRecognized: string; remoteVerified: string; rollback: string;
 failureCode?: string; message: string;
}
export const getRotationStatus = () => invoke<RotationStatus>('get_rotation_status');
export const setRotationConfig = (config: RotationConfig) => invoke<RotationStatus>('set_rotation_config', {config});
export const scanRotationNow = () => invoke<RotationStatus>('scan_rotation_now');
export const pauseRotation = (reason?: string) => invoke<RotationStatus>('pause_rotation', {reason});
export const resumeRotation = () => invoke<RotationStatus>('resume_rotation');
export const confirmRotation = (suggestionId: string, targetAccountId: string, expectedCurrentAccountId?: string, switchMethod?: string) =>
 invoke<SwitchOutcome>('confirm_rotation', {suggestionId, targetAccountId, expectedCurrentAccountId, switchMethod});
export const dismissRotation = (suggestionId: string) => invoke<void>('dismiss_rotation', {suggestionId});
export const acknowledgeRotationRecovery = () => invoke<RotationStatus>('acknowledge_rotation_recovery');
export type NativeVerifyResult =
 | {state:'verified'; sessionLabel:string; remoteStatus?: 'passed'|'rejected'|'unavailable'}
 | {state:'pending'; sessionLabel?:string}
 | {state:'no_session'};
const nativeVerifications = new Map<string, Promise<NativeVerifyResult>>();
export const verifyNativeLogin = (targetAccountId: string) => {
 const existing = nativeVerifications.get(targetAccountId);
 if (existing) return existing;
 const request = invoke<NativeVerifyResult>('verify_native_login', {targetAccountId})
  .finally(() => { if (nativeVerifications.get(targetAccountId) === request) nativeVerifications.delete(targetAccountId); });
 nativeVerifications.set(targetAccountId, request);
 return request;
};
export const tryNativeSwitch = (accountId: string) =>
 invoke<SwitchOutcome>('try_native_switch', {accountId});
export const getSwitchCapabilities = () => invoke<{restartSwitch:string;nativeHotSwitch:string;isolatedProfileSwitch:string;autoRotation:string;notes:string[]}>('get_switch_capabilities');

// ---- 连接诊断与修复（诊断引擎只读；恢复命令各自带服务端前置校验与备份） ----
export const runConnectionDiagnostics = () => invoke<DiagnosticsResult>('run_connection_diagnostics');
export const openClientForDiagnostics = () => invoke<void>('open_client_for_diagnostics');
export interface LogExport { archivePath: string; folderPath: string; files: number; truncatedFiles: number; skippedFiles: number; }
export const exportDevinLogs = () => invoke<LogExport>('export_devin_logs');
export const openLogExportFolder = () => invoke<void>('open_log_export_folder');
export const completeRestartDevin = () => invoke<{logExport: LogExport; terminatedProcesses: number; message: string}>('complete_restart_devin', {confirmed: true});
export const getLastDiagnostics = () => invoke<DiagnosticsResult | null>('get_last_diagnostics');
export const exportDiagnosticsReport = () => invoke<string>('export_diagnostics_report');
export interface ProxyFixOutcome {
  settingsPath: string;
  newProxy: string;
  backupPath: string;
  /** 检测到旧版误写的嵌套 http.proxy 字段（未删除，仅提示）。 */
  legacyNestedProxyPresent: boolean;
  /** 写后回读核对通过。 */
  writeVerified: boolean;
  /** 本工具记录的写入状态文件（供恢复比对）。 */
  statePath: string;
}
export const applyClientProxyFix = (port: number) => invoke<ProxyFixOutcome>('apply_client_proxy_fix', { port });
/** 撤销本工具上次写入的代理修改：恢复原值（原本无值则移除键；文件由本
 *  工具创建则删回）；仅当当前值未被改动时才执行。 */
export const revertClientProxyFix = () => invoke<ProxyFixOutcome>('revert_client_proxy_fix');
export interface ProxyFixStateInfo {
  /** 本工具上次写入的 http.proxy 值。 */
  writtenValue: string;
  /** 写入前的原值；原本没有该键时为 null。 */
  previousValue: string | null;
  writtenAtMs: number;
  settingsPath: string;
  backupPath: string;
}
/** 是否存在本工具写入、尚未恢复的代理修改记录（撤销入口跨页面保留依据）。 */
export const getProxyFixState = () => invoke<ProxyFixStateInfo | null>('get_proxy_fix_state');
/** 持久化记录用户对恢复结果的人工确认（'confirmed' | 'unresolved'），纳入报告。 */
export const recordRecoveryFeedback = (verdict: 'confirmed' | 'unresolved') => invoke<void>('record_recovery_feedback', { verdict });
/** 导出前预览脱敏后的完整报告文本（不落盘）。 */
export const previewDiagnosticsReport = () => invoke<string>('preview_diagnostics_report');
export interface PacClearGuidance { performed: boolean; applicable: boolean; steps: string[]; note: string; }
export const clearStalePacConfig = () => invoke<PacClearGuidance>('clear_stale_pac_config');
export const restartDevinClient = () => invoke<string>('restart_devin_client');
