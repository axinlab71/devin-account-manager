import { invoke } from '@tauri-apps/api/core';
import type { WindsurfAccount } from '../types/windsurf';
export interface WindsurfOAuthLoginStartResponse {loginId:string; expiresIn:number; intervalSeconds:number; verificationUri:string;}
export const listWindsurfAccounts = () => invoke<WindsurfAccount[]>('list_windsurf_accounts');
export const deleteWindsurfAccount = (accountId:string) => invoke<void>('delete_windsurf_account',{accountId});
export const importWindsurfFromJson = (jsonContent:string) => invoke<WindsurfAccount[]>('import_windsurf_from_json',{jsonContent});
export const importWindsurfFromLocal = () => invoke<WindsurfAccount[]>('import_windsurf_from_local');
export const refreshWindsurfToken = (accountId:string) => invoke<WindsurfAccount>('refresh_windsurf_token',{accountId});
export const addWindsurfAccountWithToken = (githubAccessToken:string) => invoke<WindsurfAccount>('add_windsurf_account_with_token',{githubAccessToken});
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
export const confirmRotation = (suggestionId: string, targetAccountId: string, expectedCurrentAccountId?: string) =>
 invoke<SwitchOutcome>('confirm_rotation', {suggestionId, targetAccountId, expectedCurrentAccountId});
export const dismissRotation = (suggestionId: string) => invoke<void>('dismiss_rotation', {suggestionId});
export const acknowledgeRotationRecovery = () => invoke<RotationStatus>('acknowledge_rotation_recovery');
export type NativeVerifyResult =
 | {state:'verified'; sessionLabel:string}
 | {state:'pending'; sessionLabel?:string}
 | {state:'no_session'};
export const verifyNativeLogin = (targetAccountId: string) =>
 invoke<NativeVerifyResult>('verify_native_login', {targetAccountId});
export const tryNativeSwitch = (accountId: string) =>
 invoke<SwitchOutcome>('try_native_switch', {accountId});
export const getSwitchCapabilities = () => invoke<{restartSwitch:string;nativeHotSwitch:string;isolatedProfileSwitch:string;autoRotation:string;notes:string[]}>('get_switch_capabilities');
