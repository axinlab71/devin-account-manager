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
