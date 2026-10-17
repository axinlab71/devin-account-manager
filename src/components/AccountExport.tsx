import { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import type { WindsurfAccount } from '../types/windsurf';

type Outcome = { path: string; count: number; format: string; shortLivedCount: number };

export function AccountExport({ accounts, privateMode, busy }: {accounts: WindsurfAccount[]; privateMode: boolean; busy: boolean}) {
 const [selected, setSelected] = useState<string[]>([]);
 const [format, setFormat] = useState('json');
 const [confirmed, setConfirmed] = useState(false);
 const [saving, setSaving] = useState(false);
 const [error, setError] = useState('');
 const [outcome, setOutcome] = useState<Outcome | null>(null);
 const lock = useRef(false);
 useEffect(() => { setSelected(previous => previous.filter(id => accounts.some(a => a.id === id))); }, [accounts]);
 function choose(ids: string[]) { setSelected(ids); setConfirmed(false); setOutcome(null); setError(''); }
 async function exportFile() {
  if (lock.current || !confirmed || !selected.length || busy) return;
  lock.current = true; setSaving(true); setError(''); setOutcome(null);
  try { setOutcome(await invoke<Outcome>('export_account_credentials', {accountIds: selected, format, confirmed: true})); }
  catch (e) { setError(String(e)); }
  finally { lock.current = false; setSaving(false); setConfirmed(false); }
 }
 return <><h2 className="preferences-section-title">导出账号与 Token</h2><div className="preferences-card">
  <div className="preferences-copy"><strong>选择账号，导出到本机文件</strong><p>JSON 适合迁移，保留账号、组织和刷新凭据；TXT 每行一个 Token，优先导出长期凭据，不保留组织信息。导出不会刷新凭据或修改官方登录状态。</p>
   <div className="row"><button disabled={saving || busy || !accounts.length} onClick={() => choose(accounts.map(a => a.id))}>全选账号</button><button disabled={saving || busy || !selected.length} onClick={() => choose([])}>清空选择</button><span className="hint">已选 {selected.length} / {accounts.length}</span></div>
   <div className="export-account-list">{accounts.map((account, index) => <label key={account.id}><input type="checkbox" disabled={saving || busy} checked={selected.includes(account.id)} onChange={event => choose(event.target.checked ? [...selected, account.id] : selected.filter(id => id !== account.id))}/><span>{privateMode ? `账号 ${index + 1}` : account.github_name || account.github_email || account.github_login}<small>{privateMode ? '信息已隐藏' : `${account.github_name ? account.github_email || account.github_login : '本地账号'} · ${account.id.slice(-8)}`}</small></span></label>)}{!accounts.length && <p>暂无可导出的账号，请先添加或导入账号。</p>}</div>
   <div className="row"><label htmlFor="credential-export-format">文件格式</label><select id="credential-export-format" disabled={saving || busy} value={format} onChange={event => { setFormat(event.target.value); setConfirmed(false); setOutcome(null); setError(''); }}><option value="json">JSON · 完整账号迁移（推荐）</option><option value="txt">TXT · 每行一个 Token</option></select></div>
   {format === 'txt' && <p className="hint">TXT 不包含组织信息，重新导入时可能需要重新确认组织；短期 Token 可能失效，无法导出的账号会使本次操作中止，不静默跳过。</p>}
   <label className="diag-check"><input type="checkbox" disabled={saving || busy} checked={confirmed} onChange={event => setConfirmed(event.target.checked)}/> 我了解导出文件含明文登录凭据，只用于本人授权账号的备份或迁移，并会妥善保管</label>
   <div className="row"><button className="primary" disabled={saving || busy || !confirmed || !selected.length} onClick={() => void exportFile()}>{saving ? '导出中…' : '确认导出文件'}</button></div>
   {error && <p className="error" role="alert">{error}</p>}
   {outcome && <div role="status"><strong>已导出 {outcome.count} 个账号（{outcome.format.toUpperCase()}）</strong><p className="preferences-directory">{outcome.path}</p>{outcome.shortLivedCount > 0 && <p className="hint">其中 {outcome.shortLivedCount} 个为短期 Token，可能过期；建议使用 JSON 迁移。</p>}<button onClick={() => void invoke('open_account_exports_folder').catch(e => setError(String(e)))}>打开账号导出目录</button><p className="hint">此文件没有加密，请勿放入日志包或公开仓库。文件内容不会显示在本页面。</p></div>}
  </div></div></>;
}
