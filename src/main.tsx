import { StrictMode, useEffect, useRef, useState, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import * as service from './services/windsurfService';
import { getWindsurfPlanBadgeClass, type WindsurfAccount } from './types/windsurf';
import { AccountQuota, accountPlan } from './components/AccountQuota';
import { SettingsPage } from './components/SettingsPage';
import { ConnectionDiagnostics } from './components/ConnectionDiagnostics';
import { RotationRecommendation } from './components/RotationRecommendation';
import { RotationSettings } from './components/RotationSettings';
import { useNativeAutoVerify } from './hooks/useNativeAutoVerify';
import type { RotationStatus } from './services/windsurfService';
import './style.css';
import './account-theme.css';

type ClientStatus = { installed: boolean; appPath: string | null; currentAccountId: string | null; dataDir: string };
type RecoveryStatus = {available:boolean;pending:boolean;createdAt:number|null;legacyCount:number};
type SwitchResult = { message: string; localVerified: boolean; backupPath: string };
type IconName = 'plus' | 'search' | 'refresh' | 'grid' | 'list' | 'settings' | 'globe' | 'key' | 'file' | 'arrow' | 'trash' | 'close' | 'shield' | 'monitor' | 'eye' | 'moon' | 'sun' | 'check' | 'user';
const paths: Record<IconName, ReactNode> = {
 plus: <path d="M12 5v14M5 12h14"/>, search: <><circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4.5 4.5"/></>,
 refresh: <><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/></>,
 grid: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
 list: <path d="M8 6h13M8 12h13M8 18h13M3 6h.1M3 12h.1M3 18h.1"/>, settings: <><path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3"/><circle cx="15" cy="17" r="3"/></>,
 globe: <><circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/></>, key: <><circle cx="8" cy="9" r="5"/><path d="m12 13 8 8m-4-4 3-3m-6 0 3-3"/></>,
 file: <><path d="M14 3H5v18h14V8Z M14 3v6h5M8 14h8M8 17h5"/></>, arrow: <path d="M4 8h15m-4-4 4 4-4 4M20 16H5m4-4-4 4 4 4"/>,
 trash: <><path d="M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7M14 10v7"/></>, close: <path d="m6 6 12 12M6 18 18 6"/>,
 shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9S4 17 4 12V6Z"/><path d="m8 12 3 3 5-6"/></>, monitor: <><rect x="3" y="3" width="18" height="13" rx="2"/><path d="M12 16v5M8 21h8"/></>,
 eye: <><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></>, moon: <path d="M20 15A9 9 0 0 1 9 4a9 9 0 1 0 11 11Z"/>, sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1 1M18 18l1 1M5 19l1-1M18 6l1-1"/></>, check: <path d="m5 12 4 4L19 6"/>, user: <><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.5-6.5 8-6.5s8 2.5 8 6.5"/></>
};
function Icon({ name, spinning = false }: { name: IconName; spinning?: boolean }) { return <svg className={spinning ? 'icon spin' : 'icon'} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>; }
function readPreference(key: string, fallback: string) { try { return localStorage.getItem(key) || fallback; } catch { return fallback; } }
function Modal({ title, children, onClose, locked = false, small = false }: {title: string; children: ReactNode; onClose: () => void; locked?: boolean; small?: boolean}) {
 const ref = useRef<HTMLElement>(null);
 const closeRef = useRef(onClose); closeRef.current = onClose;
 useEffect(() => {
  const previous = document.activeElement as HTMLElement | null;
  const oldOverflow = document.body.style.overflow; document.body.style.overflow = 'hidden';
  ref.current?.focus();
  return () => { document.body.style.overflow = oldOverflow; previous?.focus(); };
 }, []);
 return <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget && !locked) closeRef.current(); }}><section ref={ref} tabIndex={-1} className={`modal ${small ? 'small' : ''}`} role="dialog" aria-modal="true" aria-label={title} onKeyDown={e => {
  if (e.key === 'Escape' && !locked) { e.stopPropagation(); closeRef.current(); }
  if (e.key === 'Tab') {
   const elements = Array.from(ref.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), summary, a[href]') || []);
   const first = elements[0], last = elements[elements.length - 1];
   if (!first) { e.preventDefault(); return; }
   if (e.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) { e.preventDefault(); last.focus(); }
   else if (!e.shiftKey && (document.activeElement === last || document.activeElement === ref.current)) { e.preventDefault(); first.focus(); }
  }
 }}><div className="modal-heading"><div><span className="eyebrow">DEVIN ACCOUNT MANAGER</span><h2>{title}</h2></div><button className="icon-button" disabled={locked} aria-label="关闭弹窗" onClick={onClose}><Icon name="close"/></button></div>{children}</section></div>;
}
function formatTime(value: number) { return value > 0 ? new Date(value * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '暂无切换记录'; }
function App() {
 const [accounts, setAccounts] = useState<WindsurfAccount[]>([]);
 const [client, setClient] = useState<ClientStatus>();
 const [busy, setBusy] = useState(false);
 const operation = useRef(false);
 const browserFlow = useRef<{cancelled:boolean; loginId?:string} | undefined>(undefined);
 const [browserWaiting,setBrowserWaiting] = useState(false);
 const [browserStage,setBrowserStage] = useState('waiting');
 const [recovery,setRecovery] = useState<RecoveryStatus>();
 const [recoveryConfirm,setRecoveryConfirm] = useState<'restore'|'cleanup'>();
 const [notice, setNotice] = useState('');
 const [error, setError] = useState('');
 useEffect(() => { if (!notice || browserWaiting || busy) return; const timer = setTimeout(() => setNotice(''), 4500); return () => clearTimeout(timer); }, [notice, browserWaiting, busy]);
 const [adding, setAdding] = useState(false);
 const [mode, setMode] = useState<'official' | 'password' | 'credentials' | 'migration'>('official');
 const [input, setInput] = useState('');
 const [pwEmail, setPwEmail] = useState('');
 const [pwPass, setPwPass] = useState('');
 const [path, setPath] = useState('');
 const [settings, setSettings] = useState(false);
 const [cockpitPath, setCockpitPath] = useState('');
 const [migrationResult, setMigrationResult] = useState('');
 const [deleting, setDeleting] = useState<string>();
 const [health, setHealth] = useState<Record<string, string>>({});
 const [query, setQuery] = useState('');
 const [filter, setFilter] = useState('all');
 const [sort, setSort] = useState('recent');
 const [view, setView] = useState(() => readPreference('devin.view', 'grid'));
 const [privateMode, setPrivateMode] = useState(() => readPreference('devin.privacy', 'false') === 'true');
 const [reducedMotion, setReducedMotion] = useState(() => readPreference('devin.reducedMotion', 'false') === 'true');
 useEffect(() => { document.documentElement.dataset.reducedMotion = String(reducedMotion); try { localStorage.setItem('devin.reducedMotion', String(reducedMotion)); } catch {} }, [reducedMotion]);
 const [theme, setTheme] = useState(() => readPreference('devin.theme', 'dark'));
 const [switchMethod, setSwitchMethod] = useState(() => readPreference('devin.switchMethod', 'standard') === 'native' ? 'native' : 'standard');
 const [activeId, setActiveId] = useState<string>();
 const [initialLoading, setInitialLoading] = useState(true);
 const [loadError, setLoadError] = useState('');
 const [clientWarning, setClientWarning] = useState('');
 const [bulkProgress, setBulkProgress] = useState<{done:number;total:number} | null>(null);
 const bulkCancelled = useRef(false);
 const [rotation, setRotation] = useState<RotationStatus>();
 useEffect(() => {
  let unlisten: (() => void) | undefined;
  import('@tauri-apps/api/event')
   .then(m => m.listen<RotationStatus>('rotation-status', e => {
    setRotation(e.payload);
    if (e.payload.lastDecision?.resolution === 'verified') void load().catch(() => {});
   }).then(f => { unlisten = f; }))
   .catch(() => {});
  return () => unlisten?.();
 }, []);
 useEffect(() => { document.documentElement.dataset.theme = theme; try { localStorage.setItem('devin.theme', theme); localStorage.setItem('devin.view', view); localStorage.setItem('devin.privacy', String(privateMode)); localStorage.setItem('devin.switchMethod', switchMethod); } catch {} }, [theme, view, privateMode, switchMethod]);
  const load = async () => {
    const [list, status, recoveryState, rotationState] = await Promise.allSettled([service.listWindsurfAccounts(), invoke<ClientStatus>('get_client_status'), invoke<RecoveryStatus>('get_recovery_status'), service.getRotationStatus()]);
    setRecovery(recoveryState.status === 'fulfilled' ? recoveryState.value : undefined);
    if (rotationState.status === 'fulfilled') setRotation(rotationState.value);
    if (list.status === 'fulfilled') { setAccounts(list.value); setLoadError(''); }
    else { setLoadError('无法读取本地账号，请重试或检查数据目录权限。'); }
    if (status.status === 'fulfilled') { setClient(status.value); setClientWarning(''); }
    else { setClient(undefined); setClientWarning('客户端状态读取失败，暂时无法切换。可以继续管理账号，在设置中重新检测。'); }
    if (list.status === 'rejected') throw new Error('无法读取本地账号数据，请检查目录权限后重试。');
  };
  useEffect(() => { void load().catch(() => {}).finally(() => setInitialLoading(false)); }, []);
  const run = async (fn: () => Promise<string | void>) => {
    if (operation.current) return;
    operation.current = true; setBusy(true); setError(''); setNotice('');
    try { const message = await fn(); if (message) setNotice(message); await load(); }
    catch (e) { setError(String(e)); await load().catch(() => {}); }
    finally { operation.current = false; setBusy(false); }
  };
  const refresh = (account: WindsurfAccount) => run(async () => {
    setActiveId(account.id);
    try {
      const updated = await service.refreshWindsurfToken(account.id);
      const failure = updated.quota_query_last_error;
      setHealth(h => ({ ...h, [account.id]: failure ? '额度查询异常' : '刷新完成' }));
      return failure ? '凭据刷新完成，但额度查询未成功；已保留上次数据，可稍后重试。' : '账号刷新完成。';
    } catch (e) { setHealth(h => ({ ...h, [account.id]: '刷新失败' })); throw e; }
    finally { setActiveId(undefined); }
  });
  const importInput = () => run(async () => {
    const value = input.trim().replace(/^\uFEFF/, '');
    if (/^[{\[]/.test(value)) await service.importWindsurfFromJson(value);
    else await service.addWindsurfAccountWithToken(value);
    setInput(''); setAdding(false); return '账号已保存到本机。';
  });
  const startBrowser = () => run(async () => {
    const flow: {cancelled:boolean;loginId?:string}={cancelled:false};
    browserFlow.current=flow;setBrowserWaiting(true);setBrowserStage('waiting');
    let progressTimer:ReturnType<typeof setInterval>|undefined;
    try {
      const session=await service.startWindsurfOAuthLogin();flow.loginId=session.loginId;
      progressTimer=setInterval(()=>{if(!flow.cancelled)void invoke<string>('get_oauth_login_phase',{loginId:session.loginId}).then(phase=>{if(browserFlow.current===flow)setBrowserStage(phase);}).catch(()=>{});},700);
      setNotice('浏览器已打开。请登录目标账号，授权完成后凭据将自动保存，无需打开 Devin 客户端。');
      const deadline=Date.now()+session.expiresIn*1000;
      while (!flow.cancelled && Date.now()<deadline) {
        let account: WindsurfAccount | null;
        try { account=await service.pollWindsurfOAuthLogin(session.loginId); }
        catch(e) { if(flow.cancelled)break; throw e; }
        if (flow.cancelled) break;
        if (account) {setAdding(false);return '网页授权已处理，账号已保存；请在客户端确认实际登录。';}
        await new Promise(resolve=>setTimeout(resolve,2000));
      }
      if (!flow.cancelled) throw new Error('网页授权超时，请重新发起授权并在浏览器完成登录。');
      return '已取消网页授权等待。';
    } finally {
      if(progressTimer)clearInterval(progressTimer);
      if (flow.loginId) await service.cancelWindsurfOAuthLogin(flow.loginId).catch(()=>{});
      setBrowserWaiting(false);if(browserFlow.current===flow)browserFlow.current=undefined;
    }
  });
  const cancelBrowser=async()=>{
    const flow=browserFlow.current;if(!flow)return;flow.cancelled=true;setBrowserStage('cancelled');
    if(flow.loginId)await service.cancelWindsurfOAuthLogin(flow.loginId).catch(()=>{});
  };
  const addAccount = () => { setAdding(true); setMode('official'); setInput(''); setPwEmail(''); setPwPass(''); setError(''); };
  const closeAdd = () => { setAdding(false); setInput(''); setPwEmail(''); setPwPass(''); };
  const identity = (a: WindsurfAccount) => privateMode ? `账号 ${accounts.findIndex(x => x.id === a.id) + 1}` : a.github_name || a.github_login || 'Devin 账号';
  const email = (a: WindsurfAccount) => privateMode ? '••••••@••••••' : a.github_email || a.github_login;
  const needsAttention = (a: WindsurfAccount) => Boolean(a.quota_query_last_error || (a.copilot_expires_at && a.copilot_expires_at * 1000 < Date.now()) || health[a.id]?.includes('失败') || health[a.id]?.includes('错误'));
  const visible = accounts.filter(a => {
    const matches = `${a.github_name || ''} ${a.github_email || ''} ${a.github_login} ${(a.tags || []).join(' ')}`.toLowerCase().includes(query.trim().toLowerCase());
    return matches && (filter === 'all' || (filter === 'current' ? a.id === client?.currentAccountId : needsAttention(a)));
  }).sort((a, b) => {
    const current = Number(b.id === client?.currentAccountId) - Number(a.id === client?.currentAccountId);
    return current || (sort === 'name' ? identity(a).localeCompare(identity(b), 'zh-CN') : sort === 'created' ? b.created_at - a.created_at : (b.last_switched_at || 0) - (a.last_switched_at || 0) || b.created_at - a.created_at);
  });
  const currentAccount = accounts.find(a => a.id === client?.currentAccountId);
  const deletingAccount = accounts.find(a => a.id === deleting);
  const refreshAll = () => run(async () => {
    let success = 0, failed = 0;
    bulkCancelled.current = false;
    setBulkProgress({done:0,total:accounts.length});
    try {
      for (const a of accounts) {
        if (bulkCancelled.current) break;
        setActiveId(a.id);
        try {
          const updated = await service.refreshWindsurfToken(a.id);
          setAccounts(previous => previous.map(item => item.id === updated.id ? updated : item));
          if (updated.quota_query_last_error) { failed++; setHealth(h => ({...h,[a.id]:'额度查询失败'})); }
          else { success++; setHealth(h => ({...h,[a.id]:'已同步'})); }
        } catch { failed++; setHealth(h => ({...h,[a.id]:'刷新失败'})); }
        setBulkProgress({done:success+failed,total:accounts.length});
      }
      return `${bulkCancelled.current ? '已停止后续刷新' : '刷新结束'}：${success} 个完成${failed ? `，${failed} 个需检查，可在对应账号上单独重试` : ''}。`;
    } finally { setActiveId(undefined); setBulkProgress(null); }
  });
  const switchAccount = (a: WindsurfAccount) => run(async () => {
    setActiveId(a.id);
    try { return (await invoke<SwitchResult>('inject_windsurf_to_vscode', { accountId: a.id })).message; }
    finally { setActiveId(undefined); }
  });
  const [nativeSwitch, setNativeSwitch] = useState<{account: WindsurfAccount; outcome?: service.SwitchOutcome; verify?: service.NativeVerifyResult; busy?: boolean; blockedBy?: {suggestionId: string; targetId: string}} | null>(null);
  const nativeRequest = useRef(false);
  useNativeAutoVerify(nativeSwitch?.outcome ? nativeSwitch.account.id : undefined,
    nativeSwitch?.blockedBy?.targetId ?? nativeSwitch?.account.id,
    !!nativeSwitch?.outcome && (!nativeSwitch.outcome.failureCode || nativeSwitch.outcome.failureCode === 'uri_delivery_unconfirmed') && (nativeSwitch.verify?.state !== 'verified' || nativeSwitch.verify.remoteStatus === 'unavailable'),
    verify => {
      if (verify.state === 'verified' && verify.remoteStatus === 'passed') {
        setNativeSwitch(null);
        setNotice('账号切换已核对，服务端已接受当前会话。');
        void load().catch(() => {});
      } else setNativeSwitch(prev => prev ? {...prev, verify} : prev);
    });
  const nativeLaunch = async (account: WindsurfAccount) => {
    if (nativeRequest.current) return;
    nativeRequest.current = true;
    const ns = {account};
    setNativeSwitch({...ns, busy: true});
    try { const outcome = await service.tryNativeSwitch(ns.account.id); setNativeSwitch(prev => prev?.account.id === ns.account.id ? {account: ns.account, outcome} : prev); }
    catch (e) {
      // A stale in-flight record (awaiting_client) blocks the launch before
      // any URI is sent — surface it so the user can verify or abandon it
      // from this modal instead of hunting for the banner behind it.
      const s = await service.getRotationStatus().catch(() => undefined);
      if (s) setRotation(s);
      const d = s?.lastDecision;
      const blockedBy = d?.suggestionId && d.target && (d.resolution === 'awaiting_client' || d.resolution === 'executing')
        ? {suggestionId: d.suggestionId, targetId: d.target.accountId} : undefined;
      setNativeSwitch(prev => prev?.account.id === ns.account.id ? {account: ns.account, blockedBy, outcome: {targetAccountId: ns.account.id, restartRequired: false, localMatch: 'not_attempted', clientRecognized: 'not_attempted', remoteVerified: 'not_attempted', rollback: 'not_attempted', failureCode: 'invoke_failed', message: String(e)}} : prev);
    } finally { nativeRequest.current = false; }
  };
  const nativeCheck = async () => {
    const ns = nativeSwitch; if (!ns || ns.busy) return;
    setNativeSwitch({...ns, busy: true});
    // Verify against the in-flight record's target when this launch was
    // blocked by a previous request — that is the account Devin may hold.
    const targetId = ns.blockedBy?.targetId ?? ns.account.id;
    try {
      const verify = await service.verifyNativeLogin(targetId);
      if (verify.state === 'verified' && verify.remoteStatus === 'passed') {
        setNativeSwitch(null); setNotice('账号切换已核对，服务端已接受当前会话。');
        await load();
      } else setNativeSwitch(prev => prev?.account.id === ns.account.id ? {...prev, verify, busy: false} : prev);
      await service.getRotationStatus().then(setRotation).catch(() => {});
    }
    catch (e) { setNativeSwitch(prev => prev?.account.id === ns.account.id ? {...prev, verify: {state: 'pending', sessionLabel: String(e)}, busy: false} : prev); }
  };
  const nativeAbandon = async () => {
    const ns = nativeSwitch; if (!ns || ns.busy || !ns.blockedBy) return;
    setNativeSwitch({...ns, busy: true});
    try {
      await service.dismissRotation(ns.blockedBy.suggestionId);
      await service.getRotationStatus().then(setRotation).catch(() => {});
      // This explicit "abandon and retry" click authorizes one fresh attempt.
      await nativeLaunch(ns.account);
    } catch { setNativeSwitch(prev => prev ? {...prev, busy: false} : prev); }
  };
  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><img className="mark" src="/devin.png" alt=""/><div><strong>Devin 账户管理器</strong><span className="brand-caption">ACCOUNT MANAGER</span></div></div>
      <div className="nav-label">工作空间</div><button className={`nav-item ${!settings ? 'active' : ''}`} onClick={() => setSettings(false)}><Icon name="grid"/>账号管理<span className="nav-count">{accounts.length}</span></button><button className={`nav-item settings-nav ${settings ? 'active' : ''}`} disabled={busy} onClick={() => { setPath(client?.appPath || ''); setSettings(true); }}><Icon name="settings"/>应用设置</button>

    </aside>
    <main>    <div className="toast-stack" aria-live="polite">{busy && !browserWaiting && <div className="toast" role="status"><Icon name="refresh" spinning/>{bulkProgress ? `正在刷新 ${bulkProgress.done} / ${bulkProgress.total}` : '正在处理，请稍候…'}{bulkProgress && <button disabled={bulkCancelled.current} onClick={() => { bulkCancelled.current = true; setBulkProgress(p => p ? {...p} : p); }}>停止后续刷新</button>}</div>}{notice && !browserWaiting && !busy && <div className="toast success" role="status"><Icon name="check"/><span>{notice}</span><button className="icon-button" aria-label="关闭提示" onClick={() => setNotice('')}><Icon name="close"/></button></div>}{error && !adding && !settings && <div className="toast error" role="alert"><span>{error}</span><button className="icon-button" aria-label="关闭错误提示" onClick={() => setError('')}><Icon name="close"/></button></div>}</div>
    {recovery?.pending && !recoveryConfirm && <div className="client-warning" role="status">检测到上一次切换未完成，加密恢复点仍保留。请先确认客户端状态。<button disabled={busy} onClick={() => setRecoveryConfirm('restore')}>查看恢复操作</button></div>}
    {settings ? <SettingsPage client={client} currentAccount={currentAccount ? identity(currentAccount) : undefined} busy={busy} error={error} path={path} onPath={setPath} onDetect={() => void run(async () => { await load(); return '已重新读取客户端状态。'; })} onSave={() => void run(async () => { await invoke('set_client_path', {path:path.trim()}); return '客户端路径已保存。'; })} theme={theme} onTheme={setTheme} privateMode={privateMode} onPrivacy={value => { if (value) setQuery(''); setPrivateMode(value); }} view={view} onView={setView} reducedMotion={reducedMotion} onReducedMotion={setReducedMotion} onMigrate={() => { addAccount(); setMode('migration'); }} recovery={recovery} onRestore={() => setRecoveryConfirm('restore')} onCleanup={() => setRecoveryConfirm('cleanup')} switchMethod={switchMethod} onSwitchMethod={setSwitchMethod} rotation={<RotationSettings status={rotation} accounts={accounts} busy={busy} onSave={async c => { const s = await service.setRotationConfig(c); setRotation(s); return s; }} onScan={async () => { const s = await service.scanRotationNow(); setRotation(s); return s; }} onPause={async () => { const s = await service.pauseRotation('user'); setRotation(s); return s; }} onResume={async () => { const s = await service.resumeRotation(); setRotation(s); return s; }}/>} diagnostics={<ConnectionDiagnostics/>}/> : <><header className="page-heading"><div><span className="eyebrow">工作空间 / DEVIN</span><h1>账户管理器</h1><p>查看使用额度，管理和切换 Devin 账户。</p></div><div className="row"><button className={`icon-button ${privateMode ? 'selected' : ''}`} aria-label={privateMode ? '显示账号信息' : '隐藏账号信息'} aria-pressed={privateMode} title="隐私显示" onClick={() => { if (!privateMode) setQuery(''); setPrivateMode(!privateMode); }}><Icon name="eye"/></button><button className="primary" disabled={busy} onClick={addAccount}><Icon name="plus"/>添加账号</button></div></header>

    {clientWarning && <div className="client-warning" role="status">{clientWarning}<button disabled={busy} onClick={() => { setPath(''); setSettings(true); }}>应用设置</button></div>}
    <RotationRecommendation status={rotation} accountName={id => { const a = accounts.find(x => x.id === id); return a ? identity(a) : id; }} currentAccountId={client?.currentAccountId ?? undefined} busy={busy} switchMethod={switchMethod} onConfirm={async (sid, tid) => { const outcome = await service.confirmRotation(sid, tid, client?.currentAccountId ?? undefined, switchMethod); await service.getRotationStatus().then(setRotation).catch(() => {}); return outcome; }} onDismiss={async sid => { await service.dismissRotation(sid); await service.getRotationStatus().then(setRotation).catch(() => {}); }} onAcknowledgeRecovery={async () => { await service.acknowledgeRotationRecovery().then(setRotation).catch(() => {}); }}/>
    <section className="account-section"><div className="section-heading"><div><h2>全部账户 <span>{visible.length}{visible.length !== accounts.length ? ` / ${accounts.length}` : ''}</span></h2><p>当前账号置顶 · 切号方式：{switchMethod === 'native' ? '免重启（实验性）——主按钮走官方确认流程，需在 Devin 中确认' : '标准切号（重启）——「切换账号」走保存后重启的标准流程'}</p></div><button disabled={busy || accounts.length === 0} onClick={() => void refreshAll()}><Icon name="refresh" spinning={busy && !!activeId}/>刷新全部</button></div>
      <div className="toolbar"><div className="search-field"><Icon name="search"/><input aria-label="搜索账号" value={query} onChange={e => setQuery(e.target.value)} placeholder="搜索名称、邮箱或标签…"/>{query && <button className="icon-button" aria-label="清空搜索" onClick={() => setQuery('')}><Icon name="close"/></button>}</div><select aria-label="筛选账号" value={filter} onChange={e => setFilter(e.target.value)}><option value="all">全部账号</option><option value="current">当前账号</option><option value="attention">需要检查</option></select><select aria-label="账号排序" value={sort} onChange={e => setSort(e.target.value)}><option value="recent">最近切换</option><option value="created">最近添加</option><option value="name">名称排序</option></select><div className="view-toggle" aria-label="显示方式"><button className={view === 'grid' ? 'selected icon-button' : 'icon-button'} aria-label="网格视图" aria-pressed={view === 'grid'} onClick={() => setView('grid')}><Icon name="grid"/></button><button className={view === 'list' ? 'selected icon-button' : 'icon-button'} aria-label="列表视图" aria-pressed={view === 'list'} onClick={() => setView('list')}><Icon name="list"/></button></div></div>
      {initialLoading ? <section className="empty" role="status"><Icon name="refresh" spinning/><h3>正在读取本地账号</h3></section> : loadError && accounts.length === 0 ? <section className="empty" role="alert"><h3>账号读取失败</h3><p>{loadError}</p><button disabled={busy} onClick={() => void run(async () => { await load(); })}>重新读取</button></section> : accounts.length === 0 ? <section className="empty"><span className="empty-icon"><Icon name="plus"/></span><h3>从第一个账号开始</h3><p>在浏览器完成授权，账号将自动保存到这里。<br/>也可以导入已有的 Token 或 JSON。</p><button className="primary" disabled={busy} onClick={addAccount}><Icon name="globe"/>网页授权添加</button><small>支持多账号 · 本地加密存储</small></section> : visible.length === 0 ? <section className="empty compact"><Icon name="search"/><h3>没有找到匹配的账号</h3><p>试试其他关键词，或清除筛选条件。</p><button onClick={() => { setQuery(''); setFilter('all'); }}>清除筛选</button></section> : <section className={`accounts ${view}`} aria-label="账号列表">{visible.map(a => {
       const current = client?.currentAccountId === a.id;
       const attention = needsAttention(a);
       return <article key={a.id} title={`凭据状态：${a.credential_state === 'expired' ? '可能过期' : '尚未验证客户端连接'}；最近切换：${formatTime(a.last_switched_at || 0)}`} className={`account ${current ? 'current' : ''}`}><div className="card-identity"><div className="avatar">{privateMode ? 'D' : identity(a).slice(0, 1).toUpperCase()}</div><div className="account-info"><div className="name" title={identity(a)}>{identity(a)}</div><p title={email(a)}>{email(a)}</p></div></div><div className="card-meta"><span className={`plan-badge plan-${getWindsurfPlanBadgeClass(accountPlan(a))}`}>{accountPlan(a)}</span>{attention && <span className="health warning"><span className="dot"/>{a.credential_state === 'expired' ? '凭据可能过期' : health[a.id] || (a.quota_query_last_error ? '额度异常' : '登录待检查')}</span>}{current && <span className="badge" title="根据客户端本地保存的登录态匹配，尚未验证服务连接"><span className="dot online"/>当前</span>}{!current && a.native_switch_credential_ready === false && <span className="health warning" title="此账号缺少官方 URI 登录所需凭据（devin-session 或一次性令牌），无法使用免重启切换；标准切号不受影响"><span className="dot"/>暂不支持免重启</span>}</div>{a.tags && a.tags.length > 0 && <div className="tags">{a.tags.map(t => <span key={t}>{privateMode ? '标签' : t}</span>)}</div>}<AccountQuota account={a} refreshFailed={Boolean(health[a.id]?.includes('失败') || health[a.id]?.includes('错误'))}/><div className="last-used" title="最近成功写入并启动客户端的时间">最近切换 <span>{formatTime(a.last_switched_at || 0)}</span></div><div className="card-actions"><button className="icon-button" aria-label={`刷新 ${identity(a)}`} title="刷新登录态" disabled={busy} onClick={() => void refresh(a)}><Icon name="refresh" spinning={busy && activeId === a.id}/></button><button className="icon-button danger" aria-label={`删除 ${identity(a)}`} title="删除账号" disabled={busy} onClick={() => setDeleting(a.id)}><Icon name="trash"/></button>{!current && switchMethod === 'native' && <button className={a.native_switch_credential_ready === false ? 'switch-button' : 'primary switch-button'} disabled={busy || !client?.installed || a.native_switch_credential_ready === false} title={a.native_switch_credential_ready === false ? '此账号暂不支持免重启：缺少官方 URI 登录所需凭据，请使用「切换账号」（重启）' : '当前切号方式：免重启（实验性）。尝试不关闭 IDE 窗口切换，需要在 Devin 中确认'} onClick={() => void nativeLaunch(a)}>免重启切换</button>}<button className={current || (switchMethod === 'native' && a.native_switch_credential_ready !== false) ? 'switch-button' : 'primary switch-button'} disabled={busy || !client?.installed} title={client?.installed ? (switchMethod === 'native' && !current ? '标准切号：保存工作后切换，客户端会自动重启' : '保存工作后切换，客户端会自动重启') : '请先配置客户端路径'} onClick={() => void switchAccount(a)}><Icon name="arrow" spinning={busy && activeId === a.id}/>{busy && activeId === a.id ? '处理中' : current ? '重新应用' : switchMethod === 'native' ? '标准切号' : '切换账号'}</button>{!current && switchMethod !== 'native' && <button className="switch-button native" disabled={busy || !client?.installed || a.native_switch_credential_ready === false} title={a.native_switch_credential_ready === false ? '此账号暂不支持免重启：缺少官方 URI 登录所需凭据，请使用「切换账号」（重启）' : '实验性：尝试不关闭 IDE 窗口切换，需要在 Devin 中确认'} onClick={() => void nativeLaunch(a)}>免重启</button>}</div></article>;
      })}</section>}
    </section></>}
    </main>
    {recoveryConfirm && <Modal title={recoveryConfirm === 'restore' ? '恢复上一次切换前的状态？' : '清理旧版明文备份？'} small onClose={() => setRecoveryConfirm(undefined)} locked={busy}><p>{recoveryConfirm === 'restore' ? '将正常关闭客户端并恢复上一次切换前的完整数据库，覆盖此后的客户端状态。请先保存工作。恢复时会检查备份完整性与客户端加密密钥。' : `将删除 ${recovery?.legacyCount || 0} 份旧版明文数据库备份，保留当前加密恢复点。删除前会再次验证加密恢复点可读。`}</p><div className="modal-footer"><button disabled={busy} onClick={() => setRecoveryConfirm(undefined)}>取消</button><button className="primary" disabled={busy} onClick={() => void run(async () => { const message = recoveryConfirm === 'restore' ? await invoke<string>('restore_last_client_state') : `已清理 ${await invoke<number>('cleanup_legacy_client_backups')} 份旧版备份。`;setRecoveryConfirm(undefined);return message; })}>{recoveryConfirm === 'restore' ? '确认恢复' : '确认清理'}</button></div>{error && <p className="error notice" role="alert">{error}</p>}</Modal>}
    {adding && <Modal title="添加 Devin 账号" onClose={closeAdd} locked={busy}><p className="modal-subtitle">通过网页授权，或导入已有账号凭据。</p><div className="tabs" role="tablist" aria-label="添加方式">{(['official', 'password', 'credentials', 'migration'] as const).map(m => <button key={m} id={`tab-${m}`} role="tab" aria-selected={mode === m} aria-controls="import-panel" disabled={busy} className={mode === m ? 'selected' : ''} onClick={() => { setMode(m); setInput(''); }}><Icon name={m === 'official' ? 'globe' : m === 'password' ? 'user' : m === 'credentials' ? 'key' : 'file'}/>{m === 'official' ? '网页授权' : m === 'password' ? '邮箱密码' : m === 'credentials' ? 'Token / JSON' : '本地迁移'}</button>)}</div><div id="import-panel" role="tabpanel" aria-labelledby={`tab-${mode}`}>
      {mode === 'official' ? <><div className={`auth-hero ${browserWaiting ? 'waiting' : ''}`}><span className="auth-icon"><Icon name={browserWaiting ? 'refresh' : 'globe'} spinning={browserWaiting}/></span><h3>{browserWaiting ? browserStage === 'cancelled' ? '正在取消，请等待当前请求结束' : browserStage === 'saving' ? '正在保存账号' : ['verifying','callback_received'].includes(browserStage) ? '已收到授权，正在处理凭据' : '等待浏览器授权' : '在浏览器安全登录'}</h3><p>{browserWaiting ? `请在已打开的浏览器中完成登录。
收到授权后，我们会验证凭据并自动保存账号。` : `使用系统浏览器登录 Devin，授权完成后将自动安全保存。
无需先打开 Devin Desktop。`}</p></div><div className="steps"><span><b>1</b>打开浏览器</span><i/><span><b>2</b>完成登录</span><i/><span><b>3</b>自动保存</span></div><button className="primary full-width" disabled={busy} onClick={() => void startBrowser()}><Icon name="globe"/>{browserWaiting ? '正在等待授权…' : '开始网页授权'}</button>{browserWaiting && <button className="full-width cancel-auth" onClick={() => void cancelBrowser()}>取消本次授权</button>}<div className="local-import"><span>已经在官方客户端登录？</span><button className="text-button" disabled={busy} onClick={() => void run(async () => { await service.importWindsurfFromLocal(); setAdding(false); return '已导入官方客户端当前账号。'; })}>导入本机账号 →</button></div></> : mode === 'credentials' ? <><label htmlFor="credentials">Token / JSON 凭据</label><p className="hint">自动识别 Token、单个账号 JSON 或账号数组，兼容 Cockpit Tools 导出的账号文件。</p><textarea id="credentials" spellCheck={false} autoComplete="off" value={input} onChange={e => setInput(e.target.value)} placeholder="粘贴 Token 或 JSON 账号数据…"/><label className="file-picker">从文件读取<input type="file" accept=".json,.txt,application/json,text/plain" disabled={busy} aria-label="读取导入文件" onChange={e => { const f = e.target.files?.[0]; if (f) { if (f.size > 5 * 1024 * 1024) { setError('文件不能超过 5 MB'); return; } void f.text().then(setInput).catch(() => setError('无法读取文件')); } }}/></label><button className="primary full-width" disabled={busy || !input.trim()} onClick={() => void importInput()}>{busy ? '正在导入…' : '导入并保存'}</button></> : mode === 'password' ? <><label htmlFor="pw-email">邮箱</label><input id="pw-email" type="email" autoComplete="username" spellCheck={false} value={pwEmail} onChange={e => setPwEmail(e.target.value)} placeholder="name@example.com"/><label htmlFor="pw-password">密码</label><input id="pw-password" type="password" autoComplete="current-password" value={pwPass} onChange={e => setPwPass(e.target.value)} placeholder="账号密码"/><p className="hint">使用官方账号密码登录，凭据只发往官方服务并保存在本机。Devin 账号会完整保存会话凭据，同时满足免重启切换（实验性）的凭据条件；未开启密码登录的账号请改用网页授权。</p><button className="primary full-width" disabled={busy || !pwEmail.trim() || !pwPass} onClick={() => void run(async () => { await service.addWindsurfAccountWithPassword(pwEmail.trim(), pwPass); setPwEmail(''); setPwPass(''); setAdding(false); return '账号已保存到本机。'; })}>{busy ? '正在登录…' : '登录并保存'}</button></> : <div className="migration-panel"><section><h3>官方客户端当前账号</h3><p className="hint">读取已登录的 Devin Desktop，本次只导入当前账号。</p><button disabled={busy} onClick={() => void run(async () => { await service.importWindsurfFromLocal(); setAdding(false); return '已导入官方客户端当前账号。'; })}>导入本机账号</button></section><section><h3>从 Cockpit Tools 迁移</h3><p className="hint">只读导入 Windsurf / Devin 账号，保留原数据；重复账号跳过。加密账号需要原目录密钥，并在原 Windows 用户下操作。</p><label htmlFor="cockpit-path">Cockpit 数据目录（留空自动检测）</label><input id="cockpit-path" value={cockpitPath} onChange={e => setCockpitPath(e.target.value)} placeholder="包含 windsurf_accounts 的数据目录"/><button className="primary" disabled={busy} onClick={() => void run(async () => { const r = await invoke<{imported:number;skipped:number;failed:number}>('import_cockpit_accounts', {sourcePath:cockpitPath.trim() || null}); const message = `迁移完成：导入 ${r.imported}，跳过 ${r.skipped}，失败 ${r.failed}${r.failed ? '。请检查原密钥，或使用 Cockpit 导出的 JSON' : '。'}`; setMigrationResult(message); return message; })}>导入 Cockpit 账号</button>{migrationResult && <p className="migration-result" role="status">{migrationResult}</p>}</section><p className="hint">也可在 Cockpit 导出账号文件，切换到「Token / JSON」导入。</p></div>}

      </div><p className="privacy-note"><Icon name="shield"/>凭据仅保存在本机，请勿将账号文件发给他人。</p>{error && <p className="error notice" role="alert">{error}</p>}</Modal>}
    {deleting && <Modal title="删除这个账号？" small onClose={() => setDeleting(undefined)} locked={busy}><p>将从本机账号列表中移除 <strong>{deletingAccount ? identity(deletingAccount) : '该账号'}</strong>，客户端当前登录态不会被注销。</p><div className="modal-footer"><button disabled={busy} onClick={() => setDeleting(undefined)}>保留账号</button><button className="danger danger-solid" disabled={busy} onClick={() => void run(async () => { await service.deleteWindsurfAccount(deleting); setDeleting(undefined); return '已删除保存的账号。'; })}>确认删除</button></div>{error && <p className="error notice" role="alert">{error}</p>}</Modal>}
    {nativeSwitch && <Modal title="免重启切换（实验性）" small onClose={() => !nativeSwitch.busy && setNativeSwitch(null)} locked={nativeSwitch.busy}>
      {!nativeSwitch.outcome ? <>
        <p role="status">正在为 <strong>{identity(nativeSwitch.account)}</strong> 获取登录凭据并发起免重启切换…</p>
        <p>请在 Devin 官方窗口点击 Yes；之后会自动核对账号，无需再次确认或重复点击。</p>
      </> : <>
        <p className={nativeSwitch.outcome.failureCode ? 'error notice' : 'success notice'}>{nativeSwitch.outcome.message}</p>
        {!nativeSwitch.outcome.failureCode && !nativeSwitch.verify && <p>正在自动检查登录状态；如 Devin 提示确认，请先完成确认。也可点击“验证生效”立即检查。<strong>仅发出登录请求不代表切换成功。</strong></p>}
        {nativeSwitch.outcome.failureCode === 'uri_delivery_unconfirmed' && !nativeSwitch.verify && <p>结果未知：URI 已交给系统，未能确认 Devin 是否收到。若 Devin 实际已处理登录，请点击“验证生效”核对当前账号；未生效可关闭后重试。<strong>在核对前请勿重复发起，以免请求重叠。</strong></p>}
        {nativeSwitch.blockedBy && <p>上一次免重启请求仍在等待核对（目标：{(() => { const t = accounts.find(x => x.id === nativeSwitch.blockedBy!.targetId); return t ? identity(t) : '另一账号'; })()}）。<strong>本次点击没有向 Devin 发送任何请求。</strong>若 Devin 已处理上次的登录，请点「验证生效」核对；确认未生效可「放弃并重新发起」。</p>}
        {nativeSwitch.verify && <p className={nativeSwitch.verify.state === 'verified' && nativeSwitch.verify.remoteStatus === 'passed' ? 'success notice' : 'notice'}>{
          nativeSwitch.verify.state === 'verified' ? `当前登录：${nativeSwitch.verify.sessionLabel}。${nativeSwitch.verify.remoteStatus === 'passed' ? '服务端已接受当前会话令牌。' : nativeSwitch.verify.remoteStatus === 'rejected' ? '注意：服务端拒绝了当前会话令牌，切换可能未真正生效。' : ''}请再发送一次 AI 请求确认身份。`
          : nativeSwitch.verify.state === 'pending' ? `尚未确认生效${nativeSwitch.verify.sessionLabel ? `（当前会话：${nativeSwitch.verify.sessionLabel}）` : ''}——若已在 Devin 中确认，请稍等片刻再验证。`
          : '未检测到客户端登录会话，请在 Devin 中完成官方确认后重试。'}</p>}
        <div className="modal-footer"><button onClick={() => setNativeSwitch(null)}>关闭</button>{nativeSwitch.blockedBy && <button disabled={nativeSwitch.busy} onClick={() => void nativeAbandon()}>放弃并重试</button>}{(!nativeSwitch.outcome.failureCode || nativeSwitch.outcome.failureCode === 'uri_delivery_unconfirmed' || nativeSwitch.blockedBy) && <button className="primary" disabled={nativeSwitch.busy} onClick={() => void nativeCheck()}>{nativeSwitch.busy ? '验证中…' : '验证生效'}</button>}</div>
      </>}
    </Modal>}
  </div>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
