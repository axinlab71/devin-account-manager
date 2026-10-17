import { useEffect, useState, type ReactNode } from 'react';
import type { RotationConfig, RotationStatus } from '../services/windsurfService';
import { getWindsurfPlanBadge, getWindsurfPlanBadgeClass, getWindsurfResolvedPlanLabel, type WindsurfAccount } from '../types/windsurf';

function Row({ title, description, children }: {title: string; description: string; children: ReactNode}) {
 return <div className="preferences-row"><div><strong>{title}</strong><p>{description}</p></div><div className="preferences-control">{children}</div></div>;
}

type Props = {
 status: RotationStatus | undefined;
 accounts: WindsurfAccount[];
 busy: boolean;
 onSave: (config: RotationConfig) => Promise<RotationStatus>;
 onScan: () => Promise<RotationStatus>;
 onPause: () => Promise<RotationStatus>;
 onResume: () => Promise<RotationStatus>;
};

const DEFAULTS: RotationConfig = {
 mode: 'off', enabledPool: [], thresholdPercent: 10, pollIntervalSecs: 60,
 snapshotMaxAgeSecs: 120, lowConfirmGapMs: 5000, candidateMarginPoints: 5,
 minSwitchIntervalSecs: 600, cooldownSecs: 1800, maxConsecutiveFailures: 3,
 sortMode: 'min_remaining_desc', priorities: {},
};

// Human-readable labels for policy reason codes emitted by the backend.
const REASON_TEXT: Record<string, string> = {
 monitoring_disabled: '监控模式为关闭',
 monitor_paused: '监控已暂停',
 circuit_open_failures: '连续失败达到上限，已暂停推荐',
 current_identity_unknown: '未能识别客户端当前登录账号',
 current_snapshot_missing: '当前账号还没有额度数据',
 current_snapshot_stale: '当前账号额度数据已过期',
 clock_anomaly: '检测到时间异常，已跳过本次结果',
 current_auth_rejected: '当前账号凭据被拒绝',
 current_policy_denied: '当前账号额度查询被拒绝',
 current_rate_limited: '当前账号额度查询被限流',
 current_query_network_error: '当前账号额度查询网络错误',
 current_query_server_error: '当前账号额度查询服务器错误',
 current_query_parse_failed: '当前账号额度数据无法解析',
 current_no_usable_credential: '当前账号没有可用凭据',
 current_limits_unknown: '当前账号额度结构无法识别',
 unverified_quota_semantics: '额度字段含义未经证实，不算可信低额度',
 awaiting_second_low_confirmation: '已低于阈值，等待下一次扫描确认',
 dismissed_low_cycle: '同类提醒近期已被忽略',
 min_switch_interval: '距上次切换不足最小间隔',
 no_eligible_candidate: '备用池中没有额度更高且可用的账号',
 low_quota_notify_only: '当前账号额度不足（仅提醒，不推荐切换）',
 low_quota_confirmed: '已确认当前账号额度不足',
 switch_in_progress: '已有切换等待官方客户端确认',
 manual_switch: '手动免重启切换进行中，等待官方确认',
};

const formatMs = (ms?: number) =>
 ms ? new Date(ms).toLocaleString('zh-CN', {month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'}) : '尚未扫描';

// Rotation monitoring settings. Fully automatic mode is deliberately not
// selectable: it requires verified same-process switching + auth-compat
// evidence that does not exist yet.
export function RotationSettings(p: Props) {
 const [cfg, setCfg] = useState<RotationConfig>(DEFAULTS);
 const [saved, setSaved] = useState('');
 const [dirty, setDirty] = useState(false);
 const [working, setWorking] = useState(false);
 const perform = async (action: () => Promise<void>) => {
  if (working) return;
  setWorking(true);
  try { await action(); } catch (e) { setSaved(`操作失败：${String(e)}`); }
  finally { setWorking(false); }
 };
 // Sync server config only while the form is unedited — a background status
 // push must not clobber in-progress edits.
 useEffect(() => {
  const s = p.status;
  if (s && !dirty) setCfg(s.config);
 }, [p.status?.config]);
 useEffect(() => {
  if (!saved) return;
  const t = setTimeout(() => setSaved(''), 4000);
  return () => clearTimeout(t);
 }, [saved]);

 const edit = (f: (c: RotationConfig) => RotationConfig) => {
  setSaved('');
  setDirty(true);
  setCfg(f);
 };
 const setPool = (id: string, on: boolean) =>
  edit(c => ({...c, enabledPool: on ? [...c.enabledPool, id] : c.enabledPool.filter(x => x !== id)}));

 const s = p.status;
 const statusLabel = !s || s.config.mode === 'off' ? '已关闭'
  : s.paused ? '已暂停' : s.scanning ? '正在扫描' : '运行中';
 const lastDecision = s?.lastDecision;
 const noRecommendation = lastDecision && lastDecision.kind !== 'recommendation' && lastDecision.reasons.length > 0;

 return <>
  <h2 className="preferences-section-title">额度监控</h2>
  <div className="preferences-card">
   <div className="preferences-row">
    <div>
     <strong>监控状态</strong>
     <p>
      当前：<b>{statusLabel}</b> · 已保存备用账号 {s?.config.enabledPool.length ?? 0} 个 · 上次扫描 {formatMs(s?.lastScanAtMs)}
      <br/>每 {s?.config.pollIntervalSecs ?? 60} 秒检查一次；低额度需重复确认后才提醒或推荐。推荐不会直接切号，关闭应用后停止轮询。
      {noRecommendation && <><br/>本次未推荐：{lastDecision.reasons.map(r => REASON_TEXT[r] || r).join('；')}</>}
     </p>
    </div>
    <div className="preferences-control">
     {s?.paused
      ? <button disabled={p.busy || working} onClick={() => void perform(async () => { await p.onResume(); setSaved('监控已恢复。'); })}>恢复监控</button>
      : <button disabled={p.busy || working || cfg.mode === 'off'} onClick={() => void perform(async () => { await p.onPause(); setSaved('监控已暂停。'); })}>暂停监控</button>}
    </div>
   </div>
   <Row title="监控模式" description="仅提醒：低额度时提示。推荐并等待确认：挑选备用账号，确认后切换；免重启方式仍需在 Devin 中点 Yes。应用退出后监控停止。">
    <select aria-label="监控模式" value={cfg.mode} onChange={e => edit(c => ({...c, mode: e.target.value as RotationConfig['mode']}))}>
     <option value="off">关闭</option>
     <option value="notify_only">仅提醒</option>
     <option value="smart_confirm">推荐并等待确认</option>
     <option value="auto" disabled>全自动（未开放）</option>
    </select>
   </Row>
   <Row title="切号方式" description="默认主按钮走标准切号（重启）；「客户端」页可改为「尝试免重启（实验性）」，此后卡片主按钮走官方确认流程。缺少 URI 凭据的账号会标注“暂不支持免重启”，仍可标准切号。额度监控只决定何时推荐，不改变切号方式。">
    <span className="rotation-method-note">在「客户端」页设置</span>
   </Row>
   <Row title="低额度阈值" description="当前账号任一适用限制剩余低于该百分比时进入观察。">
    <select aria-label="低额度阈值" value={cfg.thresholdPercent} onChange={e => edit(c => ({...c, thresholdPercent: Number(e.target.value)}))}>
     {[0,5,10,15,20,25,30].map(v => <option key={v} value={v}>{v}%</option>)}
    </select>
   </Row>
   <Row title="轮询间隔" description="每次扫描串行执行，不会对官方客户端写入。">
    <select aria-label="轮询间隔" value={cfg.pollIntervalSecs} onChange={e => edit(c => ({...c, pollIntervalSecs: Number(e.target.value)}))}>
     {[30,60,120,300,600].map(v => <option key={v} value={v}>{v < 60 ? `${v} 秒` : `${v/60} 分钟`}</option>)}
    </select>
   </Row>
   <Row title="候选排序" description="备用账号的挑选顺序，完全相同项按账号 ID 兜底，保证每次结果一致。">
    <select aria-label="候选排序" value={cfg.sortMode} onChange={e => edit(c => ({...c, sortMode: e.target.value as RotationConfig['sortMode']}))}>
     <option value="min_remaining_desc">剩余额度最多</option>
     <option value="priority_first">用户优先级最高</option>
     <option value="earliest_reset">重置时间最早</option>
     <option value="longest_idle">最久未使用</option>
    </select>
   </Row>
   <Row title="切换后冷却" description="账号被切走后进入冷却，冷却结束且额度符合条件时才重新参与推荐。默认 30 分钟。">
    <select aria-label="切换后冷却" value={cfg.cooldownSecs} onChange={e => edit(c => ({...c, cooldownSecs: Number(e.target.value)}))}>
     {[300,600,1800,3600].map(v => <option key={v} value={v}>{v < 3600 ? `${v/60} 分钟` : '1 小时'}</option>)}
    </select>
   </Row>
   <Row title="最短切换间隔" description="两次实际切换之间的全局最小间隔，防止 A→B→A 频繁摆动。默认 10 分钟。">
    <select aria-label="最短切换间隔" value={cfg.minSwitchIntervalSecs} onChange={e => edit(c => ({...c, minSwitchIntervalSecs: Number(e.target.value)}))}>
     {[300,600,900,1800].map(v => <option key={v} value={v}>{v/60} 分钟</option>)}
    </select>
   </Row>
  </div>

  <h2 className="preferences-section-title">备用账号池</h2>
  {cfg.mode === 'smart_confirm' && cfg.enabledPool.length === 0 && <p role="status">尚未选择备用账号：可以监测额度，但无法推荐切换目标。请至少勾选一个其他账号。</p>}
  <div className="preferences-card rotation-pool-card">
   <div className="pool-head">
    <p>低额度时仅从勾选的账号中推荐切换目标；未勾选的不参与轮换。{cfg.sortMode === 'priority_first' ? '数字越大优先级越高。' : ''}</p>
    <div className="pool-tools">
     <span>已选 {cfg.enabledPool.length} 个</span>
     <button className="text-button" onClick={() => edit(c => ({...c, enabledPool: p.accounts.map(a => a.id)}))}>全选</button>
     <button className="text-button" onClick={() => edit(c => ({...c, enabledPool: []}))}>清空</button>
    </div>
   </div>
   <div className="rotation-pool">
    {p.accounts.map(a => {
     const inPool = cfg.enabledPool.includes(a.id);
     const prio = cfg.priorities[a.id] ?? 0;
     const snap = s?.snapshots.find(x => x.accountId === a.id);
     const quota = snap?.minApplicablePercent != null ? `剩余 ${Math.round(snap.minApplicablePercent)}%` : (snap && !snap.healthy ? '查询异常' : '未扫描');
     return <label key={a.id} className="pool-row">
      <input type="checkbox" checked={inPool} onChange={e => setPool(a.id, e.target.checked)}/>
      <span className="pool-name">{a.github_name || a.github_login || a.id}</span>
      <span className={`plan-badge plan-${getWindsurfPlanBadgeClass(getWindsurfPlanBadge(a))}`}>{getWindsurfResolvedPlanLabel(a) || '未知'}</span>
      <span className="pool-quota">{quota}</span>
      {inPool && cfg.sortMode === 'priority_first' && (
       <select aria-label={`优先级-${a.id}`} value={prio}
        onChange={e => edit(c => {
         const priorities = {...c.priorities};
         const v = Number(e.target.value);
         if (v === 0) delete priorities[a.id]; else priorities[a.id] = v;
         return {...c, priorities};
        })}>
        {[0,1,2,3,4,5].map(v => <option key={v} value={v}>{v === 0 ? '默认' : `优先级 ${v}`}</option>)}
       </select>)}
     </label>;
    })}
   </div>
  </div>

  <div className="modal-footer rotation-actions">
   <button disabled={p.busy || working} title={dirty ? '扫描使用已保存的设置，请先保存当前修改' : '按已保存设置立即扫描一次'}
    onClick={() => void perform(async () => { await p.onScan(); setSaved('扫描完成。'); })}>立即扫描{dirty ? '（使用已保存设置）' : ''}</button>
   <button className="primary" disabled={p.busy || working}
    onClick={() => void perform(async () => { const r = await p.onSave(cfg); setDirty(false); setSaved(`已保存，备用账号 ${r.config.enabledPool.length} 个。`); })}>保存设置</button>
   {cfg.mode !== 'off' && <button className="primary" disabled={p.busy || working}
    onClick={() => void perform(async () => {
     await p.onSave(cfg); setDirty(false);
     await p.onResume();
     setSaved('监控已启用；低额度需经两次扫描确认，请保持应用运行。');
    })}>保存并启用监控</button>}
   {saved && <span className="save-hint" role="status">{saved}</span>}
  </div>
  <p className="preferences-autosave">提示：切号方式在「客户端」页选择（标准切号 / 尝试免重启）；「免重启」尝试在不关闭 IDE 窗口的情况下切换，可能需要在 Devin 中确认，完成后请检查账号并发送一次 AI 请求验证。本页模式只决定何时推荐，不改变切号方式。</p>
 </>;
}
