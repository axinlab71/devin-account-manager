import { useEffect, useState, type ReactNode } from 'react';
import type { RotationConfig, RotationStatus } from '../services/windsurfService';
import type { WindsurfAccount } from '../types/windsurf';

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

// Rotation monitoring settings. Fully automatic mode is deliberately not
// selectable: it requires verified same-process switching + auth-compat
// evidence that does not exist yet.
export function RotationSettings(p: Props) {
 const [cfg, setCfg] = useState<RotationConfig>(DEFAULTS);
 const [saved, setSaved] = useState('');
 const [dirty, setDirty] = useState(false);
 // Sync server config only while the form is unedited — a background status
 // push must not clobber in-progress edits.
 useEffect(() => {
  const s = p.status;
  if (s && !dirty) setCfg(s.config);
 }, [p.status?.config]);

 const edit = (f: (c: RotationConfig) => RotationConfig) => {
  setDirty(true);
  setCfg(f);
 };
 const setPool = (id: string, on: boolean) =>
  edit(c => ({...c, enabledPool: on ? [...c.enabledPool, id] : c.enabledPool.filter(x => x !== id)}));

 return <>
  <h2 className="preferences-section-title">额度监控</h2>
  <div className="preferences-card">
   <Row title="监控模式" description="只在应用运行时轮询额度；退出即停止。全自动模式需要原生热切换验收后才开放。">
    <select aria-label="监控模式" value={cfg.mode} onChange={e => edit(c => ({...c, mode: e.target.value as RotationConfig['mode']}))}>
     <option value="off">关闭</option>
     <option value="notify_only">仅提醒</option>
     <option value="smart_confirm">推荐并等待确认</option>
     <option value="auto" disabled>全自动（未开放）</option>
    </select>
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
   <Row title="切换后冷却" description="账号被切走后进入冷却，额度重置后才重新参与轮换。默认 30 分钟。">
    <select aria-label="切换后冷却" value={cfg.cooldownSecs} onChange={e => edit(c => ({...c, cooldownSecs: Number(e.target.value)}))}>
     {[300,600,1800,3600].map(v => <option key={v} value={v}>{v < 3600 ? `${v/60} 分钟` : '1 小时'}</option>)}
    </select>
   </Row>
   <Row title="最短切换间隔" description="两次实际切换之间的全局最小间隔，防止 A→B→A 频繁摆动。默认 10 分钟。">
    <select aria-label="最短切换间隔" value={cfg.minSwitchIntervalSecs} onChange={e => edit(c => ({...c, minSwitchIntervalSecs: Number(e.target.value)}))}>
     {[300,600,900,1800].map(v => <option key={v} value={v}>{v/60} 分钟</option>)}
    </select>
   </Row>
   <Row title="备用账号池" description="低额度时仅从这些账号中挑选目标；未勾选的账号不会被推荐。优先级仅在排序方式为「用户优先级最高」时生效，数字越大越靠前。">
    <div className="rotation-pool">{p.accounts.map(a => {
     const inPool = cfg.enabledPool.includes(a.id);
     const prio = cfg.priorities[a.id] ?? 0;
     return <label key={a.id} style={{display:'flex',alignItems:'center',gap:6}}>
      <input type="checkbox" checked={inPool} onChange={e => setPool(a.id, e.target.checked)}/>
      {a.github_name || a.github_login || a.id}
      {inPool && cfg.sortMode === 'priority_first' && (
       <select aria-label={`优先级-${a.id}`} value={prio} style={{marginLeft:'auto'}}
        onChange={e => edit(c => {
         const priorities = {...c.priorities};
         const v = Number(e.target.value);
         if (v === 0) delete priorities[a.id]; else priorities[a.id] = v;
         return {...c, priorities};
        })}>
        {[0,1,2,3,4,5].map(v => <option key={v} value={v}>{v === 0 ? '默认' : `优先级 ${v}`}</option>)}
       </select>)}
     </label>;
    })}</div>
   </Row>
   <div className="modal-footer">
    <button disabled={p.busy} onClick={() => void p.onScan().then(() => setSaved('已扫描。'))}>立即扫描</button>
    {p.status?.paused
     ? <button disabled={p.busy} onClick={() => void p.onResume()}>恢复监控</button>
     : <button disabled={p.busy || cfg.mode === 'off'} onClick={() => void p.onPause()}>暂停监控</button>}
    <button className="primary" disabled={p.busy} onClick={() => void p.onSave(cfg).then(() => { setDirty(false); setSaved('已保存。'); })}>保存设置</button>
   </div>
   {saved && <p className="notice">{saved}</p>}
   <p className="preferences-autosave">切换执行为「官方 URI 登录」实验路径：确认后由官方客户端自己的弹窗完成登录，不重启、不改写客户端文件；结果需只读验证后生效。</p>
  </div>
 </>;
}
