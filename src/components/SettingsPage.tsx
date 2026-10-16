import { useState, type ReactNode, type KeyboardEvent } from 'react';

type ClientStatus = { installed: boolean; appPath: string | null; dataDir: string };
type Props = {
 client?: ClientStatus; currentAccount?: string; busy: boolean; error: string;
 path: string; onPath: (value: string) => void; onSave: () => void; onDetect: () => void;
 theme: string; onTheme: (value: string) => void;
 privateMode: boolean; onPrivacy: (value: boolean) => void;
 view: string; onView: (value: string) => void;
 reducedMotion: boolean; onReducedMotion: (value: boolean) => void;
 onMigrate: () => void;
};
const tabs = [['general', '通用'], ['client', '客户端'], ['data', '数据管理'], ['about', '关于']] as const;
type Tab = typeof tabs[number][0];
function Row({ title, description, children }: {title: string; description: string; children: ReactNode}) {
 return <div className="preferences-row"><div><strong>{title}</strong><p>{description}</p></div><div className="preferences-control">{children}</div></div>;
}
export function SettingsPage(p: Props) {
 const [tab, setTab] = useState<Tab>('general');
 function navigate(event: KeyboardEvent<HTMLButtonElement>, index: number) {
  const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : -1;
  if (next < 0) return;
  event.preventDefault(); setTab(tabs[next][0]); document.getElementById(`settings-tab-${tabs[next][0]}`)?.focus();
 }
 return <section className="preferences-page" aria-label="应用设置">
  <header className="preferences-heading"><div><h1>应用设置</h1><p>按你的习惯，设置账号管理器。</p></div><div className="preferences-tabs" role="tablist" aria-label="设置分类">{tabs.map(([id, title], index) => <button key={id} id={`settings-tab-${id}`} role="tab" aria-selected={tab === id} aria-controls={`settings-panel-${id}`} tabIndex={tab === id ? 0 : -1} onKeyDown={e => navigate(e, index)} onClick={() => setTab(id)}>{title}</button>)}</div></header>
  <div role="tabpanel" id={`settings-panel-${tab}`} aria-labelledby={`settings-tab-${tab}`}>
   {tab === 'general' && <><h2 className="preferences-section-title">外观与显示</h2><div className="preferences-card">
    <Row title="应用主题" description="切换深色或浅色模式，设置会自动保存。"><button aria-label={p.theme === 'dark' ? '切换浅色主题' : '切换深色主题'} onClick={() => p.onTheme(p.theme === 'dark' ? 'light' : 'dark')}>{p.theme === 'dark' ? '深色模式 ☾' : '浅色模式 ☀'}</button></Row>
    <Row title="账号显示方式" description="网格适合浏览额度，列表适合快速查找。"><select aria-label="默认显示方式" value={p.view} onChange={e => p.onView(e.target.value)}><option value="grid">卡片网格</option><option value="list">账号列表</option></select></Row>
    <Row title="减少动画" description="减少界面过渡，保留必要的加载反馈。"><input className="preference-switch" type="checkbox" role="switch" aria-label="减少动画" checked={p.reducedMotion} onChange={e => p.onReducedMotion(e.target.checked)}/></Row>
   </div><h2 className="preferences-section-title">隐私</h2><div className="preferences-card"><Row title="隐藏账号信息" description="隐藏姓名、邮箱和标签，便于录屏和展示。"><input className="preference-switch" type="checkbox" role="switch" aria-label="隐藏账号信息" checked={p.privateMode} onChange={e => p.onPrivacy(e.target.checked)}/></Row></div><p className="preferences-autosave">显示设置自动保存到本机。</p></>}
   {tab === 'client' && <><h2 className="preferences-section-title">Devin Desktop</h2><div className="preferences-card"><Row title={p.client?.installed ? 'Devin Desktop 已就绪' : '尚未检测到 Devin Desktop'} description={p.currentAccount ? `当前账户：${p.currentAccount}` : '当前账户尚未匹配'}><button disabled={p.busy} onClick={p.onDetect}>重新检测</button></Row><div className="preferences-path"><label htmlFor="client-path">客户端程序完整路径</label><p>支持 Devin.exe / Windsurf.exe。修改后点击保存。</p><div><input id="client-path" value={p.path} onChange={e => p.onPath(e.target.value)} placeholder="例如 E:\Devin\Devin.exe" disabled={p.busy}/><button className="primary" disabled={p.busy || !p.path.trim()} onClick={p.onSave}>保存路径</button></div></div></div><h2 className="preferences-section-title">切换保护</h2><div className="preferences-card"><div className="preferences-copy"><strong>写入前自动备份</strong><p>切换账号会自动重启客户端，请先保存工作。写入前备份客户端数据库，继续使用原有账号格式和切号实现。</p></div></div></>}
   {tab === 'data' && <><h2 className="preferences-section-title">本地账号数据</h2><div className="preferences-card"><div className="preferences-copy"><strong>账号数据目录</strong><p className="preferences-directory">{p.client?.dataDir || '目录状态暂时不可用，请在客户端页重新检测。'}</p></div><Row title="账号迁移" description="从 Cockpit Tools 或已登录的官方客户端导入账号。"><button disabled={p.busy} onClick={p.onMigrate}>导入账号</button></Row></div><h2 className="preferences-section-title">凭据安全</h2><div className="preferences-card"><div className="preferences-copy"><strong>凭据在本机加密保存</strong><p>密钥由当前 Windows 用户保护，账号数据不上传到第三方存储。登录和刷新会连接 Devin / Windsurf 官方服务。</p><p>请勿分享账号文件或加密密钥。跨电脑迁移可使用 Cockpit 导出的 JSON，并妥善保管导出文件。</p></div></div></>}
   {tab === 'about' && <div className="preferences-about"><img src="/devin.png" width="72" height="72" alt="Devin 图标"/><h2>Devin 账户管理器</h2><span className="preferences-version">v0.3.1</span><p>查看额度，管理账号，快速切换。</p><div className="preferences-about-links"><a href="https://github.com/sxxxxxxxxxxxxxxxxxxxxx/devin-account-manager" target="_blank" rel="noreferrer"><strong>开源仓库</strong><span>源码与版本下载 ↗</span></a><a href="https://github.com/sxxxxxxxxxxxxxxxxxxxxx/devin-account-manager/issues" target="_blank" rel="noreferrer"><strong>意见反馈</strong><span>报告问题或提出建议 ↗</span></a></div><div className="preferences-attribution"><p>源自 <a href="https://github.com/jlcodes99/cockpit-tools" target="_blank" rel="noreferrer">Cockpit Tools · jlcodes99</a></p><p>CC BY-NC-SA 4.0 · 保留原项目许可与署名</p><p>非官方项目。Devin 图标及商标归原权利人所有。</p></div></div>}
  </div>{p.error && <p className="error notice" role="alert">{p.error}</p>}
 </section>;
}
