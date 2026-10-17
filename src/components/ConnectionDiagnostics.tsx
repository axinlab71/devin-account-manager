import { useEffect, useMemo, useRef, useState } from 'react';
import type { DiagnosticsResult, DiagnosticItem, DiagnosticCheckStatus, RecommendedFix } from '../types/windsurf';
import * as service from '../services/windsurfService';

const STATUS_LABEL: Record<DiagnosticCheckStatus, string> = { confirmed_issue: '已确认异常', ok: '检查正常', unknown: '无法判断' };
const STATUS_ORDER: DiagnosticCheckStatus[] = ['confirmed_issue', 'ok', 'unknown'];

/** 把 RecommendedFix 的 requiresRestart / affectsLogin / manual 转成按钮旁的小字标注。 */
function fixNote(fix: RecommendedFix | undefined): string {
 if (!fix) return '';
 const parts: string[] = [];
 if (fix.requiresRestart) parts.push('需要重启客户端');
 if (!fix.affectsLogin) parts.push('不影响登录状态');
 if (fix.manual) parts.push('手动步骤');
 return parts.length > 0 ? `（${parts.join(' / ')}）` : '';
}

/** 恢复结果的用户确认状态：任何恢复操作成功后进入 awaiting，
 *  由用户明确反馈「已恢复」或「未恢复」，不自动声称修好。 */
type RecoveryVerdict = 'idle' | 'awaiting' | 'confirmed' | 'unresolved';

export function ConnectionDiagnostics() {
 const [result, setResult] = useState<DiagnosticsResult | null>(null);
 const [running, setRunning] = useState(false);
 const [error, setError] = useState('');
 const [expanded, setExpanded] = useState<Set<string>>(new Set());
 const [exporting, setExporting] = useState(false);
 const [exportPath, setExportPath] = useState('');
 const [preview, setPreview] = useState('');
 const [previewing, setPreviewing] = useState(false);
 const [proxyPort, setProxyPort] = useState('');
 const [proxyPurpose, setProxyPurpose] = useState(false);
 const [proxyFixing, setProxyFixing] = useState(false);
 const [proxyFixMsg, setProxyFixMsg] = useState('');
 const [proxyFixNotes, setProxyFixNotes] = useState<string[]>([]);
 const [fixState, setFixState] = useState<service.ProxyFixStateInfo | null>(null);
 const [reverting, setReverting] = useState(false);
 const [revertMsg, setRevertMsg] = useState('');
 const [pacLoading, setPacLoading] = useState(false);
 const [pacGuide, setPacGuide] = useState<service.PacClearGuidance | null>(null);
 const [savedWork, setSavedWork] = useState(false);
 const [restarting, setRestarting] = useState(false);
 const [restartMsg, setRestartMsg] = useState('');
 const [verdict, setVerdict] = useState<RecoveryVerdict>('idle');
 const [verdictSaved, setVerdictSaved] = useState(false);
 const [feedbackSaving, setFeedbackSaving] = useState(false);
 const [openingClient, setOpeningClient] = useState(false);
 const [commandMessage, setCommandMessage] = useState('');
 const [exportingLogs, setExportingLogs] = useState(false);
 const [logBundle, setLogBundle] = useState<service.LogExport | null>(null);
 const [forceConfirmed, setForceConfirmed] = useState(false);
 const [forceRestarting, setForceRestarting] = useState(false);
 const [forceMessage, setForceMessage] = useState('');
 const feedbackLock = useRef(false);
 const runSeq = useRef(0);

 useEffect(() => {
  let alive = true;
  const seq = runSeq.current;
  service.getLastDiagnostics().then(last => { if (alive && last && seq === runSeq.current) setResult(last); }).catch(() => {});
  // 撤销入口依据持久化记录显示：跨页面/重开应用后仍然可见
  service.getProxyFixState().then(st => { if (alive) setFixState(st); }).catch(() => {});
  return () => { alive = false; };
 }, []);

 const groups = useMemo(() => {
  const grouped: Record<DiagnosticCheckStatus, DiagnosticItem[]> = { confirmed_issue: [], ok: [], unknown: [] };
  result?.items.forEach(item => { grouped[item.status].push(item); });
  return grouped;
 }, [result]);
 const hasConfirmed = groups.confirmed_issue.length > 0;
 const busy = running || proxyFixing || reverting || restarting || feedbackSaving || openingClient || exportingLogs || forceRestarting;
 const portNumber = Number(proxyPort);
 const portValid = Number.isInteger(portNumber) && portNumber > 0 && portNumber <= 65535;
 const fixById = useMemo(() => {
  const map = new Map<string, RecommendedFix>();
  result?.summary.recommendedFixes.forEach(fix => { map.set(fix.id, fix); });
  return map;
 }, [result]);
 const showProxyFix = !!result && (result.proxy.confirmedProxyIssue || result.proxy.ineffectiveProxyConfirmed || fixById.has('apply_client_proxy_fix'));
 const proxyFixBySummaryOnly = !!result && !result.proxy.confirmedProxyIssue && (result.proxy.ineffectiveProxyConfirmed || fixById.has('apply_client_proxy_fix'));
 const showPacAction = !!result && (result.proxy.pacActive || fixById.has('clear_stale_pac_config'));
 const showRestartAction = fixById.has('restart_devin_client');
 const showAcpReload = fixById.has('reload_acp_connections');

 function toggle(id: string) {
  setExpanded(prev => { const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next; });
 }
 async function runDiagnostics() {
  const seq = ++runSeq.current;
  setRunning(true); setError(''); setVerdict('idle'); setProxyFixNotes([]); setPreview(''); setExportPath(''); setExpanded(new Set());
  try {
   const fresh = await service.runConnectionDiagnostics();
   if (seq === runSeq.current) setResult(fresh); // 旧异步结果不覆盖新诊断
  }
  catch (e) { if (seq === runSeq.current) setError(String(e)); }
  finally { if (seq === runSeq.current) setRunning(false); }
 }
 async function previewReport() {
  setPreviewing(true); setError('');
  try { setPreview(await service.previewDiagnosticsReport()); }
  catch (e) { setError(String(e)); }
  finally { setPreviewing(false); }
 }
 async function exportReport() {
  setExporting(true); setError('');
  try { setExportPath(await service.exportDiagnosticsReport()); }
  catch (e) { setError(String(e)); }
  finally { setExporting(false); }
 }
 async function applyProxyFix() {
  setProxyFixing(true); setProxyFixMsg(''); setProxyFixNotes([]); setRevertMsg(''); setError('');
  try {
   const outcome = await service.applyClientProxyFix(portNumber);
   setFixState(await service.getProxyFixState().catch(() => null));
   setVerdict('awaiting');
   const notes: string[] = [];
   if (outcome.legacyNestedProxyPresent) notes.push('检测到旧版误写的嵌套代理配置（http.proxy 对象形式），官方客户端不会读取，建议手动删除该字段。');
   if (!outcome.writeVerified) notes.push('写入后回读校验未通过，请以官方客户端实际行为为准。');
   setProxyFixNotes(notes);
   const verified = outcome.writeVerified ? '并经回读核对' : '';
   setProxyFixMsg(`已写入 ${outcome.newProxy}${verified}（settings.json：${outcome.settingsPath}；备份：${outcome.backupPath}；写入记录：${outcome.statePath}）。不重启客户端、不影响登录状态。如无效可用下方「撤销本次修改」还原为写入前状态。`);
  } catch (e) { setProxyFixMsg(String(e)); }
  finally { setProxyFixing(false); }
 }
 async function revertProxyFix() {
  setReverting(true); setRevertMsg(''); setError('');
  try {
   const outcome = await service.revertClientProxyFix();
   setFixState(null);
   setRevertMsg(`已撤销本次修改：http.proxy ${outcome.newProxy}（settings.json：${outcome.settingsPath}；写入前备份：${outcome.backupPath}）。`);
   const last = await service.getLastDiagnostics().catch(() => null);
   if (last) setResult(last);
  } catch (e) { setRevertMsg(String(e)); }
  finally { setReverting(false); }
 }
 async function submitVerdict(v: Exclude<RecoveryVerdict, 'idle' | 'awaiting'>) {
  if (feedbackLock.current) return;
  feedbackLock.current = true;
  setFeedbackSaving(true);
  setError('');
  try {
   await service.recordRecoveryFeedback(v);
   setVerdictSaved(true);
  } catch (e) {
   setVerdictSaved(false);
   setError(`反馈记录落盘失败：${e}`);
  }
  setVerdict(v);
  setPreview('');
  feedbackLock.current = false;
  setFeedbackSaving(false);
 }
 async function showPacGuide() {
  setPacLoading(true); setError('');
  try { setPacGuide(await service.clearStalePacConfig()); }
  catch (e) { setError(String(e)); }
  finally { setPacLoading(false); }
 }
 async function restartClient() {
  setRestarting(true); setRestartMsg(''); setError('');
  try {
   setRestartMsg(await service.restartDevinClient());
   setVerdict('awaiting');
  }
  catch (e) { setRestartMsg(String(e)); }
  finally { setRestarting(false); }
 }

 async function copyAcpCommand() {
  try {
   await navigator.clipboard.writeText('Reload ACP Connections');
   setCommandMessage('命令已复制。在 Devin 中按 Ctrl+Shift+P，粘贴命令后按 Enter 执行。');
  } catch {
   setCommandMessage('剪贴板不可用，请选中并复制下方命令，在 Devin 命令面板执行。');
  }
 }

 async function openClient() {
  setOpeningClient(true); setCommandMessage('');
  try {
   await service.openClientForDiagnostics();
   setCommandMessage('已请求打开 Devin。按 Ctrl+Shift+P，输入 Reload ACP Connections 后执行；此按钮不会自动运行命令。');
  } catch (e) { setCommandMessage(String(e)); }
  finally { setOpeningClient(false); }
 }

 async function exportLogs() {
  setExportingLogs(true); setError('');
  try { setLogBundle(await service.exportDevinLogs()); }
  catch (e) { setError(String(e)); }
  finally { setExportingLogs(false); }
 }

 async function completeRestart() {
  if (!forceConfirmed || busy) return;
  setForceRestarting(true); setForceMessage(''); setError('');
  try {
   const outcome = await service.completeRestartDevin();
   setLogBundle(outcome.logExport);
   setForceMessage(`${outcome.message} 本次结束 ${outcome.terminatedProcesses} 个进程。`);
   setVerdict('awaiting');
  } catch (e) { setForceMessage(String(e)); }
  finally { setForceConfirmed(false); setForceRestarting(false); }
 }

 return <>
  <h2 className="preferences-section-title">模型列表诊断与恢复</h2>
  <div className="preferences-card diagnostics-card" aria-busy={busy}>
   <div className="preferences-row"><div><strong>连接诊断</strong><p>针对「模型列表不显示」等连接故障做只读诊断：检查客户端环境、系统代理与 PAC 状态、到认证服务的网络链路（server.codeium.com 等）以及 agent 日志中的认证记录。诊断会在本机保存脱敏结果，不修改官方客户端配置、代理或注册表。网络探测由管理器直连发起，探测成功不代表 Devin 子进程业务请求成功。</p></div><div className="preferences-control"><button disabled={busy} onClick={() => void runDiagnostics()}>{running ? '诊断中…' : result ? '重新诊断' : '开始诊断'}</button></div></div>
   {error && <p className="error notice" role="alert">{error}</p>}
   <div className="preferences-row"><div><strong>导出 Devin 本地日志</strong><p>无需先运行诊断。收集官方 IDE 与 agent 最近日志，自动脱敏后打包为 ZIP；最多 40 个文件，每个截取末尾 512 KiB。不导出账号数据库、密钥或配置。日志仍可能包含项目名、代码等私人内容，请打开检查后再分享。</p></div><div className="preferences-control"><button disabled={busy} onClick={() => void exportLogs()}>{exportingLogs ? '打包中…' : '导出 Devin 日志包'}</button></div></div>
   {logBundle && <div className="preferences-copy" role="status"><strong>日志包已保存在本机</strong><p className="preferences-directory">{logBundle.archivePath}</p><p>已导出 {logBundle.files} 个文件，截取 {logBundle.truncatedFiles} 个，跳过 {logBundle.skippedFiles} 个。清单和可检查的脱敏文本保存在同名目录。</p><button onClick={() => void service.openLogExportFolder().catch(e => setError(String(e)))}>打开日志目录</button></div>}
   {result && <>
    <div className="diag-metrics" aria-label="诊断结果概览">
     {STATUS_ORDER.map(status => <div key={status} className={`diag-metric ${status}`}><span>{STATUS_LABEL[status]}</span><strong>{groups[status].length}<small> 项</small></strong></div>)}
    </div>
    <div className="preferences-copy diag-summary">
     <strong>综合结论：{result.summary.category}</strong>
     <p>{result.summary.confidence}</p>
     <p>{result.summary.overview}</p>
     {result.summary.recommendedFixes.length > 0 && <p className="hint">建议操作：{result.summary.recommendedFixes.map(fix => fix.label).join('；')}</p>}
     {result.logs.failureCategories.length > 0 && <p className="hint">近期日志失败类别：{result.logs.failureCategories.join('、')}（分类仅供参考，不代表根因）</p>}
     <p className="hint">诊断时间：{new Date(result.generatedAtMs).toLocaleString('zh-CN')}</p>
    </div>
    <div className="preferences-row"><div><strong>导出脱敏报告</strong><p>把最近一次诊断结果导出为 Markdown 报告（Token、API Key、邮箱、URL 查询参数均已自动脱敏）。可先预览再导出。</p>{exportPath && <p className="hint">已导出：{exportPath}。报告仅保存在本机，未上传。</p>}</div><div className="preferences-control"><button disabled={previewing} onClick={() => void previewReport()}>{previewing ? '生成中…' : '预览报告'}</button><button disabled={exporting} onClick={() => void exportReport()}>{exporting ? '导出中…' : '导出脱敏报告'}</button></div></div>
    {preview && <div className="preferences-copy"><details open><summary>报告预览（已脱敏）</summary><pre className="diag-preview">{preview}</pre></details></div>}
    {STATUS_ORDER.map(status => groups[status].length > 0 && <div key={status} className="diag-group">
     <p className="diag-group-title">{STATUS_LABEL[status]}（{groups[status].length} 项）</p>
     {groups[status].map(item => <div key={item.id} className="diag-item">
      <button type="button" className="diag-item-head" aria-expanded={expanded.has(item.id)} onClick={() => toggle(item.id)}>
       <span className={`diag-status ${status === 'confirmed_issue' ? 'issue' : status}`}>{STATUS_LABEL[status]}</span>
       <strong>{item.title}</strong>
       <span className="diag-toggle">{expanded.has(item.id) ? '收起 ▲' : '展开 ▼'}</span>
      </button>
      {expanded.has(item.id) && <div className="diag-item-body"><p>{item.detail}</p>{item.evidence.length > 0 && <ul>{item.evidence.map((line, index) => <li key={index}><code>{line}</code></li>)}</ul>}</div>}
     </div>)}
    </div>)}
    {(hasConfirmed || result.summary.recommendedFixes.length > 0) && <div className="preferences-copy diag-recovery">
     <strong>恢复操作</strong>
     <p>以下操作按诊断结果条件出现，并非「一键修复」；请在了解作用与影响后按需执行。执行后请在 Devin 中查看模型列表并用下方按钮反馈结果。</p>
     {showAcpReload && <div className="diag-action">
      <strong>重新加载 ACP 连接</strong>
      <p>先复制命令，再打开 Devin，按 Ctrl+Shift+P 粘贴并执行。操作会刷新连接元数据缓存，可能影响会话显示，请避开正在运行的 AI 任务。</p>
      <div className="diag-action-row"><input aria-label="ACP 重载命令" readOnly value="Reload ACP Connections" onFocus={event => event.currentTarget.select()}/><button disabled={busy} onClick={() => void copyAcpCommand()}>复制命令</button><button disabled={busy} onClick={() => void openClient()}>{openingClient ? '打开中…' : '打开 Devin'}</button></div>
      <p className="hint">需要在官方客户端中执行；管理器不会自动运行此命令，也不会删除认证数据。</p>
      <button disabled={busy} onClick={() => { setVerdict('awaiting'); setVerdictSaved(false); }}>已执行命令，反馈结果</button>
      {commandMessage && <p role="status">{commandMessage}</p>}
     </div>}
     {showProxyFix && <div className="diag-action">
      <strong>写入客户端代理设置</strong>
      <p>作用：把顶层扁平键 "http.proxy"（http://127.0.0.1:端口）写入官方客户端的 User/settings.json。仅修改该键：注释、其他设置与原格式保留；写入前自动备份原文件，期间被其他程序修改会自动中止，写后回读核对。不重启客户端、不影响登录状态。</p>
      <div className="diag-action-row">
       <input disabled={busy || !!fixState} aria-label="本机代理端口" inputMode="numeric" placeholder="本机代理端口，如 7897" value={proxyPort} onChange={e => setProxyPort(e.target.value.replace(/[^0-9]/g, ''))}/>
      </div>
      <label className="diag-check"><input type="checkbox" disabled={busy || !!fixState} checked={proxyPurpose} onChange={e => setProxyPurpose(e.target.checked)}/> 我确认该端口是本机代理软件的实际代理端口，用于让 Devin 访问认证服务</label>
      <div className="diag-action-row">
       <button className="primary" disabled={busy || !!fixState || !portValid || !proxyPurpose} onClick={() => void applyProxyFix()}>{proxyFixing ? '写入中…' : fixById.get('apply_client_proxy_fix')?.label ?? '写入客户端代理设置'}</button>
       {fixById.get('apply_client_proxy_fix') && <span className="hint">{fixNote(fixById.get('apply_client_proxy_fix'))}</span>}
      </div>
      {fixState && <p className="hint">已有尚未撤销的代理修改，请先使用下方撤销入口，再尝试其他端口。</p>}
      {proxyFixBySummaryOnly && <p className="hint">该操作基于疑似/综合结论推荐：端口在监听不等于可用代理，写入前会先对该端口做真实 HTTP 代理握手探测，不通即中止。</p>}
      {proxyFixMsg && <p className="hint" role="status">{proxyFixMsg}</p>}
      {proxyFixNotes.map((note, index) => <p key={index} className="hint">{note}</p>)}
     </div>}
     {showPacAction && <div className="diag-action">
      <strong>PAC 自动配置脚本</strong>
      {result.proxy.pacActive
       ? <p>当前代理模式已启用 PAC 自动配置脚本{result.proxy.pacTarget ? `（${result.proxy.pacTarget}${result.proxy.pacListening === false ? '，该端口无监听' : ''}）` : ''}。若其指向的地址不可用，客户端流量会被错误路由。清除为手动步骤：按 Win+R 运行 inetcpl.cpl，在「连接 → 局域网设置」中取消勾选「使用自动配置脚本」。本工具不会自动修改注册表。</p>
       : <p>{result.proxy.pacConfigured ? `系统中存在未启用的 PAC 残留字符串（${result.proxy.pacTarget || '目标未知'}），当前代理模式未启用 PAC，属无害残留，无需处理。` : '当前未检测到 PAC 配置。'}</p>}
      {fixById.has('clear_stale_pac_config') && <div className="diag-action-row">
       <button disabled={pacLoading} onClick={() => void showPacGuide()}>{pacLoading ? '加载中…' : fixById.get('clear_stale_pac_config')?.label ?? '查看 PAC 清除指引'}</button>
       {fixById.get('clear_stale_pac_config') && <span className="hint">{fixNote(fixById.get('clear_stale_pac_config'))}</span>}
      </div>}
      {pacGuide && <ol className="diag-steps">{pacGuide.steps.map((step, index) => <li key={index}>{step}</li>)}</ol>}
      {pacGuide && <p className="hint">{pacGuide.note}</p>}
     </div>}
     {showRestartAction && <div className="diag-action">
      <strong>重启官方客户端（最后手段）</strong>
      <p>会关闭并重新打开 Devin Desktop，让 agent 子进程重新认证；未保存的工作会丢失；不影响登录状态。关闭为温和方式：超时或用户取消时不强杀进程，也不会继续启动新实例。</p>
      <label className="diag-check"><input type="checkbox" checked={savedWork} onChange={e => setSavedWork(e.target.checked)}/> 我已保存工作</label>
      <div className="diag-action-row">
       <button disabled={busy || !savedWork} onClick={() => void restartClient()}>{restarting ? '重启中…' : fixById.get('restart_devin_client')?.label ?? '重启官方客户端'}</button>
       {fixById.get('restart_devin_client') && <span className="hint">{fixNote(fixById.get('restart_devin_client'))}</span>}
      </div>
      {restartMsg && <p className="hint">{restartMsg}</p>}
     </div>}
     {verdict === 'awaiting' && <div className="diag-action">
      <strong>结果确认</strong>
      <p>已发起恢复操作。请在 Devin 中查看模型列表并发送一条消息验证后反馈——本工具不凭端口连通、文件写入或进程启动判定「已修复」。</p>
      <div className="diag-action-row">
       <button className="primary" disabled={busy} onClick={() => void submitVerdict('confirmed')}>已显示且消息正常</button>
       <button disabled={busy} onClick={() => void submitVerdict('unresolved')}>仍未恢复</button>
      </div>
     </div>}
     {verdict === 'confirmed' && <p className="hint">{verdictSaved ? '已记录并纳入报告：用户确认模型列表恢复、消息可发送。如需留档请导出上方报告。' : '已选择「已显示且消息正常」，但记录未成功落盘（见上方错误），不计入报告。'}</p>}
     {verdict === 'unresolved' && <p className="hint">{verdictSaved ? '已记录并纳入报告：本次恢复未解决问题。建议导出上方脱敏报告，再尝试其他恢复操作或按提示手动处理。' : '已选择「仍未恢复」，但记录未成功落盘（见上方错误），不计入报告。'}</p>}
    </div>}
   </>}
   {fixState && <div className="preferences-copy diag-recovery">
    <strong>撤销代理修改</strong>
    <div className="diag-action">
     <p>本工具于 {new Date(fixState.writtenAtMs).toLocaleString('zh-CN')} 将 http.proxy 写为 <code>{fixState.writtenValue}</code>（{fixState.settingsPath}）。{fixState.previousValue ? <>撤销将恢复原值 <code>{fixState.previousValue}</code>{fixState.previousValue.includes('***') && '（含认证信息，脱敏显示）'}</> : '撤销将移除该键（若 settings.json 由本工具创建则删回整个文件）'}；仅当当前值未被改动时执行，其余设置保留。写入前备份：{fixState.backupPath}</p>
     <div className="diag-action-row">
      <button disabled={busy} onClick={() => void revertProxyFix()}>{reverting ? '撤销中…' : '撤销本次修改'}</button>
     </div>
    </div>
   </div>}
   {/* 撤销结果消息放在块外：成功撤销后记录块卸载，消息仍可见 */}
   {revertMsg && <div className="preferences-copy" role="status"><p className="hint">{revertMsg}</p></div>}
   <div className="preferences-copy diag-recovery"><div className="diag-action diag-force"><strong>温和重启无效？彻底重启进程</strong><p>先导出现场日志，再强制结束当前安装的 Devin 主进程、子进程及残留 agent，然后重新打开。会中断终端与 AI 任务，未保存内容可能丢失。不清理登录文件或缓存，不能保证修复网络、权限及服务端故障；多个配置同时运行时会拒绝操作。</p><label className="diag-check"><input type="checkbox" disabled={busy} checked={forceConfirmed} onChange={event => setForceConfirmed(event.target.checked)}/> 我已保存工作，确认允许强制结束进程及中断终端、AI 任务</label><button className="danger" disabled={busy || !forceConfirmed} onClick={() => void completeRestart()}>{forceRestarting ? '导出日志并重启中…' : '导出日志并彻底重启'}</button>{forceMessage && <p role="status">{forceMessage}</p>}</div></div>
  </div>
 </>;
}
