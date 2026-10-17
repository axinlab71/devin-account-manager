import { useEffect, useMemo, useState } from 'react';
import type { DiagnosticsResult, DiagnosticItem, DiagnosticCheckStatus } from '../types/windsurf';
import * as service from '../services/windsurfService';

const STATUS_LABEL: Record<DiagnosticCheckStatus, string> = { confirmed_issue: '已确认异常', ok: '检查正常', unknown: '无法判断' };
const STATUS_ORDER: DiagnosticCheckStatus[] = ['confirmed_issue', 'ok', 'unknown'];

export function ConnectionDiagnostics() {
 const [result, setResult] = useState<DiagnosticsResult | null>(null);
 const [running, setRunning] = useState(false);
 const [error, setError] = useState('');
 const [expanded, setExpanded] = useState<Set<string>>(new Set());
 const [exporting, setExporting] = useState(false);
 const [exportPath, setExportPath] = useState('');
 const [proxyPort, setProxyPort] = useState('');
 const [proxyFixing, setProxyFixing] = useState(false);
 const [proxyFixMsg, setProxyFixMsg] = useState('');
 const [pacLoading, setPacLoading] = useState(false);
 const [pacGuide, setPacGuide] = useState<service.PacClearGuidance | null>(null);
 const [savedWork, setSavedWork] = useState(false);
 const [restarting, setRestarting] = useState(false);
 const [restartMsg, setRestartMsg] = useState('');

 useEffect(() => {
  let alive = true;
  service.getLastDiagnostics().then(last => { if (alive && last) setResult(last); }).catch(() => {});
  return () => { alive = false; };
 }, []);

 useEffect(() => {
  if (result && !proxyPort && result.proxy.listeningLocalPorts.length > 0) setProxyPort(String(result.proxy.listeningLocalPorts[0]));
 }, [result, proxyPort]);

 const groups = useMemo(() => {
  const grouped: Record<DiagnosticCheckStatus, DiagnosticItem[]> = { confirmed_issue: [], ok: [], unknown: [] };
  result?.items.forEach(item => { grouped[item.status].push(item); });
  return grouped;
 }, [result]);
 const hasConfirmed = groups.confirmed_issue.length > 0;
 const portNumber = Number(proxyPort);
 const portValid = Number.isInteger(portNumber) && portNumber > 0 && portNumber <= 65535;

 function toggle(id: string) {
  setExpanded(prev => { const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next; });
 }
 async function runDiagnostics() {
  setRunning(true); setError('');
  try { setResult(await service.runConnectionDiagnostics()); }
  catch (e) { setError(String(e)); }
  finally { setRunning(false); }
 }
 async function exportReport() {
  setExporting(true); setError('');
  try { setExportPath(await service.exportDiagnosticsReport()); }
  catch (e) { setError(String(e)); }
  finally { setExporting(false); }
 }
 async function applyProxyFix() {
  setProxyFixing(true); setProxyFixMsg(''); setError('');
  try {
   const outcome = await service.applyClientProxyFix(portNumber);
   setProxyFixMsg(`已写入 ${outcome.newProxy}（settings.json：${outcome.settingsPath}；备份：${outcome.backupPath}）。`);
  } catch (e) { setProxyFixMsg(String(e)); }
  finally { setProxyFixing(false); }
 }
 async function showPacGuide() {
  setPacLoading(true); setError('');
  try { setPacGuide(await service.clearStalePacConfig()); }
  catch (e) { setError(String(e)); }
  finally { setPacLoading(false); }
 }
 async function restartClient() {
  setRestarting(true); setRestartMsg(''); setError('');
  try { setRestartMsg(await service.restartDevinClient()); }
  catch (e) { setRestartMsg(String(e)); }
  finally { setRestarting(false); }
 }

 return <>
  <h2 className="preferences-section-title">连接诊断与修复</h2>
  <div className="preferences-card">
   <div className="preferences-row"><div><strong>连接诊断</strong><p>针对「模型列表不显示」等连接故障做只读诊断：检查客户端环境、系统代理 / PAC 残留、到认证服务的网络链路（server.codeium.com 等）以及 agent 日志中的认证记录。诊断过程不写任何文件，不修改代理设置与注册表。</p></div><div className="preferences-control"><button disabled={running} onClick={() => void runDiagnostics()}>{running ? '诊断中…' : result ? '重新诊断' : '开始诊断'}</button></div></div>
   {error && <p className="error notice" role="alert">{error}</p>}
   {result && <>
    <div className="preferences-copy diag-summary">
     <strong>综合结论：{result.summary.category}</strong>
     <p>{result.summary.confidence}</p>
     <p>{result.summary.overview}</p>
     {result.summary.recommendedFixes.length > 0 && <p className="hint">建议操作：{result.summary.recommendedFixes.map(fix => fix.label).join('；')}</p>}
     <p className="hint">诊断时间：{new Date(result.generatedAtMs).toLocaleString('zh-CN')}</p>
    </div>
    <div className="preferences-row"><div><strong>导出脱敏报告</strong><p>把最近一次诊断结果导出为 Markdown 报告（Token、API Key、邮箱、URL 查询参数均已自动脱敏）。</p>{exportPath && <p className="hint">已导出：{exportPath}。报告仅保存在本机，未上传。</p>}</div><div className="preferences-control"><button disabled={exporting} onClick={() => void exportReport()}>{exporting ? '导出中…' : '导出脱敏报告'}</button></div></div>
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
    {hasConfirmed && <div className="preferences-copy diag-recovery">
     <strong>恢复操作</strong>
     <p>以下操作按诊断结果条件出现，并非「一键修复」；请在了解作用与影响后按需执行。</p>
     {result.proxy.confirmedProxyIssue && <div className="diag-action">
      <strong>写入客户端代理设置</strong>
      <p>作用：把 http.proxy（http://127.0.0.1:端口）写入官方客户端的 User/settings.json。写入前会自动备份原文件；不重启客户端、不影响登录状态。恢复办法：删除 settings.json 中的 http.proxy 字段，或还原备份文件。</p>
      <div className="diag-action-row">
       <input aria-label="本机代理端口" inputMode="numeric" placeholder="本机代理端口，如 7897" value={proxyPort} onChange={e => setProxyPort(e.target.value.replace(/[^0-9]/g, ''))}/>
       <button className="primary" disabled={proxyFixing || !portValid} onClick={() => void applyProxyFix()}>{proxyFixing ? '写入中…' : '写入客户端代理设置'}</button>
      </div>
      {proxyFixMsg && <p className="hint">{proxyFixMsg}</p>}
     </div>}
     {result.proxy.stalePacConfirmed && <div className="diag-action">
      <strong>残留 PAC 配置</strong>
      <p>检测到已失效的 PAC 自动配置脚本。这是手动步骤：按 Win+R 运行 inetcpl.cpl，在「连接 → 局域网设置」中取消勾选「使用自动配置脚本」。本工具不会自动修改注册表。</p>
      <button disabled={pacLoading} onClick={() => void showPacGuide()}>{pacLoading ? '加载中…' : '查看 PAC 清除指引'}</button>
      {pacGuide && <ol className="diag-steps">{pacGuide.steps.map((step, index) => <li key={index}>{step}</li>)}</ol>}
      {pacGuide && <p className="hint">{pacGuide.note}</p>}
     </div>}
     <div className="diag-action">
      <strong>重启官方客户端</strong>
      <p>会关闭并重新打开 Devin Desktop，让 agent 子进程重新认证；未保存的工作会丢失；不影响登录状态。</p>
      <label className="diag-check"><input type="checkbox" checked={savedWork} onChange={e => setSavedWork(e.target.checked)}/> 我已保存工作</label>
      <button disabled={!savedWork || restarting} onClick={() => void restartClient()}>{restarting ? '重启中…' : '重启官方客户端'}</button>
      {restartMsg && <p className="hint">{restartMsg}</p>}
     </div>
    </div>}
   </>}
  </div>
 </>;
}
