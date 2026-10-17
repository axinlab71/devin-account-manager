import { useRef, useState } from 'react';
import { verifyNativeLogin, type NativeVerifyResult, type RotationStatus, type SwitchOutcome } from '../services/windsurfService';
import { useNativeAutoVerify } from '../hooks/useNativeAutoVerify';

type Props = {
 status: RotationStatus | undefined;
 accountName: (id: string) => string;
 currentAccountId: string | undefined;
 busy: boolean;
 onConfirm: (suggestionId: string, targetId: string) => Promise<SwitchOutcome>;
 onDismiss: (suggestionId: string) => Promise<void>;
 onAcknowledgeRecovery?: () => Promise<void>;
 switchMethod?: string;
};

// Recommendation banner: only renders when the backend produced a
// Recommendation or an informational Warning. Confirm goes through the
// server-side gate — if no adapter is verified the outcome explains that
// nothing was executed instead of silently restarting.
export function RotationRecommendation(p: Props) {
 const [result, setResult] = useState<SwitchOutcome | null>(null);
 const [verify, setVerify] = useState<NativeVerifyResult | null>(null);
 const [submitting, setSubmitting] = useState(false);
 const [verifying, setVerifying] = useState(false);
 const decision = p.status?.lastDecision;
 // All transient state is keyed to the current suggestion id: a new
 // recommendation must not inherit the previous one's confirm outcome or
 // verification result, and late async replies must not write back into it.
 const sigRef = useRef(decision?.suggestionId);
 const sig = decision?.suggestionId;
 useNativeAutoVerify(sig, decision?.target?.accountId,
  decision?.resolution === 'awaiting_client' && (verify?.state !== 'verified' || verify.remoteStatus === 'unavailable'), setVerify);
 if (sigRef.current !== sig) {
  sigRef.current = sig;
  setResult(null); setVerify(null); setSubmitting(false); setVerifying(false);
 }
 // Recovered-from-backup gate has no suggestion of its own when the restored
 // snapshot predates every recommendation — still needs an explicit exit.
 if (p.status?.recoveredFromBackup && (!decision || decision.kind !== 'recommendation')) {
  return <div className="client-warning" role="status">
   <span>检测到轮换状态从备份恢复，执行结果不确定。请核对 Devin 当前登录账号；确认无误后点击「已核对」。</span>
   {p.onAcknowledgeRecovery && <button onClick={() => void p.onAcknowledgeRecovery!()}>已核对</button>}
  </div>;
 }
 const noCandidate = decision?.kind === 'blocked' && decision.reasons.includes('no_eligible_candidate');
 if (!decision || (decision.kind !== 'recommendation' && decision.kind !== 'warning' && !noCandidate)) return null;

 const warningOnly = decision.kind === 'warning' || noCandidate;
 const target = decision.target;
 const reasonText = decision.reasons[0];
 const resolution = decision.resolution;
 const manual = decision.reasons.includes('manual_switch');
 const awaiting = resolution === 'awaiting_client';
 // `executing` is a brief window between record write and URI launch —
 // still in-flight: no confirm buttons may appear for it.
 const inFlight = awaiting || resolution === 'executing';
 const terminal = resolution === 'verified' || resolution === 'executed' || resolution === 'blocked';

 const doVerify = (targetId: string) => {
  const atSig = sig;
  setVerifying(true);
  void verifyNativeLogin(targetId)
   .then(r => { if (sigRef.current === atSig) setVerify(r); })
   .catch(e => { if (sigRef.current === atSig) setVerify({state:'pending', sessionLabel:String(e)}); })
   .finally(() => { if (sigRef.current === atSig) setVerifying(false); });
 };

 const confirm = async () => {
  if (!decision.suggestionId || !target) return;
  const atSig = sig;
  setSubmitting(true);
  try {
   const outcome = await p.onConfirm(decision.suggestionId, target.accountId);
   if (sigRef.current === atSig) setResult(outcome);
  } catch (e) {
   if (sigRef.current === atSig) setResult({targetAccountId: target.accountId, restartRequired:false, localMatch:'not_attempted', clientRecognized:'not_attempted', remoteVerified:'not_attempted', rollback:'not_needed', failureCode:'ipc_error', message:String(e)});
  } finally { if (sigRef.current === atSig) setSubmitting(false); }
 };

 return <div className="client-warning" role="status">
  {warningOnly ? (
   <span>额度提醒：{reasonText === 'unverified_quota_semantics'
    ? '当前账号额度字段语义未验证，仅供参考，暂不推荐切换。'
    : noCandidate
     ? '当前账号额度偏低，但备用池没有可用账号。请在应用设置的额度轮换页选择备用账号并扫描；本次不会切号。'
    : reasonText === 'low_quota_notify_only'
     ? `当前账号的适用额度已低于 ${p.status?.thresholdPercent ?? 10}%（0% 阈值表示耗尽）。当前为仅提醒模式，不会自动切号。`
     : '当前账号额度偏低，请检查额度和监控设置。'}</span>
  ) : (
   <span>
    {manual
     ? <>免重启切换（实验性）：已发起切换到 {target ? p.accountName(target.accountId) : '目标账号'} 的官方登录请求。</>
     : <>当前账号额度已低于阈值{target ? `，建议切换到 ${p.accountName(target.accountId)}（最低剩余 ${Math.round(target.minApplicablePercent)}%）` : ''}。
    {target?.crossOrg && <strong> 注意：目标账号属于不同组织。</strong>}
    {p.switchMethod === 'native'
     ? ' 将尝试免重启：通过官方 URI 登录请求完成，不重启、不改写客户端文件。'
     : ' 将使用标准切号：写入目标账号并重启 Devin Desktop（切换前自动备份）。'}</>}
   </span>
  )}
  {terminal && (
   <span> {resolution === 'verified' ? '已完成切换并通过官方会话验证。' : resolution === 'executed' ? '本地写入校验通过并已重启客户端；账号与服务连接待确认。' : '切换被门禁阻止。'}</span>
  )}
  {result?.failureCode && <span> {result.message}</span>}
  {result && !result.failureCode && result.adapter !== 'native' && <span> {result.message}</span>}
  {(result && !result.failureCode && result.adapter === 'native' || inFlight) && target && (
   <>
    {result?.message && <span> {result.message}</span>}
    {resolution === 'executing' && <span> 正在发起官方登录请求…</span>}
    {awaiting && result?.failureCode === 'uri_delivery_unconfirmed'
     ? <span> 结果未知：Devin 可能仍在处理该登录。请先点「验证生效」核对，核对前请勿重复发起以免请求重叠。</span>
     : awaiting && <span> 正在自动核对登录状态；如 Devin 弹出确认框，请完成确认。URI 发出不代表切换成功。</span>}
    {awaiting && <button disabled={verifying} onClick={() => void doVerify(target.accountId)}>
     {verifying ? '检查中…' : '验证生效'}
    </button>}
    {verify?.state === 'verified' && <span> 已切换到 {verify.sessionLabel}。{verify.remoteStatus === 'passed' ? '服务端已接受当前会话令牌。' : verify.remoteStatus === 'rejected' ? '注意：服务端拒绝了当前会话令牌，切换可能未真正生效。' : ''}请再发送一次 AI 请求确认身份。</span>}
    {verify?.state === 'pending' && <span> 客户端会话仍是 {verify.sessionLabel || '未知'}，请在 Devin 确认框中点击确认后再验证。</span>}
    {verify?.state === 'no_session' && <span> 尚未检测到客户端会话变化。</span>}
   </>
  )}
  {!warningOnly && target && decision.suggestionId && !terminal && !inFlight && (
   <>
    <button className="primary" disabled={p.busy || submitting} onClick={() => void confirm()}>{submitting ? '确认中…' : '切换到此账号'}</button>
    <button disabled={p.busy || submitting} onClick={() => void p.onDismiss(decision.suggestionId!)}>暂时忽略</button>
   </>
  )}
  {(terminal || inFlight) && decision.suggestionId && (
   <button disabled={p.busy} onClick={() => void p.onDismiss(decision.suggestionId!)}>关闭</button>
  )}
 </div>;
}
