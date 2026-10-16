import { useRef, useState } from 'react';
import { verifyNativeLogin, type NativeVerifyResult, type RotationStatus, type SwitchOutcome } from '../services/windsurfService';

type Props = {
 status: RotationStatus | undefined;
 accountName: (id: string) => string;
 currentAccountId: string | undefined;
 busy: boolean;
 onConfirm: (suggestionId: string, targetId: string) => Promise<SwitchOutcome>;
 onDismiss: (suggestionId: string) => Promise<void>;
 onAcknowledgeRecovery?: () => Promise<void>;
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
 if (!decision || (decision.kind !== 'recommendation' && decision.kind !== 'warning')) return null;

 const warningOnly = decision.kind === 'warning';
 const target = decision.target;
 const reasonText = decision.reasons[0];
 const resolution = decision.resolution;
 const awaiting = resolution === 'awaiting_client';
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
   <span>额度提醒：{reasonText === 'unverified_quota_semantics' ? '当前账号额度字段语义未验证，仅供参考，暂不推荐切换。' : `当前账号额度偏低（${reasonText}）。`}</span>
  ) : (
   <span>
    当前账号额度已低于阈值{target ? `，建议切换到 ${p.accountName(target.accountId)}（最低剩余 ${Math.round(target.minApplicablePercent)}%）` : ''}。
    {target?.crossOrg && <strong> 注意：目标账号属于不同组织。</strong>}
    {' '}将通过官方客户端的登录确认完成，不重启、不改写客户端文件。
   </span>
  )}
  {terminal && (
   <span> {resolution === 'verified' ? '已完成切换并通过官方会话验证。' : resolution === 'executed' ? '切换已执行。' : '切换被门禁阻止。'}</span>
  )}
  {result?.failureCode && <span> {result.message}</span>}
  {(result && !result.failureCode && result.adapter === 'native' || awaiting) && target && (
   <>
    {result?.message && <span> {result.message}</span>}
    {awaiting && <span> 已发起官方登录，请在 Devin 的确认框中确认。</span>}
    <button disabled={verifying} onClick={() => void doVerify(target.accountId)}>
     {verifying ? '检查中…' : '验证生效'}
    </button>
    {verify?.state === 'verified' && <span> 已切换到 {verify.sessionLabel}。</span>}
    {verify?.state === 'pending' && <span> 客户端会话仍是 {verify.sessionLabel || '未知'}，请在 Devin 确认框中点击确认后再验证。</span>}
    {verify?.state === 'no_session' && <span> 尚未检测到客户端会话变化。</span>}
   </>
  )}
  {!warningOnly && target && decision.suggestionId && !terminal && !awaiting && (
   <>
    <button className="primary" disabled={p.busy || submitting} onClick={() => void confirm()}>{submitting ? '确认中…' : '切换到此账号'}</button>
    <button disabled={p.busy || submitting} onClick={() => void p.onDismiss(decision.suggestionId!)}>暂时忽略</button>
   </>
  )}
  {(terminal || awaiting) && decision.suggestionId && (
   <button disabled={p.busy} onClick={() => void p.onDismiss(decision.suggestionId!)}>关闭</button>
  )}
 </div>;
}
