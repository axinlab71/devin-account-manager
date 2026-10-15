import { memo } from 'react';
import { getWindsurfCreditsSummary, getWindsurfOfficialUsageMode, getWindsurfQuotaUsageSummary, getWindsurfResolvedPlanLabel, type WindsurfAccount } from '../types/windsurf';

const number = (value: number) => new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 2 }).format(value);
function resetLabel(time: number | null) {
  if (!time) return '';
  if (time * 1000 <= Date.now()) return '已到重置时间，请刷新';
  return `${new Date(time * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })} 重置`;
}
function Meter({ label, remaining, detail, reset }: {label: string; remaining: number | null; detail?: string; reset?: number | null}) {
  const percent = remaining == null ? null : Math.max(0, Math.min(100, remaining));
  return <div className={`quota-meter ${percent != null && percent <= 15 ? 'low' : ''}`}>
    <div className="quota-heading"><span>{label}</span><strong>{detail || (percent == null ? '暂无数据' : `剩余 ${number(percent)}%`)}</strong></div>
    {percent == null ? <div className="quota-track unknown"/> : <div className="quota-track" role="progressbar" aria-label={`${label}剩余`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent} aria-valuetext={detail || `剩余 ${number(percent)}%`}><span style={{ width: `${percent}%` }}/></div>}
    {reset ? <small>{resetLabel(reset)}</small> : null}
  </div>;
}
export const AccountQuota = memo(function AccountQuota({ account }: {account: WindsurfAccount}) {
  const quota = getWindsurfQuotaUsageSummary(account);
  const credits = getWindsurfCreditsSummary(account);
  const quotaMode = getWindsurfOfficialUsageMode(account) === 'quota' || quota.dailyUsedPercent != null || quota.weeklyUsedPercent != null;
  const creditKnown = credits.promptCreditsLeft != null || credits.addOnCredits != null;
  const cached = Boolean(account.quota_query_last_error);
  const quotaKnown = quota.dailyUsedPercent != null || quota.weeklyUsedPercent != null;
  const left = credits.promptCreditsLeft;
  const total = credits.promptCreditsTotal;
  const percent = left != null && total != null && total > 0 ? left / total * 100 : null;
  return <div className="account-quota" aria-label="使用额度"><div className="quota-caption"><span>使用额度</span><span>{cached ? (quotaKnown || creditKnown ? '已缓存数据' : '待更新') : quotaMode ? '日 / 周限额' : creditKnown ? 'Credits' : '就绪'}</span></div>
    {quotaMode ? <div className="quota-meters"><Meter label="每日额度" remaining={quota.dailyUsedPercent == null ? null : 100 - quota.dailyUsedPercent} reset={quota.dailyResetAt}/><Meter label="每周额度" remaining={quota.weeklyUsedPercent == null ? null : 100 - quota.weeklyUsedPercent} reset={quota.weeklyResetAt}/></div> : creditKnown ? <><Meter label="月度 Credits" remaining={percent} detail={left == null ? '暂无数据' : `剩余 ${number(left)}${total == null ? '' : ` / ${number(total)}`}`} reset={credits.planEndsAt}/>{credits.addOnCredits != null ? <div className="extra-credits"><span>加购 Credits</span><strong>{number(credits.addOnCredits)}</strong></div> : null}</> : <div className="quota-empty">暂无额度数据<span>点击刷新，获取最新使用情况</span></div>}
  </div>;
});
export function accountPlan(account: WindsurfAccount) { return getWindsurfResolvedPlanLabel(account) || account.copilot_plan || '计划未知'; }
