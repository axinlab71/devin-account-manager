const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const ts = require('typescript');
function load(file, deps = {}) {
 const exports = {};
 const code = ts.transpileModule(fs.readFileSync(file, 'utf8'), { compilerOptions: { module:ts.ModuleKind.CommonJS, target:ts.ScriptTarget.ES2022 } }).outputText;
 vm.runInNewContext(code, { exports, module:{exports}, require:name=>{assert.ok(deps[name],name);return deps[name]}, TextDecoder,TextEncoder,Uint8Array,Buffer,atob,btoa,Date,Intl });
 return exports;
}
const data = load('src/utils/dataExtract.ts');
const q = load('src/types/windsurf.ts', {'../utils/dataExtract':data});
const account = { id:'synthetic',github_login:'synthetic',github_id:0,created_at:1,last_used:1 };
let a={...account,windsurf_plan_status:{billingStrategy:'quota',dailyQuotaRemainingPercent:75,weeklyQuotaRemainingPercent:40,dailyQuotaResetAtUnix:'1900000000'}};
let usage=q.getWindsurfQuotaUsageSummary(a);assert.equal(usage.dailyUsedPercent,25);assert.equal(usage.weeklyUsedPercent,60);assert.equal(usage.dailyResetAt,1900000000);
a={...account,windsurf_user_status:{userStatus:{planStatus:{billing_strategy:'quota',daily_quota_remaining_percent:0,weekly_quota_remaining_percent:100}}}};
usage=q.getWindsurfQuotaUsageSummary(a);assert.equal(usage.dailyUsedPercent,100);assert.equal(usage.weeklyUsedPercent,0);
a={...account,windsurf_plan_status:{billingStrategy:'quota'}};usage=q.getWindsurfQuotaUsageSummary(a);assert.equal(usage.dailyUsedPercent,null);assert.equal(usage.weeklyUsedPercent,null);
let credits=q.getWindsurfCreditsSummary(account);assert.equal(credits.promptCreditsLeft,null);assert.equal(credits.addOnCredits,null);assert.equal(credits.creditsLeft,null);
a={...account,windsurf_plan_status:{planInfo:{monthlyPromptCredits:5000},availablePromptCredits:5000,usedPromptCredits:1200}};
credits=q.getWindsurfCreditsSummary(a);assert.equal(credits.promptCreditsTotal,50);assert.equal(credits.promptCreditsUsed,12);assert.equal(credits.promptCreditsLeft,38);
a={...account,windsurf_plan_status:{planInfo:{monthlyPromptCredits:5000},availablePromptCredits:5000,usedPromptCredits:5000}};assert.equal(q.getWindsurfCreditsSummary(a).promptCreditsLeft,0);
a={...account,windsurf_plan_status:{dailyQuotaRemainingPercent:110,weeklyQuotaRemainingPercent:-5}};usage=q.getWindsurfQuotaUsageSummary(a);assert.equal(usage.dailyUsedPercent,0);assert.equal(usage.weeklyUsedPercent,100);
assert.equal(data.toNumber(''),null);assert.equal(data.toNumber('  '),null);assert.equal(data.toNumber('0'),0);
console.log('PASS: camel/snake quota; zero versus missing; remaining->used; reset timestamps; credits total/used/left; exhausted versus unknown; bounds; blank fields.');

function varint(n) { const out=[]; do { let b=n%128;n=Math.floor(n/128);out.push(b+(n ? 128 : 0)); } while(n);return out; }
const planBytes=[...varint(14*8),100,...varint(15*8),25,...varint(17*8),...varint(1900000000)];
const proto=Buffer.from([...varint(13*8+2),...varint(planBytes.length),...planBytes]).toString('base64');
usage=q.getWindsurfQuotaUsageSummary({...account,usage_proto_b64:proto});
assert.equal(usage.dailyUsedPercent,0);assert.equal(usage.weeklyUsedPercent,75);assert.equal(usage.dailyResetAt,1900000000);
console.log('PASS: retained binary protobuf quota snapshot; remaining semantics agree with upstream Rust decoder.');
