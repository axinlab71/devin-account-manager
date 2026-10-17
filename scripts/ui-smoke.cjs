// Local UI regression with synthetic IPC fixtures; never reads real account data.
const { chromium } = require(process.env.DEVIN_PLAYWRIGHT_PATH || 'playwright');
const assert = require('node:assert/strict');
const path = require('node:path');
(async () => {
 const browser = await chromium.launch({ ...(process.env.DEVIN_BROWSER_CHANNEL === 'chromium' ? {} : {channel:'msedge'}), headless: true });
 const page = await browser.newPage({ viewport: { width:1120, height:780 }, reducedMotion: 'reduce' });
 const errors = []; page.on('pageerror', e => errors.push(e.message));
 await page.addInitScript(() => {
  if (!localStorage.getItem('devin.view')) localStorage.setItem('devin.view','grid');
  if (!localStorage.getItem('devin.theme')) localStorage.setItem('devin.theme','light');
  const now = Math.floor(Date.now()/1000);
  const account = (id,name,email,plan,days) => ({id,github_name:name,github_login:email,github_email:email,github_id:0,credential_state:'unverified',last_switched_at:now-days*3600,copilot_plan:plan,created_at:now-days*86400,last_used:now-days*3600});
  window.uiFixture = { accounts:[{...account('demo-1','Alex Chen','alex@example.com','Pro',1),windsurf_plan_status:{planInfo:{monthlyPromptCredits:5000},availablePromptCredits:5000,usedPromptCredits:1200}}, {...account('demo-2','Design Studio','design@example.com','Teams',3),windsurf_plan_status:{billingStrategy:'quota',dailyQuotaRemainingPercent:75,weeklyQuotaRemainingPercent:40,dailyQuotaResetAtUnix:now+3600,weeklyQuotaResetAtUnix:now+86400}}, {...account('demo-3','Personal','personal@example.com','Free',5),quota_query_last_error:'synthetic expired',native_switch_credential_ready:false}],calls:[],legacyCount:2 };
  const mockRotationCfg = () => ({mode:'off',enabledPool:[],thresholdPercent:10,pollIntervalSecs:60,snapshotMaxAgeSecs:120,lowConfirmGapMs:5000,candidateMarginPoints:5,minSwitchIntervalSecs:600,cooldownSecs:1800,maxConsecutiveFailures:3,sortMode:'min_remaining_desc',priorities:{}});
  const mockDiag = () => ({generatedAtMs:Date.now(),appVersion:'0.5.1',
   items:[{id:'pac',group:'proxy',title:'PAC 自动配置脚本生效中且目标不可达',status:'confirmed_issue',detail:'PAC 生效但端口无监听',evidence:['flags=0x0F','pac=http://127.0.0.1:9/pac']},{id:'net',group:'network',title:'认证服务 TLS 正常',status:'ok',detail:'server.codeium.com 握手正常',evidence:[]}],
   client:{exePath:'E:\\Devin\\Devin.exe',exeExists:true,productVersion:'1.126.0',productCommit:'abc',fileVersion:'1.126.0',dataDir:'C:\\synthetic',dataDirExists:true,userSettingsExists:true,cliLogDirExists:true,ideProcessesRunning:3,agentProcessesRunning:1,acpReloadAvailable:true,acpReconnectAvailable:false},
   proxy:{systemProxyEnabled:false,systemProxyServer:null,systemProxyListening:null,pacConfigured:true,pacActive:true,pacTarget:'http://127.0.0.1:9/pac',pacListening:false,envProxies:[],devinSettingsProxy:null,devinAgentEnvKeys:[],confirmedProxyIssue:true,stalePacConfirmed:false,ineffectiveProxyConfirmed:false,listeningLocalPorts:[7897]},
   network:[{host:'server.codeium.com',dnsOk:true,resolvedIp:'104.18.0.1',tcp:{attempts:2,successes:2,minMs:10,maxMs:20},tls:{attempts:2,successes:2,minMs:40,maxMs:60},classification:'healthy',path:'direct',riskNote:null}],
   logs:{logDir:'C:\\synthetic\\logs',totalLogFiles:5,logsExamined:5,agentStarts:2,authenticateAttempts:2,authenticateWithCredentials:2,teamSettingsFailures:1,timeoutFailures:0,zdrTimeouts:0,remoteConfigFailures:0,lastFailureAt:'2026-10-17 10:00',agentVersions:['1.126'],runningAgentPids:[1234],runningAgentsAuthenticated:false,newestLogHasAuthFailure:true,failureCategories:['auth_failed']},
   summary:{category:'代理配置问题',confidence:'高',overview:'合成：PAC 生效且目标不可达',recommendedFixes:[{id:'clear_stale_pac_config',label:'查看 PAC 清除指引',requiresRestart:false,affectsLogin:false,manual:true},{id:'reload_acp_connections',label:'重新加载 ACP 连接',requiresRestart:false,affectsLogin:false,manual:true},{id:'apply_client_proxy_fix',label:'写入客户端代理设置',requiresRestart:false,affectsLogin:false,manual:false},{id:'restart_devin_client',label:'重启官方客户端',requiresRestart:true,affectsLogin:false,manual:false}]}});
  window.__TAURI_INTERNALS__ = { invoke: async (cmd,args) => {
   const f=window.uiFixture; f.calls.push(cmd);
   if(cmd==='list_windsurf_accounts') {if(sessionStorage.getItem('failList')) throw new Error('synthetic storage error');return [...f.accounts];}
   if(cmd==='get_client_status' && sessionStorage.getItem('failClient'))throw new Error('synthetic client status failure');
   if(cmd==='get_client_status')return {installed:true,appPath:'E:\\Devin\\Devin.exe',currentAccountId:'demo-2',dataDir:'Synthetic UI fixture'};
   if(cmd==='refresh_windsurf_token') {if(f.refreshDelay)await new Promise(r=>setTimeout(r,f.refreshDelay));if(args.accountId==='demo-3' || args.accountId===f.failAccount) throw new Error('Synthetic refresh failure');return f.accounts.find(a=>a.id===args.accountId);}
   if(cmd==='windsurf_oauth_login_start')return {loginId:'synthetic-login',expiresIn:30};
   if(cmd==='windsurf_oauth_login_poll')return null;
   if(cmd==='windsurf_oauth_login_cancel')return;
   if(cmd==='get_recovery_status')return {available:true,pending:sessionStorage.getItem('pendingSwitch')==='true',createdAt:now,legacyCount:f.legacyCount};
   if(cmd==='restore_last_client_state'){if(sessionStorage.getItem('failRestore'))throw new Error('Synthetic restore refused before writes');sessionStorage.removeItem('pendingSwitch');return '已恢复上一次切换前的数据库，请在客户端确认账号。';}
   if(cmd==='cleanup_legacy_client_backups'){f.legacyCount=0;return 2;}
   if(cmd==='get_oauth_login_phase')return 'verifying';
   if(cmd==='set_client_path')return;
   if(cmd==='import_cockpit_accounts')return {imported:1,skipped:1,failed:0};
   if(cmd==='add_windsurf_account_with_token' || cmd==='add_windsurf_account_with_password' || cmd==='import_windsurf_from_json')return [];
   if(cmd==='delete_windsurf_account'){f.accounts=f.accounts.filter(a=>a.id!==args.accountId);return;}
   if(cmd==='plugin:event|listen'||cmd==='plugin:event|unlisten')return 0;
   if(cmd==='get_rotation_status'){const base=f.rotation?JSON.parse(JSON.stringify(f.rotation)):{config:mockRotationCfg(),mode:'off',paused:false,thresholdPercent:10,pollIntervalSecs:60,enabledPool:[],scanning:false,monitoringActive:false,consecutiveFailures:0,snapshots:[]};if(sessionStorage.getItem('manualAwaiting'))base.lastDecision={kind:'recommendation',reasons:['manual_switch'],target:{accountId:sessionStorage.getItem('manualAwaiting'),minApplicablePercent:0,crossOrg:false},suggestionId:'manual-1',expiresAtMs:Date.now()+600000,requiresConfirmation:true,resolution:'awaiting_client'};return base;}
   if(cmd==='set_rotation_config'||cmd==='pause_rotation'||cmd==='resume_rotation')return {config:args?.config||mockRotationCfg(),mode:args?.config?.mode||'off',paused:cmd==='pause_rotation',thresholdPercent:10,pollIntervalSecs:60,enabledPool:[],scanning:false,monitoringActive:false,consecutiveFailures:0,snapshots:[]};
   if(cmd==='scan_rotation_now'){f.rotation={config:{...mockRotationCfg(),mode:'smart_confirm',enabledPool:['demo-2','demo-3']},mode:'smart_confirm',paused:false,thresholdPercent:10,pollIntervalSecs:60,enabledPool:['demo-2','demo-3'],scanning:false,monitoringActive:true,consecutiveFailures:0,lastDecision:{kind:'recommendation',reasons:['low_quota_confirmed'],target:{accountId:'demo-3',orgId:'org-b',minApplicablePercent:88,crossOrg:true},suggestionId:'sug-ui',expiresAtMs:Date.now()+60000,requiresConfirmation:true},snapshots:[{accountId:'demo-3',orgId:'org-b',minApplicablePercent:88,queriedAtMs:Date.now(),confidence:'verified',healthy:true}]};return f.rotation;}
   if(cmd==='confirm_rotation'){f.calls.push('confirm_rotation:'+(args.switchMethod||'standard'));const native=args.switchMethod==='native';if(f.rotation?.lastDecision)f.rotation.lastDecision.resolution=native?'awaiting_client':'verified';return {targetAccountId:args.targetAccountId,adapter:native?'native':'safe_restart',restartRequired:!native,localMatch:native?'not_attempted':'passed',clientRecognized:'not_attempted',remoteVerified:'not_attempted',rollback:'not_needed',message:native?'已确认 Devin 收到官方登录请求。此版本客户端可能直接静默登录而无确认框；请稍候点击「验证生效」核对身份。':'已写入目标账号并启动客户端，请在 Devin Desktop 确认账号及服务连接。'};}
   if(cmd==='try_native_switch'){if(sessionStorage.getItem('failNative'))throw new Error('synthetic native launch failure');if(sessionStorage.getItem('manualAwaiting'))throw new Error('已有切换等待官方客户端确认，请先验证或关闭后再发起');sessionStorage.setItem('manualAwaiting',args.accountId);return {targetAccountId:args.accountId,adapter:'native',restartRequired:false,localMatch:'not_attempted',clientRecognized:'not_attempted',remoteVerified:'not_attempted',rollback:'not_needed',message:'已向 Devin 发起官方登录请求，请在客户端弹出的确认框中确认。'};}
   if(cmd==='verify_native_login'){
    if(f.nativeVerifyUnavailableOnce){f.nativeVerifyUnavailableOnce=false;return {state:'verified',sessionLabel:'Synthetic switched account',remoteStatus:'unavailable'};}
    return f.nativeVerifySuccess ? {state:'verified',sessionLabel:'Synthetic switched account',remoteStatus:'passed'} : {state:'pending'};
   }
   if(cmd==='dismiss_rotation'){if(f.rotation)f.rotation.lastDecision=undefined;sessionStorage.removeItem('manualAwaiting');return;}
   if(cmd==='get_last_diagnostics')return f.lastDiag||null;
   if(cmd==='run_connection_diagnostics'){f.lastDiag=mockDiag();return f.lastDiag;}
   if(cmd==='preview_diagnostics_report')return '# 诊断报告预览（合成）\n- 代理异常：已确认\n- 敏感信息已脱敏\n';
   if(cmd==='export_diagnostics_report')return 'C:\\synthetic\\diagnostics-report.md';
   if(cmd==='get_proxy_fix_state')return f.fixState||null;
   if(cmd==='apply_client_proxy_fix'){if(sessionStorage.getItem('failProxyFix'))throw new Error('Synthetic proxy handshake refused');f.fixState={writtenValue:'http://127.0.0.1:'+args.port,previousValue:'http://127.0.0.1:7890',writtenAtMs:Date.now(),settingsPath:'C:\\synthetic\\settings.json',backupPath:'C:\\synthetic\\backup.json'};return {settingsPath:'C:\\synthetic\\settings.json',newProxy:'http://127.0.0.1:'+args.port,backupPath:'C:\\synthetic\\backup.json',legacyNestedProxyPresent:false,writeVerified:true,statePath:'C:\\synthetic\\proxy-fix-state.json'};}
   if(cmd==='revert_client_proxy_fix'){if(!f.fixState)throw new Error('没有本工具写入的代理修改记录');const prev=f.fixState.previousValue;f.fixState=null;return {settingsPath:'C:\\synthetic\\settings.json',newProxy:prev?'已恢复为 '+prev:'(已移除)',backupPath:'C:\\synthetic\\backup.json',legacyNestedProxyPresent:false,writeVerified:true,statePath:''};}
   if(cmd==='record_recovery_feedback'){f.calls.push('feedback:'+args.verdict);return;}
   if(cmd==='clear_stale_pac_config')return {performed:false,applicable:true,steps:['Win+R 运行 inetcpl.cpl','连接 → 局域网设置','取消勾选「使用自动配置脚本」'],note:'本工具不修改注册表'};
   if(cmd==='export_account_credentials'){if(!args.confirmed)throw new Error('confirmation required');if(sessionStorage.getItem('failCredentialExport'))throw new Error('Synthetic export failure');f.calls.push('credential-export:'+args.format+':'+args.accountIds.length);return {path:'C:/synthetic/credentials.'+args.format,count:args.accountIds.length,format:args.format,shortLivedCount:args.format==='txt'?1:0};}
   if(cmd==='open_account_exports_folder'){f.calls.push('credential-folder-open');return;}
   if(cmd==='export_devin_logs'){if(sessionStorage.getItem('failLogExport'))throw new Error('Synthetic log export failed');return {archivePath:'C:/synthetic/logs.zip',folderPath:'C:/synthetic/logs',files:4,truncatedFiles:1,skippedFiles:2};}
   if(cmd==='open_log_export_folder'){f.calls.push('log-folder-open');return;}
   if(cmd==='complete_restart_devin'){if(!args.confirmed)throw new Error('confirmation required');f.calls.push('forced-restart-confirmed');if(sessionStorage.getItem('failForceRestart'))throw new Error('Synthetic multi-profile refusal');return {message:'已完成进程彻底重启，请核对模型',terminatedProcesses:3,logExport:{archivePath:'C:/synthetic/pre-restart.zip',folderPath:'C:/synthetic/pre-restart',files:3,truncatedFiles:0,skippedFiles:0}};}
   if(cmd==='open_client_for_diagnostics'){f.calls.push('diagnostic-client-open');return;}
   if(cmd==='open_project_link'){f.calls.push('project-link:'+args.destination);if(sessionStorage.getItem('failProjectLink'))throw new Error('Synthetic browser unavailable');return;}
   if(cmd==='restart_devin_client')return '客户端已正常关闭并重新启动，agent 子进程将重新认证。';
   throw new Error('Unexpected mock command: '+cmd);
  }};
 });
 await page.goto('http://127.0.0.1:1420');
 await page.locator('.account').first().waitFor();
 assert.equal(await page.locator('.account').count(),3);
 const card = await page.locator('.account').first().boundingBox();assert.ok(card.width >= 260 && card.width < 310);assert.ok(card.height >= 350 && card.height < 460);
 assert.equal(await page.locator('.quota-reset summary').count(),0);
 const firstRow=await page.locator('.account').evaluateAll(nodes=>nodes.map(n=>n.getBoundingClientRect().top));assert.equal(new Set(firstRow).size,1);
 await page.evaluate(()=>{const base=window.uiFixture.accounts.slice();window.uiFixture.accounts=[...base,...base.map(a=>({...a,id:a.id+'-extra',github_name:'Extended '+a.github_name,github_email:'a-long-account-name@subdomain.example.invalid'}))];});
 await page.getByRole('button',{name:'刷新全部',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('.account').length===6);
 const rows=await page.locator('.account').evaluateAll(nodes=>nodes.map(n=>Math.round(n.getBoundingClientRect().top)));assert.equal(new Set(rows).size,2);
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.getByRole('button',{name:'关闭提示',exact:true}).click();await page.screenshot({path:'docs/ui-0.4.0-six-accounts.png',fullPage:true});
 await page.reload();await page.locator('.account').first().waitFor();
 await page.setViewportSize({width:1000,height:780});assert.equal(await page.locator('.accounts.grid').evaluate(n=>getComputedStyle(n).gridTemplateColumns.split(' ').length),2);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.setViewportSize({width:1120,height:780});

 assert.equal(await page.locator('.overview, .client-bar').count(),0);
 assert.match(await page.locator('.account').first().innerText(), /Design Studio/);
 assert.match(await page.locator('.account').first().innerText(), /剩余 75%/);
 assert.match(await page.locator('.account').filter({hasText:'Alex Chen'}).innerText(), /剩余 38 \/ 50/);
 assert.match(await page.locator('.account').filter({hasText:'Personal'}).innerText(), /暂无额度数据/);
 // Card-level experimental native-switch entry: visible alongside standard switch
 // on non-current cards only; gated by an experimental confirmation.
 const demo1=page.locator('.account').filter({hasText:'Alex Chen'});
 assert.equal(await demo1.getByRole('button',{name:'切换账号',exact:true}).count(),1);
 assert.equal(await demo1.getByRole('button',{name:'免重启',exact:true}).count(),1);
 assert.equal(await page.locator('.account').filter({hasText:'Design Studio'}).getByRole('button',{name:'免重启',exact:true}).count(),0);
 // Accounts without URI-compatible credentials are labeled upfront, not only
// after a failed launch: badge + disabled native action, standard kept.
const demo3card=page.locator('.account').filter({hasText:'Personal'});
await demo3card.getByText(/暂不支持免重启/).waitFor();
assert.equal(await demo3card.getByRole('button',{name:'免重启',exact:true}).isDisabled(),true);
assert.equal(await demo3card.getByRole('button',{name:'切换账号',exact:true}).isEnabled(),true);
const nativeDlg=page.getByRole('dialog');
 // One card click sends exactly one request, without a second manager confirmation.
 const beforeOneClick=await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='try_native_switch').length);
 // Same-tick double activation must still dispatch just one request.
 await demo1.getByRole('button',{name:'免重启',exact:true}).evaluate(button=>{button.click();button.click();});
 await nativeDlg.getByText(/官方登录请求/).waitFor();
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='try_native_switch').length),beforeOneClick+1);
 assert.equal(await nativeDlg.getByRole('button',{name:'尝试免重启切换',exact:true}).count(),0);
 await nativeDlg.getByText(/不代表切换成功/).waitFor();
 await nativeDlg.getByRole('button',{name:'验证生效',exact:true}).click();
 await nativeDlg.getByText(/尚未确认生效/).waitFor();
 await page.evaluate(()=>{window.uiFixture.nativeVerifySuccess=true;});
 await nativeDlg.waitFor({state:'hidden'});
 await page.getByText('账号切换已核对，服务端已接受当前会话。',{exact:true}).waitFor();
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='try_native_switch').length),beforeOneClick+1);
 await page.evaluate(()=>{window.uiFixture.nativeVerifySuccess=false;});
 await page.getByRole('button',{name:'关闭提示',exact:true}).click();
 // Failure path: a failed launch (with no in-flight record) shows the error
 // and offers no verify button — it must not silently close or fall through
 // to a restart.
 await page.evaluate(()=>sessionStorage.removeItem('manualAwaiting'));
 await page.evaluate(()=>sessionStorage.setItem('failNative','1'));
 await demo1.getByRole('button',{name:'免重启',exact:true}).click();
 await nativeDlg.getByText(/synthetic native launch failure/).waitFor();
 assert.equal(await nativeDlg.getByRole('button',{name:'验证生效',exact:true}).count(),0);
 await nativeDlg.getByRole('button',{name:'关闭',exact:true}).click();
 await page.evaluate(()=>sessionStorage.removeItem('failNative'));
 assert.equal(await page.evaluate(()=>document.querySelectorAll('.modal').length),0);
 // After a successful manual launch the durable awaiting record must surface
 // the banner entry (verify/dismiss) on next status load — closing the modal
 // must not strand the operation.
 await demo1.getByRole('button',{name:'免重启',exact:true}).click();
 await nativeDlg.getByText(/官方登录请求/).waitFor();
 await nativeDlg.getByRole('button',{name:'关闭',exact:true}).click();
 await page.reload();await page.locator('.account').first().waitFor();
 const manualBanner=page.locator('.client-warning').filter({hasText:'免重启切换（实验性）'});
 await manualBanner.waitFor();await manualBanner.getByText(/不代表切换成功/).waitFor();
 await manualBanner.getByRole('button',{name:'验证生效',exact:true}).click();
 await manualBanner.getByText(/请在 Devin 确认框中点击确认后再验证/).waitFor();
 // Automatic read-only verification must detect completion without a
 // second click or another URI launch.
 const launchesBeforeAuto=await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='try_native_switch').length);
 await page.evaluate(()=>{window.uiFixture.nativeVerifySuccess=true;window.uiFixture.nativeVerifyUnavailableOnce=true;});
 await manualBanner.getByText(/服务端已接受当前会话令牌/).waitFor();
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='try_native_switch').length),launchesBeforeAuto);
 await page.evaluate(()=>{window.uiFixture.nativeVerifySuccess=false;});
 await manualBanner.getByRole('button',{name:'关闭',exact:true}).click();
 await manualBanner.waitFor({state:'hidden'});
// Blocked-launch reconcile: a stale awaiting record must surface inside the
// modal (verify + abandon), not dead-end with only a close button.
await demo1.getByRole('button',{name:'免重启',exact:true}).click();
await nativeDlg.getByText(/官方登录请求/).waitFor();
await nativeDlg.getByRole('button',{name:'关闭',exact:true}).click();
await demo1.getByRole('button',{name:'免重启',exact:true}).click();
await nativeDlg.getByText(/仍在等待核对/).waitFor();
await nativeDlg.getByText(/没有向 Devin 发送任何请求/).waitFor();
await nativeDlg.getByRole('button',{name:'放弃并重试',exact:true}).click();
await nativeDlg.getByText(/官方登录请求/).waitFor();
await nativeDlg.getByRole('button',{name:'关闭',exact:true}).click();
await page.evaluate(()=>sessionStorage.removeItem('manualAwaiting'));
// Saved switch method drives the primary card button: with 'native' saved,
// 免重启切换 becomes primary and the standard restart path stays secondary.
await page.evaluate(()=>localStorage.setItem('devin.switchMethod','native'));
await page.reload();await page.locator('.account').first().waitFor();
const demo1native=page.locator('.account').filter({hasText:'Alex Chen'});
assert.equal(await demo1native.getByRole('button',{name:'免重启切换',exact:true}).count(),1);
assert.equal(await demo1native.getByRole('button',{name:'标准切号',exact:true}).count(),1);
assert.match(await page.locator('.section-heading').innerText(),/免重启（实验性）/);
await page.evaluate(()=>localStorage.setItem('devin.switchMethod','standard'));
await page.reload();await page.locator('.account').first().waitFor();
 await page.getByRole('button',{name:'应用设置',exact:true}).click();
 assert.equal(await page.getByRole('dialog').count(),0);
 await page.getByRole('tab',{name:'通用',exact:true}).waitFor();
 assert.ok((await page.getByRole('button',{name:'应用设置',exact:true}).boundingBox()).y > 650);
 await page.screenshot({path:'docs/ui-0.4.0-settings.png',fullPage:true});
 await page.getByRole('switch',{name:'减少动画',exact:true}).check();assert.equal(await page.locator('html').getAttribute('data-reduced-motion'),'true');
 await page.getByRole('switch',{name:'隐藏账号信息',exact:true}).check();await page.getByRole('switch',{name:'隐藏账号信息',exact:true}).uncheck();
 await page.getByRole('combobox',{name:'默认显示方式'}).selectOption('list');await page.getByRole('combobox',{name:'默认显示方式'}).selectOption('grid');
 await page.getByRole('tab',{name:'客户端',exact:true}).click();
 await page.getByText('Devin Desktop 已就绪',{exact:true}).waitFor();
// Switch method setting: standard is the default; native is experimental opt-in.
const methodSel=page.getByRole('combobox',{name:'切号方式'});
await methodSel.waitFor();
assert.equal(await methodSel.inputValue(),'standard');
await page.getByText('当前：标准切号（重启）',{exact:false}).waitFor();
await methodSel.selectOption('native');
await page.getByText('当前：尝试免重启（实验性）',{exact:false}).waitFor();
assert.equal(await page.evaluate(()=>localStorage.getItem('devin.switchMethod')),'native');
await methodSel.selectOption('standard');
 await page.getByRole('textbox',{name:'客户端程序完整路径'}).fill('E:\\Devin\\Devin.exe');await page.getByRole('button',{name:'保存路径',exact:true}).click();await page.getByText('客户端路径已保存。',{exact:true}).waitFor();await page.getByRole('button',{name:'关闭提示',exact:true}).click();await page.screenshot({path:'docs/ui-0.4.0-settings-client.png',fullPage:true});
 await page.locator('.sidebar .nav-item').first().click();
 await page.getByRole('button',{name:'导出 Token',exact:true}).click();
 await page.getByRole('heading',{name:'导出账号与 Token',exact:true}).waitFor();
 await page.getByRole('button',{name:'应用设置',exact:true}).click();
 await page.getByRole('tab',{name:'客户端',exact:true}).click();
 // Diagnostics has its own sidebar page, not the bottom of client settings.
 assert.equal(await page.getByRole('heading',{name:'模型列表诊断与恢复',exact:true}).count(),0);
 await page.getByRole('button',{name:'诊断与恢复',exact:true}).click();
 await page.getByRole('heading',{name:'诊断与恢复',exact:true}).waitFor();
 const forceButton=page.getByRole('button',{name:'导出日志并彻底重启',exact:true});
 assert.equal(await forceButton.isDisabled(),true);
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='forced-restart-confirmed').length),0);
 await page.evaluate(()=>sessionStorage.setItem('failLogExport','true'));
 await page.getByRole('button',{name:'导出 Devin 日志包',exact:true}).click();
 await page.getByText(/Synthetic log export failed/).waitFor();
 await page.evaluate(()=>sessionStorage.removeItem('failLogExport'));
 await page.getByRole('button',{name:'导出 Devin 日志包',exact:true}).click();
 await page.getByText('C:/synthetic/logs.zip',{exact:true}).waitFor();
 await page.getByRole('button',{name:'打开日志目录',exact:true}).click();
 assert.ok(await page.evaluate(()=>window.uiFixture.calls.includes('log-folder-open')));
 await page.getByText('我已保存工作，确认允许强制结束进程及中断终端、AI 任务',{exact:true}).click();
 await page.evaluate(()=>sessionStorage.setItem('failForceRestart','true'));
 await forceButton.click();await page.getByText(/Synthetic multi-profile refusal/).waitFor();
 assert.equal(await forceButton.isDisabled(),true);
 await page.evaluate(()=>sessionStorage.removeItem('failForceRestart'));
 await page.getByText('我已保存工作，确认允许强制结束进程及中断终端、AI 任务',{exact:true}).click();
 await forceButton.click();await page.getByText(/已完成进程彻底重启，请核对模型/).waitFor();
 assert.equal(await forceButton.isDisabled(),true);
 // Diagnostics & recovery: read-only scan, preview, confirm gates, verdict feedback.
 await page.getByRole('button',{name:'开始诊断',exact:true}).click();
 await page.getByText('已确认异常（1 项）',{exact:true}).waitFor();
 assert.equal(await page.locator('.diag-metric').count(),3);
 assert.equal(await page.getByRole('textbox',{name:'本机代理端口'}).inputValue(),'');
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.filter(c=>['apply_client_proxy_fix','restart_devin_client','revert_client_proxy_fix'].includes(c)).length),0);
 await page.getByRole('button',{name:'预览报告',exact:true}).click();
 await page.locator('.diag-preview').waitFor();assert.match(await page.locator('.diag-preview').innerText(),/诊断报告预览/);
 assert.equal(await page.getByRole('textbox',{name:'ACP 重载命令'}).inputValue(),'Reload ACP Connections');
 await page.context().grantPermissions(['clipboard-read','clipboard-write'],{origin:'http://127.0.0.1:1420'});
 await page.getByRole('button',{name:'复制命令',exact:true}).click();
 await page.getByText(/命令已复制/).waitFor();
 assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),'Reload ACP Connections');
 await page.getByRole('button',{name:'打开 Devin',exact:true}).click();
 await page.getByText(/已请求打开 Devin/).waitFor();
 assert.ok(await page.evaluate(()=>window.uiFixture.calls.includes('diagnostic-client-open')));
 assert.equal(await page.getByText('PAC 自动配置脚本',{exact:true}).count(),1);
 const applyBtn=page.getByRole('button',{name:'写入客户端代理设置',exact:true});
 await applyBtn.waitFor();assert.equal(await applyBtn.isDisabled(),true);
 await page.getByRole('textbox',{name:'本机代理端口'}).fill('7897');
 assert.equal(await applyBtn.isDisabled(),true);
 await page.getByText('我确认该端口是本机代理软件的实际代理端口').click();
 await page.evaluate(()=>sessionStorage.setItem('failProxyFix','true'));
 await applyBtn.click();await page.getByText('Error: Synthetic proxy handshake refused',{exact:true}).waitFor();
 await page.evaluate(()=>sessionStorage.removeItem('failProxyFix'));
 await applyBtn.click();await page.getByText(/已写入 http:\/\/127\.0\.0\.1:7897/).waitFor();
 const revertBtn=page.getByRole('button',{name:'撤销本次修改',exact:true});await revertBtn.waitFor();
 assert.equal(await applyBtn.isDisabled(),true,'未撤销修改期间不能重复写入代理');
 // Revert restores the original value recorded in persisted state, not a bare delete.
 await page.getByText(/撤销将恢复原值 http:\/\/127\.0\.0\.1:7890/).waitFor();
 await page.getByRole('button',{name:'已显示且消息正常',exact:true}).waitFor();
 await revertBtn.click();await page.getByText(/已撤销本次修改：http\.proxy 已恢复为 http:\/\/127\.0\.0\.1:7890/).waitFor();
 await page.getByRole('button',{name:'仍未恢复',exact:true}).click();await page.getByText(/本次恢复未解决问题/).waitFor();
 const restartBtn=page.getByRole('button',{name:'重启官方客户端',exact:true});
 assert.equal(await restartBtn.isDisabled(),true);
 await page.getByText('我已保存工作',{exact:true}).click();assert.equal(await restartBtn.isDisabled(),false);
 await restartBtn.click();await page.getByText(/agent 子进程将重新认证/).waitFor();
 await page.getByRole('button',{name:'已显示且消息正常',exact:true}).click();await page.getByText(/用户确认模型列表恢复/).waitFor();
 assert.ok(await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='feedback:confirmed'||c==='feedback:unresolved').length>=2));
 await page.getByRole('button',{name:'应用设置',exact:true}).click();
 await page.getByRole('tab',{name:'数据管理',exact:true}).click();await page.getByText('Synthetic UI fixture',{exact:true}).waitFor();await page.screenshot({path:'docs/ui-0.4.0-settings-data.png',fullPage:true});
 // Explicit credential export writes a file; IPC/UI never receives token text.
 const exportFileButton=page.getByRole('button',{name:'确认导出文件',exact:true});
 assert.equal(await exportFileButton.isDisabled(),true);
 const exportCalls=await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='export_account_credentials').length);
 await page.getByRole('button',{name:'全选账号',exact:true}).click();
 assert.equal(await exportFileButton.isDisabled(),true);
 await page.getByText('我了解导出文件含明文登录凭据，只用于本人授权账号的备份或迁移，并会妥善保管',{exact:true}).click();
 await page.evaluate(()=>sessionStorage.setItem('failCredentialExport','true'));
 await exportFileButton.click();await page.getByText(/Synthetic export failure/).waitFor();
 assert.equal(await exportFileButton.isDisabled(),true);
 await page.evaluate(()=>sessionStorage.removeItem('failCredentialExport'));
 await page.getByText('我了解导出文件含明文登录凭据，只用于本人授权账号的备份或迁移，并会妥善保管',{exact:true}).click();
 await exportFileButton.click();await page.getByText('C:/synthetic/credentials.json',{exact:true}).waitFor();
 await page.getByRole('button',{name:'打开账号导出目录',exact:true}).click();
 assert.ok(await page.evaluate(()=>window.uiFixture.calls.includes('credential-folder-open')));
 await page.getByLabel('文件格式',{exact:true}).selectOption('txt');
 assert.equal(await exportFileButton.isDisabled(),true);
 await page.getByText('我了解导出文件含明文登录凭据，只用于本人授权账号的备份或迁移，并会妥善保管',{exact:true}).click();
 await exportFileButton.click();await page.getByText('C:/synthetic/credentials.txt',{exact:true}).waitFor();
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='export_account_credentials').length),exportCalls+3);
 await page.setViewportSize({width:720,height:900});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.setViewportSize({width:1120,height:780});
 const restoresBefore=await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='restore_last_client_state').length);
 await page.getByRole('button',{name:'恢复上次状态',exact:true}).click();await page.getByRole('dialog').getByRole('button',{name:'取消',exact:true}).click();assert.equal(await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='restore_last_client_state').length),restoresBefore);
 await page.evaluate(()=>sessionStorage.setItem('failRestore','true'));await page.getByRole('button',{name:'恢复上次状态',exact:true}).click();await page.getByRole('button',{name:'确认恢复',exact:true}).click();await page.getByRole('dialog').getByText('Error: Synthetic restore refused before writes',{exact:true}).waitFor();await page.keyboard.press('Escape');await page.evaluate(()=>sessionStorage.removeItem('failRestore'));
 await page.getByRole('button',{name:'恢复上次状态',exact:true}).click();await page.getByRole('button',{name:'确认恢复',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});await page.getByRole('button',{name:'关闭提示',exact:true}).click();
 await page.getByRole('button',{name:'清理旧版备份',exact:true}).click();await page.getByRole('button',{name:'确认清理',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});assert.equal(await page.getByRole('button',{name:'清理旧版备份',exact:true}).isDisabled(),true);await page.getByRole('button',{name:'关闭提示',exact:true}).click();
 await page.getByRole('button',{name:'导入账号',exact:true}).click();await page.getByRole('tab',{name:'本地迁移',exact:true}).waitFor();await page.keyboard.press('Escape');
 await page.getByRole('tab',{name:'关于',exact:true}).click();await page.getByText('v0.5.1',{exact:true}).waitFor();assert.equal(await page.getByRole('link',{name:/开源仓库/}).getAttribute('href'),'https://github.com/axinlab71/devin-account-manager');await page.screenshot({path:'docs/ui-0.4.0-about.png',fullPage:true});
 await page.getByRole('link',{name:/开源仓库/}).click();
 assert.ok(await page.evaluate(()=>window.uiFixture.calls.includes('project-link:repository')));
 await page.evaluate(()=>sessionStorage.setItem('failProjectLink','true'));
 await page.getByRole('link',{name:/意见反馈/}).click();
 await page.getByText(/Synthetic browser unavailable/).waitFor();
 await page.evaluate(()=>sessionStorage.removeItem('failProjectLink'));
 assert.equal(await page.locator('img[src*="support/"]').count(),0,'二维码仅在 README 展示');
 // Rotation tab: status line, pool layout with 全选/清空, dirty-scan hint, concise save feedback.
 await page.getByRole('tab',{name:'额度轮换',exact:true}).click();await page.getByText('额度监控',{exact:true}).waitFor();
 await page.getByText(/已关闭|运行中|已暂停/).waitFor();
 await page.getByText(/已保存备用账号 0 个/).waitFor();
 assert.equal(await page.getByRole('combobox',{name:'监控模式'}).locator('option[value="auto"]').isDisabled(),true);
 // Enabling monitoring is an explicit save+resume operation, never a switch.
 await page.getByRole('combobox',{name:'监控模式'}).selectOption('smart_confirm');
 await page.getByText(/尚未选择备用账号/).waitFor();
 await page.getByRole('combobox',{name:'监控模式'}).selectOption('notify_only');
 const switchesBeforeEnable=await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='try_native_switch'||c.startsWith('confirm_rotation:')).length);
 await page.getByRole('button',{name:'保存并启用监控',exact:true}).click();
 await page.getByText(/监控已启用；低额度需经两次扫描确认/).waitFor();
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.includes('resume_rotation')),true);
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='try_native_switch'||c.startsWith('confirm_rotation:')).length),switchesBeforeEnable);
 await page.getByText('切号方式',{exact:true}).waitFor();
 // Pool: full-width rows with select-all/clear and a live selected count.
 await page.getByRole('button',{name:'全选',exact:true}).click();
 await page.getByText('已选 3 个',{exact:true}).waitFor();
 assert.equal(await page.locator('.pool-row').count(),3);
 assert.match(await page.getByRole('button',{name:/立即扫描/}).innerText(),/使用已保存设置/);
 await page.getByRole('button',{name:'清空',exact:true}).click();
 await page.getByText('已选 0 个',{exact:true}).waitFor();
 await page.getByRole('button',{name:'保存设置',exact:true}).click();await page.getByText(/已保存，备用账号 \d+ 个/).waitFor();
 await page.getByRole('button',{name:/立即扫描/}).click();
 await page.locator('.sidebar .nav-item').first().click();
 const banner=page.locator('.client-warning').filter({hasText:'建议切换到'});
 await banner.waitFor();assert.match(await banner.innerText(),/不同组织/);
 // Rotation confirm honors the switch-method setting: default 'standard'
 // dispatches the restart path, not the experimental URI adapter.
 await banner.getByText('将使用标准切号',{exact:false}).waitFor();
 await banner.getByRole('button',{name:'切换到此账号',exact:true}).click();await banner.getByText(/已写入目标账号并启动客户端/).waitFor();
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.includes('confirm_rotation:standard')),true);
 assert.equal(await banner.getByRole('button',{name:'验证生效',exact:true}).count(),0);
 await banner.getByRole('button',{name:'关闭',exact:true}).click();await banner.waitFor({state:'hidden'});
 // Same recommendation confirmed under 'native' dispatches the URI adapter.
 await page.getByRole('button',{name:'应用设置',exact:true}).click();await page.getByRole('tab',{name:'客户端',exact:true}).click();
 await page.getByRole('combobox',{name:'切号方式'}).selectOption('native');
 await page.getByRole('tab',{name:'额度轮换',exact:true}).click();await page.getByRole('button',{name:/立即扫描/}).click();
 await page.locator('.sidebar .nav-item').first().click();
 const banner2=page.locator('.client-warning').filter({hasText:'建议切换到'});
 await banner2.waitFor();await banner2.getByText('将尝试免重启',{exact:false}).waitFor();
 await banner2.getByRole('button',{name:'切换到此账号',exact:true}).click();await banner2.getByText(/官方登录请求/).waitFor();
 assert.equal(await page.evaluate(()=>window.uiFixture.calls.includes('confirm_rotation:native')),true);
 await banner2.getByRole('button',{name:'验证生效',exact:true}).click();await banner2.getByText(/请在 Devin 确认框中点击确认后再验证/).waitFor();
 await banner2.getByRole('button',{name:'关闭',exact:true}).click();await banner2.waitFor({state:'hidden'});
 await page.getByRole('button',{name:'应用设置',exact:true}).click();await page.getByRole('tab',{name:'客户端',exact:true}).click();
 await page.getByRole('combobox',{name:'切号方式'}).selectOption('standard');
 await page.locator('.sidebar .nav-item').first().click();
 await page.getByRole('button',{name:'应用设置',exact:true}).click();await page.getByRole('tab',{name:'关于',exact:true}).click();
 await page.getByRole('tab',{name:'关于',exact:true}).press('Home');assert.equal(await page.getByRole('tab',{name:'通用',exact:true}).getAttribute('aria-selected'),'true');
 await page.locator('.sidebar .nav-item').first().click();
 await page.locator('h1').click();
 await page.screenshot({path:'docs/ui-0.4.0-light.png',fullPage:true});
 await page.getByRole('textbox',{name:'搜索账号'}).fill('alex@');assert.equal(await page.locator('.account').count(),1);
 await page.getByRole('button',{name:'清空搜索'}).click();
 await page.getByRole('combobox',{name:'筛选账号'}).selectOption('attention');assert.equal(await page.locator('.account').count(),1);
 await page.getByRole('combobox',{name:'筛选账号'}).selectOption('all');
 await page.getByRole('button',{name:'隐藏账号信息'}).click();assert.equal(await page.locator('.account').filter({hasText:'alex@example.com'}).count(),0);
 await page.getByRole('button',{name:'显示账号信息'}).click();
 await page.getByRole('button',{name:'列表视图',exact:true}).click(); assert.equal(await page.locator('.accounts.list').count(),1);
 await page.getByRole('button',{name:'应用设置',exact:true}).click();await page.getByRole('button',{name:'切换深色主题'}).click();await page.screenshot({path:'docs/ui-0.4.0-settings-dark.png',fullPage:true});await page.locator('.sidebar .nav-item').first().click();await page.screenshot({path:'docs/ui-0.4.0-dark-list.png',fullPage:true});
 await page.getByRole('button',{name:'添加账号',exact:true}).click();
 assert.equal(await page.getByRole('dialog').count(),1);
 await page.keyboard.press('Shift+Tab');
 assert.equal(await page.evaluate(()=>document.activeElement.textContent.includes('导入本机账号')),true);
 await page.keyboard.press('Tab');
 assert.equal(await page.evaluate(()=>document.activeElement.getAttribute('aria-label')),'关闭弹窗');
 await page.screenshot({path:'docs/ui-0.4.0-auth.png',fullPage:true});
 await page.getByRole('button',{name:'开始网页授权',exact:true}).click();
 await page.getByRole('button',{name:'取消本次授权'}).waitFor();await page.getByRole('heading',{name:'已收到授权，正在处理凭据',exact:true}).waitFor();
 assert.equal(await page.getByRole('button',{name:'关闭弹窗'}).isDisabled(),true);
 await page.getByRole('button',{name:'取消本次授权'}).click();
 await page.getByRole('button',{name:'开始网页授权',exact:true}).waitFor({state:'visible'});
 await page.waitForFunction(()=>!document.querySelector('button[aria-label="关闭弹窗"]').disabled);
 await page.getByRole('tab',{name:'Token / JSON'}).click();assert.equal(await page.getByRole('textbox',{name:'Token / JSON 凭据'}).count(),1);
 await page.getByRole('tab',{name:'本地迁移'}).click();assert.equal(await page.getByRole('button',{name:'导入 Cockpit 账号',exact:true}).count(),1);await page.screenshot({path:'docs/ui-0.4.0-migration.png',fullPage:true});await page.getByRole('button',{name:'导入 Cockpit 账号',exact:true}).click();await page.waitForFunction(()=>window.uiFixture.calls.includes('import_cockpit_accounts'));await page.getByRole('dialog').getByText('迁移完成：导入 1，跳过 1，失败 0。',{exact:true}).waitFor();await page.waitForFunction(()=>!document.querySelector('button[aria-label="关闭弹窗"]').disabled);
 await page.getByRole('tab',{name:'邮箱密码'}).click();
 await page.getByLabel('邮箱',{exact:true}).fill('synthetic@example.com');
 await page.getByLabel('密码',{exact:true}).fill('synthetic-pw');
 await page.getByRole('button',{name:'登录并保存',exact:true}).click();
 await page.waitForFunction(()=>window.uiFixture.calls.includes('add_windsurf_account_with_password'));
 await page.getByRole('dialog').waitFor({state:'hidden'});
 await page.keyboard.press('Escape');assert.equal(await page.getByRole('dialog').count(),0);
 for(const [value,cmd] of [['synthetic-ui-token','add_windsurf_account_with_token'],['[{"synthetic":true}]','import_windsurf_from_json']]){await page.getByRole('button',{name:'添加账号',exact:true}).click();await page.getByRole('tab',{name:'Token / JSON'}).click();await page.getByRole('textbox',{name:'Token / JSON 凭据'}).fill(value);await page.getByRole('button',{name:'导入并保存',exact:true}).click();await page.waitForFunction(c=>window.uiFixture.calls.includes(c),cmd);await page.getByRole('dialog').waitFor({state:'hidden'});}
 await page.getByRole('button',{name:'刷新全部',exact:true}).click();
 const toast=page.getByText('刷新结束：2 个完成，1 个需检查，可在对应账号上单独重试。',{exact:true});
 await toast.waitFor(); await toast.waitFor({state:'hidden',timeout:7000});
 await page.getByRole('button',{name:'删除 Personal',exact:true}).click();
 await page.getByRole('button',{name:'保留账号'}).click();assert.equal(await page.locator('.account').count(),3);
 await page.getByRole('button',{name:'删除 Personal',exact:true}).click();await page.getByRole('button',{name:'确认删除'}).click();await page.waitForFunction(()=>document.querySelectorAll('.account').length===2);
 await page.getByRole('button',{name:'应用设置',exact:true}).click();await page.getByRole('button',{name:'切换浅色主题'}).click();await page.locator('.sidebar .nav-item').first().click();await page.getByRole('button',{name:'网格视图',exact:true}).click();
 await page.setViewportSize({width:1400,height:850});const wideCard=await page.locator('.account').first().boundingBox();assert.ok(wideCard.width>=300 && wideCard.width<400);await page.screenshot({path:'docs/ui-0.4.0-wide.png',fullPage:true});
 await page.setViewportSize({width:720,height:560});
 await page.getByRole('button',{name:'应用设置',exact:true}).click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:'docs/ui-0.4.0-settings-compact.png',fullPage:true});await page.locator('.sidebar .nav-item').first().click();
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.screenshot({path:'docs/ui-0.4.0-compact.png',fullPage:true});
 await page.getByRole('button',{name:'添加账号',exact:true}).click();
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.keyboard.press('Escape');
 await page.reload();await page.locator('.account').first().waitFor();
 assert.equal(await page.locator('.accounts.grid').count(),1);
 assert.equal(await page.locator('html').getAttribute('data-theme'),'light');assert.equal(await page.locator('html').getAttribute('data-reduced-motion'),'true');
 // A failed refresh must label a previously valid quota as cached/failed.
 await page.evaluate(()=>{window.uiFixture.failAccount='demo-2';});
 await page.getByRole('button',{name:'刷新 Design Studio',exact:true}).click();
 await page.locator('.account').filter({hasText:'Design Studio'}).getByText('刷新失败 · 上次数据',{exact:true}).waitFor();
 await page.evaluate(()=>{window.uiFixture.failAccount=undefined;window.uiFixture.refreshDelay=500;});
 const beforeRefresh=await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='refresh_windsurf_token').length);
 await page.getByRole('button',{name:'刷新全部',exact:true}).click();
 await page.getByRole('button',{name:'停止后续刷新',exact:true}).click();
 await page.getByText('已停止后续刷新：1 个完成。',{exact:true}).waitFor();
 const afterRefresh=await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='refresh_windsurf_token').length);
 assert.equal(afterRefresh-beforeRefresh,1);
 await page.evaluate(()=>sessionStorage.setItem('failClient','1'));await page.reload();await page.locator('.account').first().waitFor();
 assert.equal(await page.locator('.account').count(),3);
 assert.equal(await page.getByRole('button',{name:'切换账号',exact:true}).first().isDisabled(),true);
 await page.locator('.client-warning').filter({hasText:'客户端状态读取失败'}).waitFor();
 await page.evaluate(()=>{sessionStorage.removeItem('failClient');sessionStorage.setItem('failList','1');});await page.reload();
 await page.getByRole('heading',{name:'账号读取失败',exact:true}).waitFor();
 assert.equal(await page.getByRole('heading',{name:'从第一个账号开始',exact:true}).count(),0);
 await page.evaluate(()=>sessionStorage.removeItem('failList'));
 await page.getByRole('button',{name:'重新读取',exact:true}).click();await page.locator('.account').first().waitFor();
 assert.deepEqual(errors,[]);

 await page.evaluate(()=>sessionStorage.setItem('pendingSwitch','true'));await page.reload();await page.getByRole('button',{name:'查看恢复操作',exact:true}).waitFor();await page.getByRole('button',{name:'查看恢复操作',exact:true}).click();await page.getByRole('dialog').getByRole('button',{name:'取消',exact:true}).click();
 assert.deepEqual(errors,[]);
 console.log('PASS: safe-view fixtures without credentials; recovery confirmation/cancel/failure/success; legacy cleanup; pending-switch notice; OAuth progress; rotation tab + scan → recommendation banner + gated confirm + dismiss;  three-column card dimensions + six-account/two-row layout + 1000px two-column + 720px single-column; settings is a page with bottom navigation; four settings tabs + keyboard navigation; path save; reduced motion and privacy switches; settings migration entry; 3 synthetic accounts; current-first; search; filters; privacy; grid/list; theme + preference persistence; auth waiting/cancel; Token/JSON tabs; Escape; partial refresh; delete cancel/confirm; 720px responsive; quota percentages + credits + missing data; no overview banners; client status in settings; success toast auto-dismiss; stale quota labeling; bulk stop-after-current; client read failure preserves accounts; storage read failure + retry; diagnostics read-only scan + report preview + gated proxy fix apply/revert + verdict feedback + restart saved-work gate; zero browser exceptions.');
 // A confirmed-low decision without candidates is visible, but cannot switch.
 await page.evaluate(async ()=>{
  const status=await window.__TAURI_INTERNALS__.invoke('get_rotation_status');
  window.uiFixture.rotation={...status,lastDecision:{kind:'blocked',reasons:['no_eligible_candidate']}};
 });
 await page.getByRole('button',{name:'刷新全部',exact:true}).click();
 const emptyPoolWarning=page.locator('.client-warning').filter({hasText:'备用池没有可用账号'});
 await emptyPoolWarning.waitFor();
 assert.equal(await emptyPoolWarning.getByRole('button',{name:'切换到此账号',exact:true}).count(),0);
 assert.deepEqual(errors,[]);
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
