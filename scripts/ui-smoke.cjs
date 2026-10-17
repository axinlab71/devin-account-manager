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
 await page.getByRole('tab',{name:'数据管理',exact:true}).click();await page.getByText('Synthetic UI fixture',{exact:true}).waitFor();await page.screenshot({path:'docs/ui-0.4.0-settings-data.png',fullPage:true});
 const restoresBefore=await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='restore_last_client_state').length);
 await page.getByRole('button',{name:'恢复上次状态',exact:true}).click();await page.getByRole('dialog').getByRole('button',{name:'取消',exact:true}).click();assert.equal(await page.evaluate(()=>window.uiFixture.calls.filter(c=>c==='restore_last_client_state').length),restoresBefore);
 await page.evaluate(()=>sessionStorage.setItem('failRestore','true'));await page.getByRole('button',{name:'恢复上次状态',exact:true}).click();await page.getByRole('button',{name:'确认恢复',exact:true}).click();await page.getByRole('dialog').getByText('Error: Synthetic restore refused before writes',{exact:true}).waitFor();await page.keyboard.press('Escape');await page.evaluate(()=>sessionStorage.removeItem('failRestore'));
 await page.getByRole('button',{name:'恢复上次状态',exact:true}).click();await page.getByRole('button',{name:'确认恢复',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});await page.getByRole('button',{name:'关闭提示',exact:true}).click();
 await page.getByRole('button',{name:'清理旧版备份',exact:true}).click();await page.getByRole('button',{name:'确认清理',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});assert.equal(await page.getByRole('button',{name:'清理旧版备份',exact:true}).isDisabled(),true);await page.getByRole('button',{name:'关闭提示',exact:true}).click();
 await page.getByRole('button',{name:'导入账号',exact:true}).click();await page.getByRole('tab',{name:'本地迁移',exact:true}).waitFor();await page.keyboard.press('Escape');
 await page.getByRole('tab',{name:'关于',exact:true}).click();await page.getByText('v0.4.0',{exact:true}).waitFor();assert.equal(await page.getByRole('link',{name:/开源仓库/}).getAttribute('href'),'https://github.com/axinlab71/devin-account-manager');await page.screenshot({path:'docs/ui-0.4.0-about.png',fullPage:true});
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
 console.log('PASS: safe-view fixtures without credentials; recovery confirmation/cancel/failure/success; legacy cleanup; pending-switch notice; OAuth progress; rotation tab + scan → recommendation banner + gated confirm + dismiss;  three-column card dimensions + six-account/two-row layout + 1000px two-column + 720px single-column; settings is a page with bottom navigation; four settings tabs + keyboard navigation; path save; reduced motion and privacy switches; settings migration entry; 3 synthetic accounts; current-first; search; filters; privacy; grid/list; theme + preference persistence; auth waiting/cancel; Token/JSON tabs; Escape; partial refresh; delete cancel/confirm; 720px responsive; quota percentages + credits + missing data; no overview banners; client status in settings; success toast auto-dismiss; stale quota labeling; bulk stop-after-current; client read failure preserves accounts; storage read failure + retry; zero browser exceptions.');
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
