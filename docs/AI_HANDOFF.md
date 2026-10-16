# Devin Account Manager：AI 工程交接

> 交接日期：2026-10-16。先读本文，再读 [AUTO_SWITCH_PLAN.md](AUTO_SWITCH_PLAN.md)。
> 本次交接只新增文档，没有实现自动轮换或热切换，没有修改业务代码，没有提交或推送。
> **已有测试通过 ≠ 新功能完成 ≠ 真实 Devin 登录兼容性验收通过。**

> **后续进展（feat/safe-account-rotation 分支）**：本文 §2 的"分支未创建"
> 已过期——轮换决策层、执行门禁、官方 URI 热切换 adapter、阶段一六项写入
> 修正均已实现，109 项离线测试通过。审核交接见 `docs/REVIEW_HANDOFF.md`，
> 真实验收手册见 `docs/ROTATION_VALIDATION.md`，兼容性矩阵见
> `docs/AUTH_COMPATIBILITY.md`，L2 机制分析见 `docs/HOT_SWITCH_RESEARCH.md`。
> **仍未完成真实客户端验收**，capabilities 如实报 `implemented_unverified`。

## 1. 项目介绍与环境

仓库：<https://github.com/axinlab71/devin-account-manager>。

Devin Account Manager 是从 [Cockpit Tools](https://github.com/jlcodes99/cockpit-tools) 提取的 Windows 桌面账号管理工具。保留上游 Windsurf/Devin 的账号格式、凭据转换、刷新及 IDE 登录态注入逻辑，并增加安全保护。不是从零实现的认证协议，也不是官方客户端。

主要场景：浏览器添加本人授权的账号、Token/JSON 导入、迁移 Cockpit、本机官方账号导入、多账号管理、额度查看，以及需要重启 IDE 的标准切号。

| 项目 | 实际基线 |
| --- | --- |
| 版本 | 0.4.0，发布说明定位 Beta |
| 技术栈 | Rust 2021、Tauri 2、React 19、TypeScript 5.8、Vite 7 |
| 本机工具 | Windows、PowerShell、Node v22.19.0、Rust 1.92.0 MSVC；此前构建使用 VS 2022 / WebView2 |
| 工程目录 | `D:\devin上号器\devin-switcher-public` |
| 官方客户端 | `E:\Devin\Devin.exe`；交接时文件/产品版本均为 **3.10.67** |
| 官方静态资料 | `E:\Devin\resources\app\extensions\windsurf\package.json`、`dist/extension.js`、`E:\Devin\resources\app\product.json` |
| 产品元数据 | `product.json` 显示 `urlProtocol=devin`、`dataFolderName=.devin`；不等于 Electron 用户数据目录，不能据此迁移 Token |
| 默认窗口 | 1120×780，最小 720×560；标准/宽窗口最多三列卡片 |
| 应用 identifier / Rust lib | `local.devin-switcher.desktop` / `devin_switcher_lib`；不要因产品改名擅自修改 |

许可证为 **CC BY-NC-SA 4.0**。保留 `LICENSE.txt`、`NOTICE.md`、`PROVENANCE.json` 及上游署名；官方图标/商标权利仍归原权利人。外部参考项目的许可证不同，研究思路不等于允许直接复制其实现。

## 2. 当前项目状态：事实与未完成事项

### Git 快照

- 当前分支：`main`。
- HEAD：`d782450dc0ce78ee7dabbab37690b02e650239b9`。
- 最近只读审计时远端 main 与本地 HEAD 一致；接手时必须重新确认，禁止用 v0.3.1 覆盖新版。
- 交接前 `git status --short` 无输出，即工作区干净。
- 交接完成后预期只有两个未跟踪文档：`docs/AI_HANDOFF.md`、`docs/AUTO_SWITCH_PLAN.md`。文档未提交，不会自动出现在远端；必须把文件一并交给下一个 AI。
- **尚未创建**计划中的 `feat/safe-account-rotation` 分支。后续业务开发前再从确认后的最新 main 创建。
- 发布：<https://github.com/axinlab71/devin-account-manager/releases/tag/v0.4.0>。含安装包、便携版、源码包和 SHA256SUMS；上次发布核验四项远端 digest 与本地一致。

### 已有功能与最近提交

现有功能包括浏览器授权、本机账号导入、Token/JSON 合并导入、Cockpit 迁移、账号删除、套餐/额度展示与刷新、三列/列表视图、隐私显示、主题、独立设置页、标准重启切号、加密恢复点和旧备份清理确认。

| 提交 | 已完成内容 |
| --- | --- |
| `ae137a7` | v0.3.2 三列卡片与额度信息层级 |
| `155450f` | v0.4.0 安全摘要 IPC、端点校验、加密完整数据库恢复、正常关闭、进程间锁、组织身份及时间语义 |
| `d782450` | 官方客户端辅助登录流程改用到期时间，避免新启动 Windows 环境的测试时间减法溢出 |

### 新需求进度

- 阶段一只读审计：**进行中，未完成**。读过重点源码及本机官方静态代码；还没有完整保护清单、认证写入审计工具或真实登录基线。
- `quota_monitor.rs`、`rotation_policy.rs`、`account_selector.rs`、`switch_adapter.rs`、`rotation_state.rs`：**未创建，未开始实现**。
- 原生 L2、全自动轮换、托盘驻留：**未实现、未实测**。
- 真实账号授权、在线额度核对、A→B→A、官方退出后重新网页登录：本轮工程验收**未实测**。用户此前说过网页登录“好像有用”，这不是可复现的正式验收证据。

### 已知限制

现有切号本质是关闭客户端、写 SQLite、回读匹配、再启动。不能称为同进程热切换，也不能凭“当前”标识宣称后续 AI 请求已获新账号授权。3.10.67 不能继承旧 3.10.48 的兼容结论。

新增自动化不能直接复用现有写入流程：其中存在批量键清理、会话数组替换和设备标识生成，详见第 4 节。额度字段语义也存在代码注释/解析冲突，不能直接以当前 UI 值驱动自动切换。

## 3. 核心代码地图与调用链

以下路径均相对仓库根目录。函数名称比行号更可靠；交接基线中的批量清理约在 `windsurf_instance.rs:603`。

| 功能 | 文件、关键符号与职责 |
| --- | --- |
| Tauri 命令注册 | `src-tauri/src/lib.rs`：`run` 内 `generate_handler!` 是真实可调用清单；模块里有函数不等于前端开放 |
| 网页 OAuth 主流程 | `src-tauri/src/modules/windsurf_oauth.rs`：`build_auth_url`、`start_login`、`start_callback_server`、`serve_callback`、`poll_login`、`build_browser_payload`、`cancel_login`、`callback_received` |
| Token/本机凭据转 payload | 同文件：`build_payload_from_token`、`build_payload_from_local_auth_status`、`build_payload_from_devin_auth1_token`、`build_payload_from_auth1_session_token`、`build_devin_payload` |
| Auth1 长期刷新 | `src-tauri/src/modules/windsurf_devin_oauth.rs`：`full_refresh_from_auth1`，内部 `windsurf_post_auth`、`get_one_time_auth_token`、`register_user`、`get_current_user_proto`；这不是纯额度查询 |
| 刷新分派/保存 | `windsurf_oauth.rs::refresh_payload_for_account` → `src-tauri/src/modules/windsurf_account.rs::refresh_account_token` / `refresh_account_token_once` → `merge_refresh_payload_with_existing`、`apply_payload`、保存详情和索引 |
| 账号 CRUD/导入 | `windsurf_account.rs`：`load_account`、`list_accounts_checked`、`upsert_account`、`upsert_account_record`、`import_from_json`、`remove_account`、`read_local_auth_status`、`read_local_login_hint`、`mark_switched` |
| Cockpit 迁移 | `src-tauri/src/modules/cockpit_migration.rs::import`；只读源目录、解密后用本工具密钥重存，按身份跳过重复，返回 imported/skipped/failed |
| 数据目录 | `src-tauri/src/modules/account.rs::get_data_dir`：本工具 `%LOCALAPPDATA%\DevinSwitcher`；单元测试可用 `COCKPIT_TOOLS_TEST_DATA_DIR`，仅 `cfg(test)` 生效 |
| 安全存储 | `src-tauri/src/modules/secure_account_storage.rs`：`serialize_account_file`、`deserialize_account_file`、`read_or_create_key_at`；AES-256-GCM，Windows 主密钥 DPAPI 包装；`key_protection.rs`、`atomic_write.rs`、`deferred_account_rewrite.rs` 配套 |
| IPC 摘要 | `src-tauri/src/modules/account_view.rs::AccountView`、`views`、`safe_value`、`filter_proto`：列表/导入/刷新/登录只返显示摘要和白名单额度；完整凭据不回传 |
| 认证端点 | `src-tauri/src/modules/auth_endpoint.rs`：`validate_base`、`validate_json`、`validate_account`；`auth_transport.rs::send` 沿用现有代理/TLS/禁止重定向重放行为，不要修改代理配置 |
| 组织身份 | `src-tauri/src/modules/account_identity.rs`：`scope`、`payload_scope`、`same`、`matches_payload`、`scoped_id`、`validate_refresh`、`current_id`；Account ID + Org ID，兼容 raw 旧字段，歧义不猜测 |
| 额度网络查询 | `windsurf_devin_oauth.rs::fetch_devin_user_status`；`windsurf_oauth.rs` 中 `get_user_status_by_api_key`、`get_plan_status`、`fetch_auth1_plan_status` 等。部分为私有函数，后续只添加最小只读入口，不能绕开端点保护 |
| 额度显示解析 | `src/types/windsurf.ts`：`parseWindsurfProtoSummary`、`getWindsurfUsage`、`getWindsurfCreditsSummary`、`getWindsurfBillingStrategy`、`getWindsurfOfficialUsageMode`、`getWindsurfQuotaUsageSummary`；`src/components/AccountQuota.tsx` 展示 |
| 官方目录/会话读取 | `src-tauri/src/modules/windsurf_instance.rs`：`get_default_windsurf_user_data_dir`、`windsurf_user_data_dir_candidates`、`state_db_score`、`read_profile_session_auth_status`、`get_windows_encryption_key` |
| 官方会话写入 | 同文件：`inject_account_to_profile` → 事务 → `write_windsurf_auth_data` → `upsert_windsurf_extension_state`；`encode_encrypted_buffer_json` 使用目标 profile 自己的密钥 |
| 客户端生命周期 | 同文件：`close_windsurf`、`request_windsurf_graceful_close`、`profile_is_running`、`start_windsurf_default_with_args_with_new_window`；`process.rs::lock_client_operation` 提供 fs2 跨进程文件锁 |
| 标准切号命令 | `lib.rs::inject_windsurf_to_vscode`；`current_account_id` 做本地凭据/组织匹配；`CLIENT_LOCK` 与跨进程锁共同保护 |
| 加密备份/回滚 | `src-tauri/src/modules/client_recovery.rs`：`create`、`preflight`、`guarded_with_close`、`restore`、`status`、`cleanup_legacy`；`lib.rs::restore_last_client_state`、`get_recovery_status`、`cleanup_legacy_client_backups` |
| 官方客户端辅助登录 | `src-tauri/src/modules/official_browser_login.rs`：`build_official_login_url`、`start`、`poll`、`cancel`、`read_local_login`、`remove_observation_metadata`。这是另一条依赖客户端的辅助流程，不是当前 UI 直接网页授权主流程 |
| 前端桥接 | `src/services/windsurfService.ts` 中 list/import/token/refresh/start/poll/cancel 包装；恢复、路径、迁移、切号也有 `src/main.tsx` 直接 `invoke` |
| 账号与设置 UI | `src/main.tsx::App`、`Modal`、`startBrowser`、`refreshAll`、`switchAccount`；`src/components/SettingsPage.tsx::SettingsPage` / `Row`；`src/style.css` 负责布局 |
| 模型/配置 | `src-tauri/src/models/windsurf.rs`、`src/types/windsurf.ts`；版本在 `package.json`、lock、`src-tauri/Cargo.toml`/lock、`tauri.conf.json` 及设置页同步 |

### 主调用关系

```text
网页添加：App.startBrowser
  → windsurf_oauth_login_start → auth::start_login → 系统浏览器
  → /auth 本机 listener + 随机 state + fragment 桥接 POST
  → windsurf_oauth_login_poll → auth::poll_login → 凭据转换/兑换
  → accounts::upsert_account → 加密保存 → AccountView

Token/JSON：合并输入框
  → add_windsurf_account_with_token / import_windsurf_from_json
  → payload 构建 / JSON 预检 → 原有账号存储 → AccountView

本机导入：import_windsurf_from_local
  → official_browser_login::read_local_login
  → 官方状态/加密 sessions 读取 → build_payload_from_local_auth_status
  → upsert_account（写本工具存储，不应注入官方客户端）

手动刷新：refresh_windsurf_token
  → refresh_account_token → refresh_payload_for_account
  → 按凭据类型远端刷新/查询 → 校验组织 → 更新长期凭据与额度缓存

标准切号：inject_windsurf_to_vscode
  → 客户端锁 → 必要的 Auth1 刷新 → 目标校验 → 正常关闭
  → guarded_with_close：加密快照 → inject_account_to_profile
  → current_account_id 本地匹配 → 启动 → mark_switched
  → 失败：先确认客户端关闭，再尝试数据库恢复；不安全则保留恢复点
```

原 Invalid redirect URI 使用 `/windsurf-auth-callback`。当前 `build_auth_url` 生成 `https://www.windsurf.com/windsurf/signin?...`，回调使用 `/auth`；仓库 `docs/official-redirect-rules.json` 是官网静态规则依据，不是第三方 OAuth 授权合同或真实在线成功保证。不能任意改 client_id、接管 `devin://` 或把 GitHub 中间 `code` 当作 Devin 凭据。

### 存储与恢复边界

- 本工具：`%LOCALAPPDATA%\DevinSwitcher\windsurf_accounts.json` 是索引摘要；`windsurf_accounts\` 是账号详情；`secure-account-storage.key` 是本工具主密钥。摘要包含身份信息，不能宣称所有本地数据都加密。
- 账号旧明文格式可读，后续保存/延迟重写为加密；`list_accounts_checked` 会去重，`load_account` 可能安排延迟重写，不是无副作用的通用纯读取 API。
- 官方候选目录：Windows `%APPDATA%\Devin`、`%APPDATA%\Windsurf`；`get_default_windsurf_user_data_dir` 按实际数据库等评分选择，不能假定固定选第一个，更不能重定向。`state_db_score` 当前使用普通 `Connection::open`，新增监控不得照搬为严格只读探测。
- 官方数据库：目标 profile 下 `User/globalStorage/state.vscdb`；`Local State` 中 `os_crypt.encrypted_key` 经 DPAPI 解开，供原 profile 的 Electron 加解密使用；不能跨 profile 搬运。
- 恢复点：本工具 `client-backups/last-switch.encrypted.json` 与 `switch-state.json`。SQLite Backup API 在内存形成完整快照，校验后加密，不产生新的明文临时数据库；绑定 profile、密钥指纹及摘要。
- 仅保留最近一次新恢复点。旧 `state-<UUID>.vscdb` 只在用户确认且恢复点有效时清理，绝不代用户自动清理。
- 恢复覆盖完整数据库，会覆盖切换之后的数据库变化；不恢复 `Local State`、系统凭据服务、协议注册或运行中会话。不得把 SQLite 回滚成功等同于整个认证系统回滚成功。

## 4. 最高优先级安全约束与审计结论

任何 AI 必须维护：用户退出官方账号后，仍能不依赖管理器通过官方网页登录。**目前尚未真实证明这一不变量在标准切号后始终成立。**

禁止改变官方默认 Token/数据目录、密钥路径和凭据服务名；禁止移动/清空认证目录、全局环境变量或参数重定向；禁止符号链接冒充默认目录；禁止改写官方 `extension.js`、认证脚本和 `devin://` 注册；禁止重置机器 ID、伪造验证、绕过设备绑定；禁止把完整凭据发给前端列表、日志或第三方服务。用户手动粘贴 Token 的导入输入是明确授权的输入，不要误写成“Token 从未进入前端”。

### 源码已确认的行为与未确认的后果

| 位置/行为 | 已确认事实 | 尚待验证 / 应对 |
| --- | --- | --- |
| `write_windsurf_auth_data` | 覆盖 `windsurfAuthStatus`；以新建单元素数组替换 `secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.sessions"}`，不保留原数组未知项 | 认证状态覆盖与数组替换均须核对官方形态；未知项影响未验证，见下一行 |
| 上述数组替换 | 写入包含随机 session id、accessToken、account label/id、空 scopes | 是否损失新版提供者所需字段、是否影响退出/重登录，**未实测**；不能直接用于 L2 |
| 同函数其他键 | 写 `windsurf_auth.apiServerUrl` 加密 secret、`codeium.windsurf-windsurf_auth` 选中账号及 `windsurfOnboarding` | 是否全属必要写入、与官方实际保存形态是否一致，未完成审计 |
| `DELETE ... LIKE 'windsurf_auth-%'` | 无条件删除匹配的全部行，再重建当前 label 的 `[]` 和 `-usages`；在事务内执行 | 元数据用途/完整集合未知，安全性**未证明**。SQL LIKE 中 `_` 是通配符，模式并非严格字面前缀；先做边界测试，不能扩大清理范围，也不能未测试就删除语句 |
| `upsert_windsurf_extension_state` | 修改 `codeium.windsurf` JSON 的 apiServerUrl / pending migration；保留有效已有 installation ID，缺失或异常时生成 UUID | 生成安装标识与新增要求存在冲突；注释声称作用不能当官方证据。新路径禁止生成/重置，需报告并批准兼容修正方案 |
| 同函数解析失败 | 现有 JSON 非对象/解析失败会退回空对象再写 | 可能丢未知扩展状态，尚未真实复现；后续应研究 fail-closed，不得悄悄覆盖 |
| `inject_account_to_profile` | 从账号 raw 状态构造 SignedIn、user、timestamp、sessionToken、authMethod、proto、account/org 字段，再事务写入 | 写入成功/本地匹配不证明官方服务验证成功；不能扩展到运行中磁盘热替换 |
| 进程关闭 | 已用正常窗口关闭与超时中止，没有自动 `/F`；存在进程内与文件锁 | 未保存工作、多个窗口、后台 AI 任务下实际行为**未实测**；新自动控制须显式用户确认 |
| 完整恢复点 | 合成 WAL/损坏/启动失败等测试通过 | 不覆盖外部认证存储；真实故障及官方重新登录未验收 |

表格第一行只记录写入事实；所有“会导致官方无法重新登录”的因果结论均**尚未证明**，不能把风险描述伪装成已复现 Bug。反过来也不能因过去能切号就认定风险不存在。

现有保护必须保留：`account_view.rs` 白名单摘要、`auth_endpoint.rs` 精确 HTTPS 官方地址校验、`client_recovery.rs`、锁、DPAPI/AES 存储、组织身份校验。端点目前限定 `server.codeium.com`、`server.self-serve.windsurf.com`、`register.windsurf.com` 根路径和 `windsurf.com/_backend`，不能为了导入兼容放宽成任意 URL。

## 5. 已研究外部项目与官方静态线索

### 老 Windsurf 项目

- <https://github.com/chaogei/windsurf-account-manager-simple>：README 明确描述修改 `extension.js` 的无感补丁、OAuth 回调和机器 ID 功能。可借鉴账号管理交互与认证事件分层；不能复制补丁、移除超时或设备标识处理。本轮未完成其全仓源码审计。
- <https://github.com/cxyttg666/windsurf-account_switch>：README 描述 `WindsurfPatchService` 注入 `handleAuthTokenWithShit` 和自定义 `windsurf.provideAuthTokenToAuthProviderWithShit` 命令，再通过 VS Code Secrets 与会话事件刷新 UI，并明确声称跳过服务器验证。定位到 `src/services/windsurfPatchService.ts`、`windsurfAutoLoginService.ts`，原始文件抓取曾网络失败；不可声称逐行审计完成。
- 这些旧项目的“无感”依赖客户端修改/注销/注入，不是已证实的新版官方外部接口；不能复制为本项目方案，也不能以“本地补丁”理由绕过服务器校验。

### OMP（只借鉴决策，不移植 API 路由器）

- [usage/devin.ts](https://github.com/can1357/oh-my-pi/blob/main/packages/ai/src/usage/devin.ts)：区分 Credits 与日/周限制、适用性与隐藏字段、重置时间、账号/组织范围；已读取关键实现片段。
- [auth/rotation.ts](https://github.com/can1357/oh-my-pi/blob/main/packages/ai/src/auth/rotation.ts)：按凭据身份及作用域阻断，区分配额/策略与认证失败，维护候选及等待重试；已浏览源码相关部分，未做完整移植评估。
- [error/rate-limit.ts](https://github.com/can1357/oh-my-pi/blob/main/packages/ai/src/error/rate-limit.ts)：错误分类及限流信息解析的参考；不能把所有 429 / Permission Denied 视为额度耗尽。原始拉取有超时，后续浏览访问成功；不存在本地完整审计报告。

**额度语义冲突已发现但未解决**：`windsurf_devin_oauth.rs::fetch_devin_user_status` 注释把 availablePromptCredits 称为剩余；`src/types/windsurf.ts` protobuf 解析约 776 行注释称其为总量；OMP 又有 available/used bucket 解释。需要按版本、套餐、计费方式和真实 IDE 显示核对，不能机械选一个解释执行轮换，也不要在本次交接中修改额度 UI。

### Devin 3.10.67 官方静态线索（仅只读）

本机 `windsurf/package.json` 声明 `windsurf_auth` 认证提供者，以及 `windsurf.*` / `devin.*` 的 login/logout/loginWithAuthToken 等命令。`dist/extension.js` 可见 `registerAuthenticationProvider`（supportsMultipleAccounts=false）、`onDidChangeSessions`、`secrets.onDidChange`、`registerUriHandler` 和 `/refresh-authentication-session` 分支；认证更新还会触发连接更新。

这些只是内部存在的机制。未证明从外部桌面进程能安全调用、传入已有凭据并完成官方校验；刷新事件本身不是换号接口。命令的备用登录可能需要交互/官方授权码，不能把 session token 当授权码。没有修改官方文件，没有调用上述入口或发送带凭据深链；**L2 仍不支持/未验证**。

## 6. 已达成技术决策与尚待事项

### 用户已选择

1. 先离线开发；之后提供隔离 Windows 环境做真实验收，不在用户默认目录做破坏实验。
2. 首版仅应用运行时监控；退出即停止，托盘延后。
3. 允许在用户主动启用的备用池中跨组织推荐；确认界面显示组织变化；跨组织全自动禁用。

### 已形成的计划默认值（尚未实现，不是实测结论）

- 智能确认是默认模式，首次安装监控关闭；另有仅提醒与受严格能力门禁的全自动模式。
- 阈值默认 10%，范围 0～30%；轮询默认 60 秒，范围 30～3600 秒；快照有效期 120 秒。
- 当前账号需两次成功低额度结果确认、间隔至少 5 秒；候选所有适用限制须高于阈值至少 5 个百分点。
- 全局最短切换间隔 10 分钟，切出账号冷却 30 分钟，连续执行失败 3 次暂停；重置后重新查询，不只看本地计时器。
- 默认按最小适用剩余比例降序，再优先级降序、最近一次重置时间升序、最近切换时间升序和 ID 排序；可选优先级/重置/最久未切换优先。
- 监控不触发注册、令牌交换、客户端写入或自动刷新长期凭据；需要刷新时提示走现有手动功能。只允许存本工具的监控摘要与状态。
- L1 为标准重启切换；L2 必须窗口/PID 保持且官方识别目标与后续请求验证；L3 运行任务跨账号续接不实现、不宣传。
- 原生/隔离实例适配器在证据不足时返回 unsupported；绝不静默降级重启。

### 阻碍与未决方案

尚无可用隔离环境及真实账号验收记录；配额字段映射未核实；原生运行时入口的支持范围、外部调用桥和安全工作状态检测未确认；多实例参数兼容性未实测；认证键清理与官方重登录关系未证明。原生桥接/独立 VSIX 不是已批准或已实现方案，需要研究证据后再决策。先交付只读推荐，不为赶功能选择补丁。

## 7. 下一个 AI 的明确工作顺序

1. 读两份交接文档、README、`docs/VALIDATION.md`、`docs/REAL-ACCOUNT-CHECKLIST.md`、许可及实际 Git 状态；保护本次未提交文档。
2. 只读核对远端 main 和本机客户端版本；不要 reset、覆盖或自动 stash 用户文件。确认后创建独立开发分支。
3. **从阶段一未完成部分开始**：对 `windsurf_instance.rs` 上述五个入口完成逐键写入矩阵、未知字段/会话保留测试和只读资源探测，建立合成测试基础；不执行真实默认 profile 的注入。
4. 在无客户端写能力的测试依赖下新增五个 Rust 模块，先完成阶段二可信配额、错误分类、冷却及确定性候选排序；UI IPC 只返安全摘要。
5. 再实现可取消/过期的确认建议。涉及认证写入修正前，向用户报告具体修改、可恢复性和风险并等批准；不能以用户授权“开发功能”代替对风险操作的明确批准。
6. 原生研究与真实验收按 [AUTO_SWITCH_PLAN.md](AUTO_SWITCH_PLAN.md) 门禁推进。能力不足时维持“不支持”，不得伪报完成。

## 8. 真正执行过的验证与复现

### 已执行结果（历史证据，本次文档任务未重新跑大规模测试）

| 命令/检查 | 真实结果与边界 |
| --- | --- |
| `npm run build` | TypeScript/Vite 通过 |
| `npm run test:quota` | 额度合成数据解析通过；不证明字段在真实套餐中语义正确 |
| `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- --test-threads=1` | 最终本地 **55 passed, 0 failed**；合成数据/临时目录，不是真实双账号验收 |
| `node scripts/ui-smoke.cjs`（先启动 Vite，Edge） | 合成 IPC 回归通过，零浏览器异常；脚本会重写仓库 `docs/ui-0.4.0-*.png`，执行后需检查差异，不能默认覆盖用户截图 |
| `node scripts/ci-ui.cjs`（Chromium） | GitHub 通过；自启端口 1420 的 Vite 子进程，不能与已有同端口服务并行 |
| `npm run tauri -- build --bundles nsis` | 最终本地 release + x64 NSIS 通过；安装包约 3.95 MiB，有未用函数警告，不是零警告 |
| 便携版启动 | 0.4.0 进程存活、窗口标题正确，然后仅关闭本次测试管理器窗口；未执行安装/卸载或真实 IDE 切号 |
| 发布校验 | 四项 GitHub 资产 digest 匹配，本次前序已核验 latest=v0.4.0；不是签名/安装验收 |

GitHub 最终成功运行：<https://github.com/axinlab71/devin-account-manager/actions/runs/38859202880>，HEAD `d782450`。包括 npm ci、前端、quota、55 项 Rust、Chromium UI 和 NSIS 构建。

首次运行 <https://github.com/axinlab71/devin-account-manager/actions/runs/38858435732> 曾 **54 通过、1 失败**：旧测试 `official_browser_login::tests::cancellation_and_expiry_do_not_read_or_import_credentials` 从 Instant 倒退十分钟，在刚启动的 Windows 环境溢出；`d782450` 改为 deadline 后本地和远端通过。不要隐瞒该失败，也不要把它描述为真实 OAuth 故障。

55 项覆盖包括 OAuth state/fragment、不落 pending 的凭据、端点拒绝、DTO 过滤、加密保存/子进程持久化、Cockpit 合成迁移、组织区分、轮换长期凭据更新、锁、WAL 快照、提交后校验失败/模拟启动失败回滚、损坏/跨目录/密钥变化拒绝和清理边界。**不包含新的自动轮换决策测试。**

本机私有证据在 `D:\devin上号器\research`：`security-tests.txt`、`ui-test-output-0.4.0.txt`、`package-verified-output-0.4.0.txt`、`startup-0.4.0.json` 等。不要把整个 research 上传；异机接手可用仓库验证文档和 CI。构建产物在 `D:\devin上号器\release\0.4.0`。

### 常用复现（业务开发时执行，交接任务不需要重跑）

```powershell
npm ci
npm run build
npm run test:quota
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- --test-threads=1
# UI 方式 A：先独立启动 npm run dev，另一终端：
node scripts/ui-smoke.cjs
# UI 方式 B：确保 1420 空闲，安装 Chromium 后由 helper 自启服务：
npx playwright install chromium
node scripts/ci-ui.cjs
npm run tauri -- build --bundles nsis
```

本机此前复用的 target：`$env:CARGO_TARGET_DIR='D:\devin上号器\devin-switcher\src-tauri\target'`，只是构建缓存，不是要修改旧项目源码；其他机器无需照搬。默认 UI 使用 Edge，`DEVIN_PLAYWRIGHT_PATH` 可指定本机 Playwright 包，`DEVIN_BROWSER_CHANNEL=chromium` 选 bundled Chromium。CI 工作流在 `.github/workflows/verify.yml`，push 仅 main，另有 PR/手动触发。

### 未实测清单

隔离 Windows 官方未安装/安装后登录基线、只读查询/导入前后认证资源差异、真实 A→B→A、官方退出后重新 OAuth、停用/卸载后独立登录、真实 Token 过期/更新/崩溃恢复、系统密钥存储完整变化、3.10.67 的 L2、工作状态检测、多实例兼容、托盘生命周期：**均未完成真实验收**。不能用既有 SQLite 合成恢复测试替代。

## 9. 常见错误与恢复提示

- 不要把 `WindsurfAccount` 磁盘模型直接作为新增 IPC 返回值；必须经过 `AccountView` 或同等严格摘要，opaque protobuf/错误响应也可能藏凭据。
- 不要在额度监控中直接调用整套 `refresh_account_token`，其中可能交换长期凭据/注册；不要在前端 setInterval 操作官方 Token 文件。
- 不要把列出账号视为绝对纯操作；新增排序应使用已读取快照，避免在排序/筛选中调用导入、刷新或去重存储函数。
- 不要仅凭邮箱或同 session 判组织相同，不要因刷新重写 `last_switched_at`；legacy `last_used` 不一定是真实切换时间。
- 不要复制官方 `Local State` 密钥到新 profile，不要通过重建密钥“修复”解密失败；解不开应停止并保留原数据。
- 失败先停止监控和写入、保留脱敏错误及恢复点，确认 IDE 已安全关闭，再由用户决定设置中的完整数据库恢复。密钥/profile 不匹配时禁止强行恢复；不能保证外部状态恢复。
- 不要自动退出官方账号、批量删除 session、覆盖损坏 JSON、生成 machine ID；任何拟修正先拿出范围明确的兼容测试和风险报告。
- 不要用官方 `devin://` 携带凭据做未经批准实验；不调用旧补丁命令；不把内部 refresh URI 当作公开稳定接口。
- 混合 CRLF/LF：避免全文重写；检查 `git diff --stat` 和 `git -c core.whitespace=cr-at-eol diff --check`，不要提交纯换行噪音。
- Windows shell 是 PowerShell，不支持 Bash 的 `{a,b}` 文件展开；用显式路径。GitHub TLS 曾偶发 EOF，重试时不得关闭 TLS 校验、泄露 gh token 或改应用代理；凭据由本机 gh/keyring 管理，不写交接文件。
- 遵守许可证，截图只用合成账号。不要提交研究日志、真实 JSON、cookie、完整官方 DB 或密钥；不要自动清理工作区/其他仓库。

## 10. 零聊天上下文接手指南

建议执行的第一项任务：**只读核对 Git 与 Devin 版本，然后补齐 `windsurf_instance.rs` 的逐键写入/删除矩阵及合成保留测试设计，明确哪些认证写入尚不安全；在此之前不接入任何自动切换。**

阅读顺序：本文 → AUTO_SWITCH_PLAN → README/NOTICE → VALIDATION/REAL-ACCOUNT-CHECKLIST → `lib.rs` 命令与 `windsurf_instance.rs` 写入路径 → 额度解析。计划文档中的“拟新增”符号不是现有代码。

未发现仓库根、docs、项目父目录或 `D:\` 的适用 `AGENTS.md`，本次没有新建或覆盖规范。如果之后要增加，只追加最小规则：

> 任何 AI 接手本项目时，必须先阅读 docs/AI_HANDOFF.md 和 docs/AUTO_SWITCH_PLAN.md；涉及 Devin 官方登录态、认证存储和切号的代码修改，必须优先保证官方客户端能够正常退出并重新网页登录。

本次交接不授权提交、推送或继续业务开发。后续实现时按用户新指令推进，逐阶段记录真实证据，明确保留所有未完成和未实测项。
