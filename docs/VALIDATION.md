# 验证记录

## 0.1.5 当前变更（2026-10-15）

- 用户截图显示 callback 已收到结果，RegisterUser 仍处于发送失败。通过无凭据 GET 在同机复现：环境代理连接失败，源异常为 `unexpected EOF during handshake`；直连获得 HTTP 404，证明 TLS/HTTP 已连通，而非账号兑换成功。
- 认证请求共 12 处 send 边界接入共享传输层；上游 URL、body 和显式 UA 保持。auth1 的客户端默认 UA 在直连尝试中也保留。
- 默认先使用原系统/环境代理；仅 is_connect 失败且请求可克隆时尝试一次直连。两条连接均保留正常证书/域名校验。认证 API 不自动跟随重定向。
- TypeScript / Vite 生产构建和 Rust fmt 检查通过；Release 与 NSIS 构建成功（安装包约 3.90 MiB）。便携程序元数据 0.1.5，启动创建 Devin Switcher 窗口并保持运行，随后仅关闭本次测试窗口。未操作用户真实账号、未替用户安装/卸载。
- 32 项后端回归测试通过，0 失败，见 `test-output-0.1.5.txt`。新增坏代理→直连、body/UA 保留、401 不重放、连接后超时不重放、307 不跟随/重放测试。
- 后续重复检查时原代理也恢复返回 HTTP 404，说明故障具有间歇性，不能断言该代理一直不可用。
- 新传输层对真实 RegisterUser 路径的无凭据 GET 获得 HTTP 405；强制坏代理后直连也获得 HTTP 405，证明 fallback 实际通过了 TLS/HTTP。405 不表示真实凭据兑换成功。
- 网络探针只发送公开域名 GET，不读取账号、不提交 Token。真实网页登录凭据兑换、刷新及切号仍需用户重试验证。

## 0.1.4 当前变更（2026-10-15）

- 界面配色来自用户指定的本地 Devin Dark / Devin Light 主题；读取安装资源不操作登录数据。来源和哈希记录见 `DESIGN-REFERENCE.json`。
- Windows 图标直接复制原客户端多分辨率 ICO；前端及跨平台尺寸由同一图标最大帧生成。
- 界面调整、图标与版本信息更新；Rust 功能源码保持前版。
- TypeScript / Vite 生产构建成功；28 项 Rust 离线回归测试通过，0 失败。`cargo fmt --check` 通过。
- Edge 合成账号界面测试通过：搜索、筛选、当前置顶、隐私、网格/列表、主题记忆、授权等待与取消、焦点循环、Token/JSON 页签、批量刷新部分失败、删除及 720px 无横向溢出；无未捕获浏览器异常。日志 `ui-test-output-0.1.4.txt`。
- Release 构建成功；随后为安装器及卸载器明确配置同款图标，执行 `tauri bundle --bundles nsis` 重新打包成功（约 3.90 MiB）。生成的 installer.nsi 中两项 ICON 定义均指向原始 Devin ICO。
- 从最终 EXE 提取图标并检查，黑白 Devin 图标正确嵌入；便携程序元数据为 0.1.4，启动保持运行并创建 Devin Switcher 窗口，随后仅关闭本次测试窗口。
- 26 个 Rust 功能源文件与 0.1.3 源码包逐一比对，无变化。真实账号未在本次验证中操作，未替用户安装或卸载。

## 0.1.3 当前变更（2026-10-15）

- 仅改前端、窗口尺寸、版本与文档；OAuth、导入、凭据存储、刷新协议及客户端注入 Rust 源码保持 0.1.2 实现。
- 用户对 0.1.2 网页授权的反馈为“好像这次确实有用了”；这是用户反馈，不冒充开发环境独立端到端验证。
- TypeScript 严格检查和 Vite 生产构建通过。28 项 Rust 离线测试通过（0 失败），日志 `test-output-0.1.3.txt`。
- Edge 无头浏览器运行 `scripts/ui-smoke.cjs`：合成账号验证当前置顶、名称/邮箱搜索、需检查筛选、隐私模式、网格/列表切换、深浅色主题及偏好持久化、授权等待/取消、Token/JSON 页签、键盘焦点循环、Escape、批量刷新部分失败、删除取消/确认和 720px 窗口无横向溢出；浏览器未产生未捕获异常。
- 截图 `ui-0.1.3-*.png` 中账号均为合成界面数据，非真实登录结果。没有将 mock 注入正式产品代码；仅测试脚本在本地浏览器页面模拟 IPC。
- 实际账号登录、刷新及两账号切换仍未由开发环境重新操作；Release 与 NSIS 安装包构建成功（安装包约 3.56 MiB）；v0.1.3 便携程序启动后保持运行且创建 `Devin Switcher` 窗口，版本元数据 0.1.3。随后仅关闭本次启动的测试窗口。未替用户运行安装/卸载流程。

## 0.1.2 当前变更

- 前端 TypeScript / Vite 构建和 Rust check 通过。
- 28 项离线测试通过，详见 `test-output-0.1.2.txt`；新增真实本机 HTTP listener 测试，而非仅对 URL 字符串断言。
- 验证 `/auth` 精确路径、错误 state 拒绝、query 凭据接收、fragment 桥接页面、同源 POST、跨来源 POST 拒绝、取消、pending 文件不含回调凭据，以及普通 GitHub code 被拒绝。
- 使用合成凭据验证本地回调，不向官方服务发送测试 Token，不将合成凭据称为真实账号登录通过。
- 官网 URI 分类函数在隔离 Node VM 中执行：旧路径与 `/auth` 都通过通用 URI 检查，但仅 `/auth` 命中专用登录分支；记录和官网脚本哈希见 `official-redirect-rules.json`。
- **尚未完成真实账号的网页登录、服务端 Token 兑换、重启后的真实账号刷新与两账号切换。** 回调离线测试不能代替这些验证。
- 最新源代码已重新构建 Release 和 NSIS 安装包；安装包约 3.55 MiB。v0.1.2 便携程序启动检查通过，创建 `Devin Switcher` 窗口，随后关闭测试窗口。界面显示版本号，避免继续运行旧的无版本文件名。

下文是历史版本记录；0.1.2 的主要授权入口不再经过 Devin Desktop。

## 0.1.1 当前变更

- 前端 TypeScript 和 Vite 构建通过。
- Rust 单元与回归测试 **25 项通过，0 失败**，详见 `test-output-0.1.1.txt`。
- 新增官方 `/devin/account/login` 参数测试：官方深链、fragment、新 state，不带用户个人 login_hint。
- 新增会话观察测试：已有凭据不被误报为新登录、同账号新会话可识别、临时会话观察字段不会写入账号 payload。
- 新增取消与超时测试：失效的观察会话不读取或自动导入凭据。
- 原有模拟 Electron 加密注入测试增加只读回读检查，验证可取出一致的 session token 并交给现有导入流程。
- 0.1.1 Release 编译、NSIS 安装包构建及资源重新打包通过（约 3.45 MiB）；Release 启动后创建 `Devin Switcher` 窗口并保持运行，随后关闭测试窗口。
- 尝试在浏览器打开官方入口时网络导航超时，未完成真实网页登录。**这不是服务端拒绝回调的证据，也不是授权成功的证据。**
- 真实账号登录、回调确认、自动导入、在线刷新与两账号切换仍待用户验证。

下文保留 0.1.0 的基线验证记录；其中“无网页 OAuth”指第三方直接接收回调，已由 0.1.1 的官方客户端协作网页登录入口补充。

日期：2026-10-15，Windows x64。Node 22.19.0、Rust 1.92.0 MSVC、Visual Studio Build Tools 2022、WebView2 155.0.4283.45。

## 已通过

- `npm run build`：TypeScript 严格检查和 Vite 生产构建成功。
- `cargo check --manifest-path src-tauri/Cargo.toml --locked`：Rust 编译检查成功。
- `cargo test --manifest-path src-tauri/Cargo.toml --locked --lib -- --test-threads=1`：22 项测试通过，0 失败。原始结果保存在 `test-output.txt`。
- 原有原子写入、条件写入、备份恢复、后台加密重写、密钥并发创建、版本解析、目录选择和 protobuf 测试通过。
- 合成账号：JSON 导出/删除/重新导入兼容，账号详情中不出现明文凭据，Windows 密钥使用 DPAPI 封装。
- 新测试进程从磁盘重新读取已保存账号，验证跨进程持久化；没有使用真实账号。
- 临时模拟客户端：构造受当前 Windows 用户 DPAPI 保护的 Local State，调用原有会话注入函数，验证 `SignedIn`、API key 及 Electron v10 加密 session；解密后的合成凭据一致。
- 注入失败回滚：缺失 Local State 导致加密失败时，原有登录态仍为 SignedOut，未出现半写入状态。
- 导入 JSON 的账号 ID 路径穿越被拒绝。
- 旧 OAuth 入口返回限制说明，不生成 pending 文件；不支持的 Token 格式被拒绝。
- 浏览器布局检查：单页、添加账号弹窗、官方登录限制提示和三个导入入口可显示。浏览器预览不具备桌面 IPC，因此此检查只证明界面布局，不证明桌面功能成功。
- `npm run tauri -- build --bundles nsis`：Release 编译和 NSIS 打包成功，生成 Windows x64 安装包（约 3.42 MiB）及独立可执行文件（约 12.8 MB）。打包工具下载首次中断，后使用官方发行文件重试，并核对 Tauri 官方源码列出的 NSIS zip、NSIS.exe 和插件 SHA1 后成功打包。
- Release 程序启动检查：进程持续运行，并创建标题为 `Devin Switcher` 的窗口；随后关闭测试窗口。未对本机真实账号做切换操作。

## 尚未验证（用户选择稍后进行）

- 有效真实 Token 的服务端登录及刷新。
- 官方客户端真实网页登录后导入当前账号。
- 两个真实账号之间切换后，官方客户端显示相应账号且服务可用。
- 真实登录态失效/撤销后的在线错误识别。
- 安装向导的实际安装/卸载流程（已生成安装包，未替用户安装）。

本机发现官方客户端 3.10.48，但当前 `windsurfAuthStatus` 为 null。未导入用户凭据，未修改其登录数据库，未替用户执行真实账号切换。不能把合成凭据的离线注入测试称为真实登录验证。

## 授权结论

当前官方客户端通过 `devin://codeium.windsurf` 深链接收 `devin_code`；Cockpit 旧逻辑使用 localhost query access_token。未取得供本应用使用的授权回调注册配置，第三方网页 OAuth 不开放。提供官方客户端登录与本地导入作为替代方案。

## 原项目基线

克隆基线 915e7a20b432546660c3cd15e90f9fa527490ecc。原项目编译在代理 sidecar 的 Go 工具链下载/校验阶段失败（sum.golang.org EOF），未宣称原项目全量编译通过。原源码没有修改。
