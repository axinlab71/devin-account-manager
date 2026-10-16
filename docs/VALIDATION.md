# 验证记录

## v0.2.1 · 2026-10-16

本次从已发布 v0.2.0 与后续仓库/文案提交继续开发；未重置已有工作。

### 已执行

- TypeScript 严格检查与 Vite 构建通过；Release 与 NSIS 构建成功（安装包约 3.91 MiB）。便携程序版本元数据为 0.2.1，启动后创建 Devin Account Manager 窗口并保持运行，随后关闭本次测试窗口。
- 36 项 Rust 离线回归测试通过，涵盖原有回调/state、凭据不落 pending、加密持久化、模拟客户端注入/回读与失败回滚、代理连接失败后的直连尝试。
- 本次新增额度快照边界：空对象、仅身份信息、无效数值不算新额度；零与嵌套额度仍有效；空快照刷新保留旧缓存；有效新快照的更新时间可跨文件读回。
- 额度解析脚本验证 JSON camel/snake、零与未知、已用/剩余换算、Credits 总量/已用/剩余、重置时间与二进制 protobuf。
- Edge 无头浏览器用合成 IPC 数据验证：额度显示、失败缓存标记、批量停止后续请求、客户端状态失败时账号仍可见、本地存储读取失败后的重试，以及原搜索/筛选/主题/授权取消/导入页签/删除与 720px 布局。
- 截图使用合成账号、合成额度；测试不会调用真实登录或切换账号。运行输出保留在本地 research，未提交私人诊断日志。

### 实际验证的边界

本次没有替用户操作真实网页登录、远端额度刷新、两账号切换或安装/卸载。程序启动检查仅确认窗口与进程可用；模拟注入不能证明真实客户端远端登录成功。

`usage_updated_at` 沿用上游可选字段；旧账号没有该时间时保持未知。额度是最近一次成功保存的服务端响应，不保证打开窗口时已实时同步。批量刷新逐个执行，停止功能只停止尚未开始的任务。

### 复现命令

```powershell
npm run build
npm run test:quota
cargo test --manifest-path src-tauri/Cargo.toml --locked --lib -- --test-threads=1
# 单独启动 npm run dev，再运行：
node scripts/ui-smoke.cjs
```

界面测试需要安装 Playwright 和 Edge，也可用 DEVIN_PLAYWRIGHT_PATH 指定运行时包目录。

## 历史基线

- v0.2.0：额度组件、精简布局、限时成功提示；当时 32 项 Rust 回归通过。
- v0.1.5：认证传输层连接失败后单次直连，保留 TLS 校验、请求体和 User-Agent；HTTP 拒绝、重定向、连接后超时不触发新增的直连重发。
- v0.1.2：/auth loopback 回调和 fragment 本机桥接；静态官网分类验证见 official-redirect-rules.json。静态规则和离线回调测试不能代替服务端真实凭据兑换。

上游来源和修改记录见 NOTICE.md 与 PROVENANCE.json。
