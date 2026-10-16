# Attribution and modification notice

Devin Account Manager is a modified, reduced desktop distribution of **Cockpit Tools** by **jlcodes / jlcodes99**.

- Original repository: https://github.com/jlcodes99/cockpit-tools
- Source revision: `915e7a20b432546660c3cd15e90f9fa527490ecc`
- Original project license: **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)**.
- License: https://creativecommons.org/licenses/by-nc-sa/4.0/
- Original README, including its licensing terms and author notice: `docs/UPSTREAM-README.md`.

The original authors retain their copyright. This derivative retains the same license. It is not an official Devin or Cognition product.

Changes made on 2026-10-15: extracted Windsurf/Devin account models, protocol, JSON import, encrypted account storage, local-client state import, Electron secret injection and default-client lifecycle; removed other providers and the proxy sidecar; replaced the general UI with a single account window; blocked the unsupported legacy loopback browser-auth entry; added official-client guidance, Windows registry discovery, DPAPI wrapping for new storage keys, transactional injection, database backup and local readback, and offline regression tests.

Version 0.1.1 adds browser login delegated to the installed official client using its existing deep-link callback, automatic import after a new client session is detected, cancellation/timeout handling, and read-only Electron session decryption using the upstream client's encryption-key helpers. It does not register the official deep-link scheme or intercept browser credentials.

Version 0.1.2 makes direct browser authorization the primary flow, restoring and adapting the upstream loopback listener for the public website's `/auth` branch. It adds fragment-to-local-POST delivery, state validation, memory-only callback credentials, explicit one-time-token/Devin-code exchanges, and local HTTP regression tests. It does not require the official client to receive the browser callback.

Historical `github_*`, `copilot_*`, and `windsurf_*` field names are retained for compatibility with upstream account exports. They do not enable other platforms in this application.

See `docs/PROVENANCE.json` for source paths and hashes before modification. Shared helper source remains attributed to the upstream project. Modified source is provided with this distribution.

0.1.3：优化单平台账号界面，增加本地搜索筛选、排序、网格/列表、隐私显示、主题与逐个批量刷新交互；保留 0.1.2 授权和账号后端。

0.1.4：参考用户提供的本机 Devin Desktop 主题和界面资源调整布局与配色。应用图标来自 E:/Devin/resources/app/resources/win32/code.ico；来源与哈希见 docs/DESIGN-REFERENCE.json。Devin 名称、图标及相关品牌资产属于其各自权利人，不因本项目代码的 CC BY-NC-SA 4.0 许可而改变其权属。本应用为独立衍生工具，不表示官方出品或背书。

0.1.5：新增认证传输层，在连接建立失败时单次直连尝试，保留上游请求载荷、认证端点与 User-Agent；添加脱敏错误类别和网络回归测试。

0.2.0：产品更名为 Devin Account Manager，兼容原存储与应用标识；复用上游 src/types/windsurf.ts 和 src/utils/dataExtract.ts，修正缺失额度处理及二进制快照已用/剩余方向，新增额度展示与回归测试，精简布局和限时成功提示。

v0.2.1（2026-10-16）：收紧额度快照有效性与缓存保留，展示原有 usage_updated_at 字段；新增批量进度/停止后续任务和读取故障恢复，修正状态与验证范围说明。授权和客户端注入协议保持原实现。
