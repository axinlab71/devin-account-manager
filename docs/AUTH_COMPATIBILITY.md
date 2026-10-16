# 官方客户端认证写入兼容性矩阵（阶段一）

> 基线：main / v0.4.0 / `d782450`，分支 `feat/safe-account-rotation`。
> 本文记录 `windsurf_instance.rs` 写入路径对官方 profile
> `User/globalStorage/state.vscdb` 的**逐键实际行为**。§5 的六项修正已按
> 批准实施并由合成测试固定（见 `src-tauri/src/auth_compat_tests.rs`）。
> “已固定行为”不等于“对真实官方客户端已证明安全”；官方退出/重新登录
> 回归仍待隔离环境验收。

## 1. 写入入口与调用链

```
inject_windsurf_to_vscode (lib.rs)
  → close_windsurf → client_recovery::guarded_with_close（加密快照）
    → inject_account_to_profile(profile_dir, account_id)
      → ensure_state_db_for_injection（缺库时从评分最高的候选目录整库复制
        state.vscdb；并可能复制 storage.json）
      → Connection::open（读写模式）
      → 组装 auth_status（apiKey/name/email/apiServerUrl/status=SignedIn/
        user/timestamp/sessionToken/authMethod/userStatusProtoBinaryBase64/
        accountId/primaryOrgId）
      → 事务：write_windsurf_auth_data → commit
```

## 2. ItemTable 逐键矩阵（已按 §5 修正，合成测试已固定新行为）

| 键 | 操作 | 实际行为 | 残余风险 |
| --- | --- | --- | --- |
| `windsurfAuthStatus` | 读+写（REPLACE） | **读官方现值后合并**：我们的身份字段（apiKey/name/email/…）覆盖，官方自行新增的未知字段保留。官方现值损坏/缺失时退回纯我们的字段集 | 官方未来新增字段的语义未审计（但不再丢失） |
| `secret://{…"windsurf_auth.sessions"}` | 读+解密+合并+写（加密 Buffer） | 解密现有数组，剔除同 label/id 的旧条目，新会话置顶，**其他账号会话与未知字段全部保留**。现有值存在但无法解密、非 Buffer JSON 或非数组 → **fail-closed 拒绝写入** | 解密依赖各平台 secret 路径；v11 on Windows 等新前缀出现时会拒绝写入而非覆盖 |
| `secret://{…"windsurf_auth.apiServerUrl"}` | 写（REPLACE，加密 Buffer） | 明文为纯 URL 字符串 | 低 |
| `codeium.windsurf-windsurf_auth` | 写（REPLACE） | 明文 = 账号 label（认证提供者"选中账号"键） | label 形态（name/email/login 回退链）与官方实际值是否一致未核对 |
| `codeium.windsurf`（扩展状态 JSON） | 读+写（REPLACE） | 原值必须是可解析的 JSON 对象，否则 **fail-closed 拒绝写入**；仅改 `apiServerUrl`、按 token 类型设置或删除 `windsurf.pendingApiKeyMigration`，其他未知字段保留；`codeium.installationId` **缺失时保持缺失，绝不生成** | 无 installationId 时官方客户端首次运行自行生成，与官方行为一致 |
| `windsurfOnboarding` | 写（REPLACE） | 覆盖为 `{completed:true,version:1,timestamp}` | 官方版本字段若升级会被压回 1；影响未实测 |
| `windsurf_auth-<label>` | 条件写 | **已存在则保留官方值**，缺失才写 `"[]"` | 该键原始语义未确认（疑似 VS Code 认证账号使用跟踪） |
| `windsurf_auth-<label>-usages` | 读+合并写 | 读现有数组：有 `extensionId=="codeium.windsurf"` 条目则就地更新 lastUsed（保留其未知字段），否则追加；其他扩展条目保留。现有值非数组 → 不动该键 | 无 |
| `windsurf_auth-*`（其余全部） | **不删** | 不再有任何批量删除。其他账号 usage 键与未知新键全部保留，与官方客户端行为一致 | 无 |

## 3. 只读入口核对

| 函数 | 结论 |
| --- | --- |
| `read_profile_session_auth_status` | 已用 `SQLITE_OPEN_READ_ONLY`，只读 sessions/apiServerUrl 两个 secret 键并解密；不创建文件。是新增只读探测的正确范式 |
| `state_db_score`（被 `get_default_windsurf_user_data_dir` 使用） | 已改为**优先 READ_ONLY** 打开官方库评分（不产生 -shm/-wal、不触碰 mtime）；仅在 RO 打开失败（锁定/WAL 状态）时回退读写打开，候选目录选择行为不变 |
| `windsurf_user_data_dir_candidates` / `pick_preferred_…` | 纯路径评分选择，无写入；选择结果依赖评分而非固定首个候选 |
| `ensure_state_db_for_injection` | profile 缺库时从最佳候选**整库复制** state.vscdb 并可能复制 storage.json——多实例注入路径的隐含写入，矩阵需覆盖 |

## 4. 新增只读探测 `auth_compatibility.rs`

`probe_profile(profile, client_meta)` / `probe_default_profile(configured_path)`：

- `SQLITE_OPEN_READ_ONLY` 打开；库缺失→`Missing`；损坏/打不开→`OpenFailed`；缺 ItemTable→`Opened` + `itemTablePresent=false`。**不创建任何文件**（测试断言目录零变化、库字节不变）。
- 输出仅键名/存在性/加密前缀（v10/v11）/扩展状态字段名清单；`windsurf_auth-*` 键中的账号 label 一律 `<label>` 脱敏；非 schema 形态键名报 `<masked-key>`。不回传任何 secret 明文或 token。
- `cleanupTargets` 用字面前缀区间查询统计 `windsurf_auth-` 键，字段为 `preservedPrefixed`/`maskedKeys`/`survivorKeys`——写入路径已不再批量删除这些键，探测报告的是"保留"而非"将删"。
- `client` 字段复用 `client_version::detect_windsurf_version_metadata`（IDE/扩展版本），供能力报告。
- IPC：`probe_auth_compatibility`（只读，无参数），返回 `AuthCompatibilityReport` 摘要。

## 5. 已批准的写入修正（全部实施，测试已固定）

1. ~~`windsurf_auth-%` LIKE 清理~~ → **已移除批量删除**。只 upsert 当前 label 的两个键，其余 `windsurf_auth-*`（其他账号 usage、未知新键、形似变体）全部保留。探测 census 改用字面前缀区间查询。
2. ~~sessions 数组单元素替换~~ → **解密合并**：剔除同 label 旧条目、新会话置顶、其他账号条目及未知字段保留；无法解密/非数组 → fail-closed 拒绝写入。
3. ~~`codeium.windsurf` 损坏回退 `{}`~~ → **fail-closed**：非 JSON 对象即拒绝写入。
4. ~~`codeium.installationId` 缺失时生成新 UUID~~ → **永不生成**：缺失保持缺失，官方客户端首次运行自行生成。
5. ~~`windsurfAuthStatus` 整体替换~~ → **读现值合并**：我们的身份字段覆盖，官方未知字段保留。
6. ~~`windsurf_auth-<label>-usages` 数组重建~~ → **数组合并**：就地更新 `codeium.windsurf` 条目 lastUsed 并保留其未知字段，其他扩展条目保留，非数组值不触碰。

新增跨平台 `decrypt_secret_payload`（Windows AES-256-GCM v10 / macOS AES-128-CBC v10 / Linux CBC v10+v11）供合并读取；解密失败一律中止写入而非覆盖。

## 6. 仍待真实验收（blocked）

- 官方登录→退出→重新网页登录在上述写入后是否始终可用（3.10.67）。
- 官方 sessions/状态键的完整字段集与 3.10.67 实际形态。
- 删除 usage 键后官方账号选择器/重登录行为。
- A→B→A 真实切换与远端验证。

合成测试锚定的是现有行为，不是官方兼容性结论。修正任何写入路径前，须报告具体文件、字段、可恢复性并等待批准。
