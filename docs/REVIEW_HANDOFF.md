# Review Handoff — feat/safe-account-rotation

> For the reviewing agent: this document describes what was built, where, and
> what invariants must hold. Verify claims against code/tests, not prose.
> Baseline: `main` @ `d782450` (v0.4.0). All work is uncommitted on
> `feat/safe-account-rotation`. No commits, pushes, or releases were made.

> **Second-pass review findings (all addressed)**: a first independent review
> found 9 real defects; all were fixed in the current tree — see §10
> "Post-review fixes" for the exact list before re-auditing.

## 0. Scope of this branch

1. **Phase 1** — read-only auth-write audit + per-key matrix + synthetic
   compatibility tests (`docs/AUTH_COMPATIBILITY.md`, `auth_compat_tests.rs`).
2. **Phase 2** — quota monitoring + rotation decision engine (read-only w.r.t.
   the official client; never writes to it).
3. **Phase 3** — server-side execution gate + confirm/dismiss IPC + UI.
4. **Phase 4 (partial)** — `NativeAuthSwitchAdapter` implemented against the
   official `devin://` URI handler; **not yet verified on a live client**.
5. **Phase 1 fixes (approved by user)** — six write-path corrections
   (merge/fail-closed semantics) in `windsurf_instance.rs`.

## 1. Safety invariants — flag any violation

- No writes to the official client's files/DB/secrets ever occur while it
  runs. All writes happen inside `inject_account_to_profile`'s transaction,
  after the client was closed by the existing guarded path.
- Fail-closed: corrupt `codeium.windsurf`, undecryptable/non-array
  `windsurf_auth.sessions` → abort with Err **before commit** (transaction
  rolls back — verify `inject_account_to_profile` uses
  `unchecked_transaction` + `?` propagation, no manual commit before all
  writes succeed).
- We never fabricate `codeium.installationId`.
- No bulk delete of `windsurf_auth-*` keys exists anymore.
- No protocol registration/hijack of `devin://`; we only *launch* a URI via
  `rundll32 url.dll,FileProtocolHandler` — same mechanism the browser uses.
- Credentials never reach logs, frontend payloads, or IPC results
  (`QuotaSnapshot` carries no tokens; `SwitchOutcome` none either).
- Auto mode cannot execute anything: `RotationMode::Auto` degrades to a
  confirm-required recommendation; the official client additionally shows
  its own "different account" modal for URI login — a second human gate.

## 2. File map (new/changed)

| File | Role |
|---|---|
| `src-tauri/src/modules/auth_compatibility.rs` | Read-only profile probe (`SQLITE_OPEN_READ_ONLY`, masked labels, creates nothing) |
| `src-tauri/src/auth_compat_tests.rs` | Synthetic-profile write-path tests (DPAPI round-trip on Windows) |
| `src-tauri/src/modules/rotation_state.rs` | Persisted config/cooldowns/breaker/recommendation; atomic write; corrupt file → fail closed |
| `src-tauri/src/modules/quota_monitor.rs` | `QuotaSnapshot` model, field+proto extraction, `QuotaFetcher` trait + real `GetUserStatus` fetcher, serial Tokio monitor, `begin_confirm`/`finish_confirm`/`mark_verified` |
| `src-tauri/src/modules/rotation_policy.rs` | Pure decision fn; `RotationStatusDto` incl. full `config` + decision `resolution` |
| `src-tauri/src/modules/account_selector.rs` | Deterministic candidate ranking |
| `src-tauri/src/modules/switch_adapter.rs` | `SwitchRequest`/`SwitchOutcome`/`validate` gate; `execute` kept as gate+blocked for tests |
| `src-tauri/src/modules/native_switch.rs` | L2 candidate: mints `ott$` via existing `GetOneTimeAuthToken`, launches `devin://codeium.windsurf/#access_token=…`, read-only `verify()` against stored sessions label |
| `src-tauri/src/modules/windsurf_instance.rs` | §5 write fixes + `decrypt_secret_payload` + RO-first `state_db_score` + `read_profile_session_auth_status` dedup |
| `src-tauri/src/utils/protobuf.rs` | `parse_user_status_quota` — UserStatus proto quota decode (field map ported from frontend) |
| `src-tauri/src/lib.rs` | IPC: `get/set_rotation_status|config`, `pause/resume`, `scan_rotation_now`, `confirm_rotation` (async two-phase), `verify_native_login`, `dismiss_rotation`, `get_switch_capabilities`, `probe_auth_compatibility` |
| `src/components/RotationRecommendation.tsx` | Banner incl. `awaiting_client` verify button + terminal resolutions |
| `src/components/RotationSettings.tsx` | Mode/threshold/interval/sort/priority/cooldown/min-interval/pool |
| `scripts/ui-smoke.cjs` | IPC mocks incl. rotation flow assertions |

## 3. Phase-1 write fixes — review focus

`write_windsurf_auth_data` + `upsert_windsurf_extension_state`:

1. `windsurfAuthStatus`: reads existing → object → overlays our fields;
   unknown official fields preserved; corrupt/missing → ours only.
2. `windsurf_auth.sessions`: decrypt via `decrypt_secret_payload`, drop
   entries matching the new label (`account.label`/`account.id`), prepend
   new session. Undecryptable / non-Buffer / non-array → Err.
3. `windsurf_auth.apiServerUrl`: unchanged (plain URL, prefixed encrypt).
4. `codeium.windsurf`: must parse as JSON object else Err; only
   `apiServerUrl` + `windsurf.pendingApiKeyMigration` touched;
   `installationId` never generated.
5. `windsurf_auth-<label>`: preserved if present, `"[]"` only if absent.
6. `windsurf_auth-<label>-usages`: merge — update `codeium.windsurf`
   entry's `lastUsed` (keeping its unknown fields) or append; other
   extensions' entries kept; non-array existing value → untouched.
7. No `DELETE` under `windsurf_auth-` prefix at all.

`decrypt_secret_payload` mirrors `encrypt_secret_payload`: Win =
AES-256-GCM v10 (DPAPI Local State key), macOS = AES-128-CBC v10
(keychain password, pbkdf2×1003), Linux = CBC v10 (fixed key) / v11
(secret-tool). Check nonce/IV layout matches the encrypt side byte-for-byte.

## 4. Native URI login — claims to verify

Static analysis of official `codeium.windsurf` extension 0.2.0
(`docs/HOT_SWITCH_RESEARCH.md`):

- `window.registerUriHandler` routes `devin://codeium.windsurf/*`; any
  non-`/refresh-authentication-session` path → `maybeHandleUriWithToken`.
- `parseAuthRedirectUri` accepts `#access_token=` (kind `codeium`, must be
  `ott$`/`oidc$`) or `devin_code=` (kind `devin`, needs live exchange).
- Absent/foreign `state` → official confirmation modal →
  `handleAuthToken` → in-process session persist + language-server restart.
- Therefore `devin-session-token$` accounts get a fresh `ott$` via
  `GetOneTimeAuthToken(session_token, auth1, account_id, org_id)` — our
  existing `windsurf_devin_oauth` code path, now `pub(crate)`.

**Unverified**: whether the running client actually applies the login,
whether LS/ACP picks up the new identity, exact URI shape edge cases.
`verify()` only checks the stored session label after the fact — honest
`pending`/`verified` reporting, no fake success.

## 5. Decision/policy rules worth re-checking

- Low quota requires 2 observations ≥ `lowConfirmGapMs` apart (5s).
- Snapshot freshness ≤ `snapshotMaxAgeSecs` (120s); future `queriedAt` >
  5s skew → `clock_anomaly` (both policy and gate).
- 429 ≠ exhaustion; `Retry-After` sets in-memory skip window (≤1h).
- `UnverifiedMapping` confidence (ambiguous `availablePromptCredits`)
  blocks executable recommendations — warning only.
- Limits unknown/absent → `Blocked`, never treated as healthy zero.
- Cross-org candidates always require confirmation.
- Confirm gate re-validates: suggestion id/expiry/resolution, current
  identity, pool membership, cooldown, freshness, eligibility margin,
  global min interval, circuit breaker.
- Resolution state machine: every terminal **and in-flight** resolution
  (`executed`/`verified`/`blocked`/`dismissed`/`executing`/
  `awaiting_client`) blocks re-confirmation; only `failed` is retryable.
  A persisted `executing` is normalized to `failed` on load (crash
  recovery). `dismiss` also closes `awaiting_client`. Cooldown +
  `last_switch_at` apply **only** on `mark_verified`, which additionally
  requires the suggestion to be in `awaiting_client` state.
- Dismissal suppression keyed on the low-quota cycle's `first_at`.

## 6. Test evidence

- `cargo test --lib -- --test-threads=1`: **109 passed / 0 failed**
  (55 baseline + compat + rotation + proto + native_switch).
- `npm run build` (tsc + vite): pass. `npm run test:quota`: pass.
- `node scripts/ui-smoke.cjs` (Playwright, synthetic fixtures): pass.
- `git -c core.whitespace=cr-at-eol diff --check`: clean.
- **None of this validates against a real client.** The full manual
  acceptance runbook (baseline login, A→B→A, URI hot-switch, official
  logout/re-auth, storage diff, failure paths) is
  `docs/ROTATION_VALIDATION.md` — all pending an isolated Windows env.

## 7. Known limits / open questions for review

- URI token transits a `rundll32` command line — visible to same-user
  process enumeration for milliseconds; no better external channel exists.
- Session merge dedupes by label/id equality; an account whose label
  changed between sessions keeps a stale foreign-label entry (harmless —
  official provider tolerates multi-entry arrays).
- `verify()` matching: when both the session's Devin user id
  (`_switcherDesktopAccountId`) and the target's `devin_account_id` exist,
  the id comparison is authoritative (labels are NOT unique — same name,
  same email different org). Label equality remains a fallback only for
  legacy accounts without a stored Devin id, and `mark_verified` only
  applies to a suggestion actually in `awaiting_client`. Still not remote
  verification — the AI-request check is a manual acceptance step.
- `state_db_score` still falls back to RW open when RO fails (documented).
- `windsurfOnboarding` is still overwritten `{completed:true,version:1}`
  — flagged low-risk in the matrix.
- Full-auto is intentionally unreachable: official modal requires a click.

## 10. Post-review fixes (first-pass audit → current tree)

The first independent review found 9 real defects; all fixed:

1. **IPC serde break** — `DecisionKind` used `tag="kind"`, producing
   `{"kind":{"kind":"recommendation"}}` and hiding the banner in real use.
   Now serializes as a plain snake_case string.
2. **Background scans couldn't resolve the current account** — the poll
   loop passed `None`. Monitor now accepts a `current_id_resolver`
   (wired to `current_account_id` at setup); `scan_inner` falls back to
   it when no override is passed.
3. **Double-confirm could re-launch** — `executing`/`awaiting_client`
   were retryable. Both now block; persisted `executing` normalizes to
   `failed` on load; `confirm_rotation` takes `CLIENT_LOCK` +
   `lock_client_operation()` (same domain as manual switching).
4. **Verification could false-positive on label** — `mark_verified`
   requires the suggestion to be in `awaiting_client`, and `verify()`
   prefers session `account.id` ↔ `devin_account_id` over labels.
5. **Capability honesty** — the native adapter claimed `Blocked` yet ran.
   New `AdapterSupport::Experimental` level: executes only behind the
   double confirmation, never eligible for `auto`.
6. **Ambiguous `available*Credits` counted as Verified** — the
   `monthly`-present/`used`-absent branch now marks `UnverifiedMapping`
   for prompt/flex/flow alike.
7. **Circuit breaker never incremented** — adapter failures now bump
   `consecutive_failures` in `finish_confirm`.
8. **Task lifecycle** — `ensure_task` clears finished handles and a
   stale `scanning` flag left by an aborted in-flight scan.
9. **IPC name mismatch** — `NativeVerifyResult::NoSession` serialized as
   `noSession`; frontend expected `no_session`. Fixed via explicit rename;
   `session_label` → `sessionLabel` was already correct.

Also fixed alongside: status pushes could clobber in-progress settings
edits (dirty-guard added), and the smoke fixture now exercises the real
confirm → `awaiting_client` → verify → dismiss flow instead of the old
fixed-blocked stub.

## 11. Second-pass review fixes

The follow-up audit found 4 more defects; all fixed:

1. **Org ambiguity in `verify()`** — session `account` objects carry only
   `label`/`id` (no org field), and a Devin user id is shared across orgs.
   `verify()` now scans stored accounts: when the matched identity (id or
   label) is shared by another account, it reports `Pending`, never
   `Verified`. Org-context correctness remains a manual acceptance check
   (`docs/ROTATION_VALIDATION.md` §4) — local data cannot prove it.
2. **Poll scans could overwrite an in-flight recommendation** — a new
   Recommendation decision replaced `last_recommendation` regardless of
   resolution, breaking `verify`/`mark_verified`/`dismiss` for an
   unfinished official confirmation. Now an unexpired `executing`/
   `awaiting_client` record is preserved and the emitted decision is
   rebound to it (reason `switch_in_progress`).
3. **`sessionLabel` IPC field actually shipped as `session_label`** —
   enum-level `rename_all` does not rename struct-variant fields.
   Explicit `#[serde(rename = "sessionLabel")]` applied + a serialization
   test now pins `state`/`sessionLabel`/`no_session` and the
   `DecisionKind` string shape.
4. **Slow network misread as clock anomaly** — freshness/future checks
   used scan-start time against completion-time `queried_at_ms`.
   `evaluate` now runs against a timestamp taken after the queries, and
   `failed_snapshot` timestamps at completion, not scan start.

## 12. Third-pass review fixes

1. **In-flight suggestion outlives its own TTL** — `expires_at_ms` bounds
   the *offer*, not a launched operation: the official modal may still be
   open after expiry. The in-flight guard no longer checks expiry; the
   record + banner persist until explicit verify or dismiss.
2. **Ambiguity check is now fail-closed** — `list_accounts*` variants
   silently dropped unreadable entries, so a corrupt store could read as
   "no ambiguity". New `list_accounts_strict()` requires every index
   entry to deserialize; on any failure `verify()` reports `Pending`.
3. **Frontend transient state keyed to suggestion id** — `result`/
   `verify` state resets when `suggestionId` changes, and async
   confirm/verify replies check the captured id before writing back.
   A new recommendation can no longer inherit the previous outcome or
   verify against a stale target.

## 13. Fourth-pass review fixes

1. **Strict listing no longer trusts repair paths** —
   `list_accounts_strict` reads the raw index file directly (no dedup, no
   `load_account_index_checked`): the latter auto-repairs a
   missing/corrupt index by rebuilding it from detail files via
   `filter_map` — silently excluding unreadable entries *and* writing —
   which could turn "store partially unreadable" into a false `Ok`.
2. **Config save cannot discard an in-flight switch** — `set_config`
   refuses to run while a recommendation is `executing`/`awaiting_client`
   (the official modal may still be open), instead of clearing the record.
3. **Crash during `executing` is "outcome unknown", not retryable** —
   persisted `executing` now normalizes to `awaiting_client` on load
   (verify/dismiss only), not `failed`: the URI may already have been
   launched, and retrying would overlap a live official login request.

## 14. Fifth-pass review fixes

1. **In-flight record must be durable before the adapter runs** —
   `begin_confirm` ignored `rotation_state::save` errors and let the URI
   launch proceed with no persisted record (a crash then leaves nothing
   recoverable). A failed save now aborts execution and reverts the
   in-memory `executing` marker so the suggestion stays confirmable.
2. **Persisted in-flight records surface immediately on startup** —
   `status_dto` previously only rendered `last_decision` (None at boot),
   so a recovered `awaiting_client` had no verify/dismiss entry while
   paused. `in_flight_decision` now rebuilds the display decision from
   the record itself; used by both `status_dto` and scan rebinding.

## 15. Sixth-pass review fixes

1. **A `.bak` restore must not resurrect a stale `pending` offer** —
   `load()` now parses the main file itself to detect when the
   auto-restore ran. A restored record that was `pending` or `executing`
   is promoted to `awaiting_client` ("outcome unknown"): the URI may
   already have been launched between the backup and the corruption, so
   verify/dismiss is required before anything new can be recommended.
   `atomic_write`'s shared restore behaviour is unchanged — only
   rotation-state interprets restored records differently.
2. **Unknown resolution strings now fail closed** — the confirm gate
   previously whitelisted specific values; a foreign/tampered
   `resolution` fell through as confirmable. Now only `None`/`failed`
   may proceed; everything else blocks.

## 16. Seventh-pass review fixes — durable recovery gate

The persisted-file model changed from "promote the restored record" to a
**persisted, explicit reconciliation gate**:

1. **`recovered_from_backup` is a durable field on `RotationState`** —
   set when `load()` detects the `.bak` restore ran, saved immediately.
   A second restart keeps the gate (regression-tested via two loads).
2. **All non-terminal restored resolutions promote to `awaiting_client`**
   — including `failed`: `failed → relaunch → corrupt → old .bak` must
   not come back retryable.
3. **Confirm gate blocks everything while `recovered_from_backup`** —
   `recovery_review_required`, independent of which record survived.
4. **Explicit reconciliation paths**: `mark_verified` and `dismiss` clear
   the flag; `acknowledge_rotation_recovery` IPC + banner notice covers
   the no-in-flight-record case (user checks the client's current login
   themselves, then clicks 已核对).
5. **Tests**: `recovery_gate` module — restored pending/failed promotion,
   double-load persistence, confirm block, unknown-resolution fail-close
   (113 tests total).

## 17. Manual experimental native-switch entry + settings UX

The experimental native path was previously only reachable via
low-quota scan → recommendation → confirm. This pass adds a direct
manual entry so the path can be exercised for real acceptance.

1. **Account-card entry**: non-current cards show a secondary
   「免重启」 button next to the standard 「切换账号」 (restart) action.
   It opens an explicit experimental-confirmation dialog — states that
   the official Devin client may show its own confirmation modal, that
   URI launch is NOT proof of a successful switch, and that the user
   should verify + send one AI request afterwards. The standard
   restart path is unchanged.
2. **`try_native_switch` IPC** (`src-tauri/src/lib.rs`): holds
   `CLIENT_LOCK` + the inter-process client-operation lock, then
   `begin_manual_switch` persists a `manual-*` in-flight record BEFORE
   the URI launch (recovery gate, concurrent in-flight block, crash
   normalization, `.bak` promotion, `set_config` protection all reuse
   the same machinery). Success → durable `awaiting_client`; adapter
   failure → record dropped (the URI never left; a `failed` manual
   record would surface a banner retry that `validate` would always
   reject for non-pool targets). The banner shows manual-specific copy
   (`manual_switch` reason) with verify/dismiss, so closing the modal
   never strands the operation. No credentials cross IPC; no client
   files are written.
3. **Settings separation**: 「监控模式」(when/who confirms) and
   「切换方式」(restart vs experimental no-restart) are now separate
   rows; `auto` stays disabled.
4. **Backup pool redesign**: full-width aligned rows
   (checkbox/name/plan/quota/priority) with 全选/清空 and a live
   `已选 N 个` count — replaces the cramped left-desc/right-list row.
5. **Status clarity**: a 监控状态 row shows 运行中/已暂停/已关闭,
   saved pool count, last scan time (`lastScanAtMs` on the DTO), and a
   human-readable reason when no recommendation was produced.
   「立即扫描」 is labelled （使用已保存设置） while the form is dirty.
6. **Save feedback**: the full-width banner is replaced by a concise
   self-clearing `已保存，备用账号 N 个` hint.
7. **Smoke coverage**: card entry visibility (absent on the current
   card), experimental copy, launch→verify flow, pool select-all/clear
   count, dirty-scan hint, and save feedback are asserted in
   `scripts/ui-smoke.cjs`.

8. **Self-review fix — manual launches now persist an in-flight
   record**: the first version of the card entry launched the URI with
   no durable record, so a second click (or a banner confirm) could
   launch overlapping official logins and a crash left nothing to
   reconcile. `begin_manual_switch`/`finish_manual_switch` close that.
   Regression tests: persist/concurrent-block, failure-drop,
   recovery-gate block (3 new tests).
9. **Build environment fix**: `cargo test` test binaries crashed with
   `STATUS_ENTRYPOINT_NOT_FOUND` — tao's `common-controls-v6` feature
   statically imports `TaskDialogIndirect` (only in the WinSxS v6
   comctl32), and unit-test binaries never receive the manifest that
   `tauri-build` embeds into the app binary. `build.rs` now disables
   the winres-embedded manifest (`new_without_app_manifest`) and feeds
   `src-tauri/common-controls.manifest` — byte-identical to tauri-build's
   default `windows-app-manifest.xml` — to the linker via
   `cargo::rustc-link-arg=/MANIFEST:EMBED + /MANIFESTINPUT`. The arg
   applies to every binary target including lib unit tests and the app
   exe; the exe's embedded manifest was verified to contain exactly the
   Common-Controls v6 dependency plus linker-generated `asInvoker`
   trustInfo, i.e. equivalent to the previous winres output.

Verification: 116 cargo tests, `npm run build`, `test:quota`,
`ui-smoke.cjs`, `diff --check` — all green. Still **not** validated
against a real Devin Desktop client; URI launch ≠ confirmed switch.

## 18. Switch-method setting (product design change)

Requirement: standard restart stays the default; native hot-switch is an
explicit, labeled opt-in with per-account eligibility.

1. **Backend eligibility flag** — `AccountView.native_switch_credential_ready`:
   `native_switch::has_uri_compatible_credential` replicates the
   `resolve_login_token` credential-existence check (devin-session
   fields or stored `ott$`/`oidc$`) without minting or network access.
   Credentials still never cross IPC — only the boolean. Semantics
   deliberately narrow: "credential precondition met", NOT "the client
   will accept the switch" — that still requires real validation.
2. **Setting** — `devin.switchMethod` localStorage pref, `standard`
   (default) / `native`. Exposed as 「切号方式」 select under
   应用设置 → 客户端 → 切换保护.
3. **Card actions follow the method** — `standard`: primary 「切换账号」
   (restart) + secondary 「免重启」; `native`: primary 「免重启切换」 +
   secondary 「标准切号」. Section heading states the active method.
   The standard restart path (`inject_windsurf_to_vscode`) is
   untouched and always reachable.
4. **Eligibility labeling** — `native_switch_credential_ready === false`
   shows a 「暂不支持免重启」 badge on the card meta (reason in title)
   and disables the native action; the standard button stays enabled.
   No error dialog after click.
5. **Safety unchanged** — `try_native_switch` still persists the
   durable in-flight record BEFORE launching, gates on
   recovery/in-flight state, launches the official URI only, and never
   degrades to a forced restart. `全自动（未开放）` stays disabled.
6. **Credential-ready accounts** — eligibility is "has a Devin session
   credential we can attempt the official mint with": any
   `devin-session-token$` value (dedicated field or the generic
   `windsurf_auth_token` / `windsurf_api_key` / `github_access_token`
   slots used by session-token import, browser OAuth and local-client
   import), or a stored `ott$`/`oidc$`. At launch,
   `get_one_time_auth_token` sends `x-devin-auth1-token`,
   `x-devin-account-id` and `x-devin-primary-org-id` only when present
   — session-only accounts attempt with just the session credential;
   if the endpoint requires the full header set it fails honestly as
   `ott_mint_failed` rather than fabricating context. Password login
   (`添加账号 → 邮箱密码` → `add_windsurf_account_with_password`) and
   `auth1_` token paste still produce the complete four-field set for
   the strongest mint.

Smoke coverage added: unsupported badge + disabled native button +
enabled standard button; method select default/persistence; primary/
secondary button swap under `native`; 邮箱密码 tab →
`add_windsurf_account_with_password` call + modal close. Verification:
116 cargo tests, `npm run build`, `test:quota`, `ui-smoke.cjs`,
`diff --check` — green.

## 2026-10-17 �� Real-client URI delivery diagnosis + rotation dispatch fix

Live-client evidence (Windows, Devin Desktop @ E:\Devin, ext codeium.windsurf 0.2.0):

- `devin://codeium.windsurf#access_token=<t>` DOES reach the extension
  natively: renderer.log shows `maybeHandleUriWithToken �� handleAuthToken
  �� handleCodeiumAuthToken �� registerUser`. Fake tokens fail server-side
  with `invalid auth token`. No confirmation modal was observed �� this
  build calls registerUser directly (the modal likely only appears in
  specific state/account conditions).
- Root cause of earlier "nothing happens": `ELECTRON_RUN_AS_NODE=1` in the
  launching process env (inherited from Devin/VS Code integrated terminals)
  makes the spawned Devin.exe boot in Node mode and die with
  `bad option: --open-url` before forwarding. Fixed: `launch_uri` and the
  standard restart spawn (`sanitize_windows_gui_launch_env`) now strip
  `ELECTRON_RUN_AS_NODE` / `VSCODE_DEV` from the child environment.
- `launch_uri` no longer fire-and-forget: waits for the launcher exit code,
  then polls `%APPDATA%\devin\logs` up to 6s for a new session dir �� a second
  Devin.exe instance creates one before forwarding the URI. Absence reports
  `uri_delivery_unconfirmed` instead of entering "await official confirm".

Rotation confirm now honors the switch-method setting: `confirm_rotation`
takes `switchMethod`; `native` �� native URI adapter, default/standard ��
`inject_windsurf_to_vscode_inner` (extracted so the lock held by
`confirm_rotation` is not re-acquired). A successful standard outcome is
locally verified �� `mark_verified` records cooldown/last-switch; native
stays `awaiting_client` until `verify_native_login` observes the session.
Banner copy states which method will run; smoke covers both dispatches.

Still open / honestly unresolved: no proof a real `ott$` completes login
(needs user's real account click); verify reads local session only �� no
remote ACP/AI-request identity proof; `failed to fetch team settings`
root cause undetermined (network vs auth context).

Follow-up same day: after a real `devin://` login succeeded once, the
manager failed to identify the new current account �� `current_id` only
matched on token equality, and the client stores a brand-new session token
after URI login. `account_identity::current_id` now matches in order:
(1) session `_switcherDesktopAccountId` == account devin id (unique),
(2) stored token equality, (3) unique official session label. Ambiguous
matches still return no current account rather than guessing.

## 2026-10-17b — Unconfirmed-delivery lifecycle fix

Reviewer finding: when `launch_uri` cannot confirm delivery
(`uri_delivery_unconfirmed`), the URI may still be processed by the
client — but the old code dropped/marked the in-flight record `failed`,
which permitted an immediate second click and overlapping login requests.

- `quota_monitor::finish_confirm`: `uri_delivery_unconfirmed` now keeps
  the durable `awaiting_client` resolution (outcome genuinely unknown)
  instead of `failed`. It still increments `consecutive_failures` for the
  circuit breaker.
- `quota_monitor::finish_manual_switch`: same treatment — the record
  survives as `awaiting_client` rather than being dropped.
- Gates already enforce the rest: `awaiting_client` blocks a second
  `begin_manual_switch` (`switch_in_progress`), a re-`confirm`
  (`suggestion_already_resolved`, fail-closed on any non-retryable
  resolution), and `set_config`. `mark_verified` resolves it to
  `verified`; `dismiss` closes it when the user abandons.
- UI: the manual modal now shows a distinct "结果未知" hint and keeps the
  验证生效 button for `uri_delivery_unconfirmed`; the banner prints
  "结果未知：Devin 可能仍在处理该登录" plus verify/dismiss for that code.
- New Rust tests: `unconfirmed_delivery_keeps_record_awaiting_and_blocks_retry`,
  `confirm_path_unconfirmed_delivery_stays_awaiting` (120/0 green).

Line-ending note: the repo mixes CRLF files (ui-smoke.cjs, main.tsx,
style.css, windsurf.ts, lib.rs, SettingsPage.tsx — CRLF in HEAD) with LF
files. `git diff --check` flags every added `\r` on the CRLF files unless
invoked as `git -c core.whitespace=cr-at-eol diff --check` (clean).

## 2026-10-17c — Stale awaiting_client reconcile UX

Observed live: an abandoned `awaiting_client` manual record blocked every
later 「免重启」 click with `switch_in_progress` — the modal showed only
the error + 关闭, so nothing was dispatched and it looked like "no
reaction". The reconcile entry already existed on the banner (verify /
dismiss via `in_flight_decision`), but the modal hid it.

- `nativeLaunch` failure path now fetches `get_rotation_status`; when a
  durable in-flight record exists (`executing`/`awaiting_client`), the
  modal shows 上一次请求的目标账号 and explains that NO new URI was sent,
  plus two reconcile actions: 「验证生效」 (runs the read-only session
  check against the *previous record's* target — not the clicked card) and
  「放弃并重试」 (`dismiss_rotation` → back to the pre-launch step so a
  fresh launch always requires a new explicit click).
- ui-smoke: `try_native_switch` mock now rejects a second launch while a
  manual record is awaiting (matching `begin_manual_switch`), and a new
  block exercises blocked → reconcile → abandon → relaunch.

## 2026-10-17d — Stronger delivery evidence, remote probe, launch timeout

Reviewer feedback round: (1) "new log session dir" only proved a second
Devin.exe spawned — not handler acceptance; (2) verification was purely
local-session; (3) the launcher wait had no total timeout.

- **Two-level delivery evidence** (`native_switch.rs`): before launch we
  snapshot every `window*/renderer.log` under the client's logs root with
  its byte length; after the launcher exits we poll ~6s. A new session dir
  → `ClientProcess`; URI-handler trace markers appended to a renderer log
  (`maybeHandleUriWithToken`, `handleAuthToken`, `handleCodeiumAuthToken`,
  `auth redirect URI`) → `ExtensionHandler` (stronger: the URI reached the
  extension's auth code path). Neither → `uri_delivery_unconfirmed`, and
  the durable record still stays `awaiting_client` — unknown is not failed.
  When no logs dir exists at all the launch also reports unconfirmed rather
  than silently succeeding.
- **Launcher bound**: the PowerShell `try_wait` loop now has a 15s hard
  deadline — a hung dispatcher is killed and the delivery probe still runs,
  so the operation can no longer wait forever while holding CLIENT_LOCK.
- **Remote probe after local verify** (`verify` → async): on a local
  identity match we additionally call read-only `GetUserStatus` with the
  client's *current* session token. `Verified.remoteStatus`:
  `passed` (backend accepts the token) / `rejected` (401/403) /
  `unavailable` (network/parse/no token). Still not proof the ACP agent
  uses the identity — the UI keeps asking for one AI request — but a
  rejected token now surfaces instead of looking like success. Frontend
  shows the remote result in both the modal and the banner.
- New test: `uri_handler_markers_match_real_log_traces` (121/0 green).

## 2026-10-17e — Five-issue review round: in-flight gate, stale-offer revocation, policy fixes

Reviewer found five logic issues (P1 x2, P2 x3). All fixed; 128/0 tests.

- **P1 standard switch bypassed in-flight native op**: manual
  `inject_windsurf_to_vscode` only held the client locks — once a URI
  launch returned, the lock was free while the client might still process
  the login, so a restart switch could race it. New shared gate
  `QuotaMonitor::ensure_no_in_flight_switch` (rejects with
  `in_flight_switch_pending` while any durable record is `executing` or
  `awaiting_client`) is wired into the standard-switch entry (lib.rs ~248)
  AND the recovery restore (`restore_last_client_state`, ~330). Verify /
  dismiss remain the only exits.
- **P1 stale low-quota offer stayed confirmable after recovery**: two
  layers. (a) `switch_adapter::validate` now re-checks the *current*
  account before execution — its snapshot must exist, be fresh
  (`snapshot_max_age_secs`), healthy, verified-semantics, and still
  `is_low(threshold)`; new codes `current_snapshot_missing`,
  `current_snapshot_stale`, `current_query_unhealthy`,
  `current_semantics_unverified`, `current_no_longer_low` (the last covers
  both "recovered" and "limits unmeasurable" since `is_low` is false for
  both). `begin_confirm` passes the monitor's own latest snapshot map, so
  a missing scan fails closed. (b) The scan now *durably revokes* a
  still-open offer (`resolution: None` or retryable `failed`) for the
  current account whenever `clear_low_observation` fires — the trigger
  condition is gone, not just the banner.
- **P2 NotifyOnly required a backup**: `evaluate` now returns
  `Warning("low_quota_notify_only")` immediately after a confirmed
  verified-low current account, before candidate selection — an empty
  pool no longer suppresses the warning. `clear_low_observation` stays
  true.
- **P2 unverified-semantics warning did not clear the observation**: the
  scan bookkeeping now applies `decision.clear_low_observation` for every
  decision kind (was: only `Blocked`/`NoAction`). A verified-low →
  unverified → verified-low sequence restarts the double-confirmation
  window from zero instead of resuming the stale streak.
- **P2 standard completion overclaimed verification**: the restart path
  proves local write + identity only. `confirm_rotation` now calls new
  `mark_executed` (resolution `executed`) instead of `mark_verified`;
  the banner shows "本地写入校验通过并已重启客户端；账号与服务连接待确认"
  for `executed`, and "已完成切换并通过官方会话验证" only for `verified`
  (native read-only session check). `client_recognized` stays `Unknown`,
  `remote_verified` stays `NotAttempted` for the standard outcome.

New tests: `confirm_rejected_when_current_no_longer_low` (+2 sibling
rejection cases), `notify_only_warns_without_backup`,
`in_flight_gate_blocks_side_paths_until_reconciled`,
`standard_completion_records_executed_not_verified`,
`scan_revokes_open_offer_once_current_recovers`,
`warning_clears_observation_and_next_low_restarts_fresh` → 128/0.
