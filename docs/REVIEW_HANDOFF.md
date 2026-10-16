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
