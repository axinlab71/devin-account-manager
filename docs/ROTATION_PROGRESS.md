# Rotation Progress / Evidence Log

Branch: `feat/safe-account-rotation` · Baseline: `main` @ `d782450` (v0.4.0)
All work below is **offline-verified only**. Nothing here is real-client
acceptance; the write gate and execution gate remain closed.

## Phase 1 — auth-write compatibility audit (done, read-only)

- `src-tauri/src/modules/auth_compatibility.rs`: read-only census of a
  `state.vscdb` (`SQLITE_OPEN_READ_ONLY`, never creates files, masks account
  labels, returns key names / encrypted prefixes / field-name lists only).
- `src-tauri/src/auth_compat_tests.rs`: 12 synthetic-profile tests.
- `docs/AUTH_COMPATIBILITY.md`: per-key write/delete matrix + risk list.
- Findings (documented, **not** changed — pending explicit approval):
  `windsurf_auth-%` LIKE cleanup matches `_`/`%` wildcards; sessions array is
  whole-replaced; corrupt `codeium.windsurf` falls back to `{}`;
  missing `installationId` gets regenerated; `state_db_score` still opens the
  official DB read-write for scoring.

## Phase 2 — quota monitor + pure decisions (done, offline)

- `modules/rotation_state.rs`: persisted config/state (atomic write,
  fail-closed corrupt recovery, cooldowns, breaker, recommendation record).
- `modules/account_selector.rs`: deterministic candidate ranking.
- `modules/rotation_policy.rs`: pure `evaluate()` — threshold, freshness
  (120 s), two confirmations ≥5 s apart, margin +5pt, cooldown, global
  interval, breaker, cross-org always-confirm, `unverified` semantics →
  warning only, `limits_unknown` → blocked (unknown is never zero).
- `modules/quota_monitor.rs`: `QuotaSnapshot` (no credentials), stored-field
  extraction mirroring the frontend parser, injectable `QuotaFetcher`,
  single-flight serial monitor task (tokio, cancellable, app-lifetime only).
- `windsurf_devin_oauth.rs`: added `fetch_devin_user_status_detailed`
  (structured error + Retry-After); original function behaviour unchanged.
- IPC: `get_rotation_status`, `set_rotation_config`, `pause_rotation`,
  `resume_rotation`, `scan_rotation_now`, `get_switch_capabilities`.
- `src-tauri/src/rotation_tests.rs`: 34 synthetic tests (incl. clock anomaly,
  dismiss-cycle suppression, flow credits, execution-gate re-checks).
- Monitor honors server `Retry-After` (per-account skip window, capped 1h);
  query failures persist a generic `quota_query_last_error` onto the account
  card via `windsurf_account::record_quota_query` (own encrypted store only).

## Phase 3 — recommendation UX + execution gate (done, offline)

- `modules/switch_adapter.rs`: unified `SwitchRequest`/`SwitchOutcome`,
  per-adapter capability declarations, server-side gate re-checking
  suggestion id/expiry, identity, pool membership, cooldown, freshness,
  eligibility, global interval. No adapter is verified → confirmed requests
  return `no_verified_adapter` with zero writes attempted.
- IPC: `confirm_rotation`, `dismiss_rotation`.
- Frontend: `RotationRecommendation` banner (cross-org warning shown),
  `RotationSettings` (settings → 额度轮换 tab; `auto` option disabled),
  status event `rotation-status`, service wrappers.
- `scripts/ui-smoke.cjs`: added rotation flow assertions.

## Evidence

- `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib
  -- --test-threads=1` → **103 passed / 0 failed**
- `npm run build` → pass (tsc + vite)
- `npm run test:quota` → pass
- `node scripts/ui-smoke.cjs` (vite dev server + Playwright) → pass,
  incl. rotation tab/scan/banner/gated-confirm/dismiss
- `git -c core.whitespace=cr-at-eol diff --check` → clean

## Known boundaries

- `utils/protobuf.rs::parse_user_status_quota` now decodes the stored
  `UserStatus` proto (field map ported from the frontend decoder), so
  proto-only accounts produce real daily/weekly/credits limits. JSON fields
  still win when both exist; corrupt proto → `Unknown`, never zero.
  Longest-idle ranking is fed by `switched_away_at` in rotation state.
- `availablePromptCredits` has conflicting documented semantics → snapshots
  derived solely from it are `unverified_mapping` and cannot yield
  executable recommendations.
- Monitor queries are read-only `GetUserStatus` calls; no credential
  refresh/exchange is attempted. 401 → `current_auth_rejected` prompt to use
  the existing manual refresh.
- `confirm_rotation` now dispatches to the implemented
  `NativeAuthSwitchAdapter` (official `devin://` URI login; fresh `ott$`
  minted for devin-session accounts). It launches the URI only — the
  client's own confirm modal is the second gate, `verify_native_login`
  performs the read-only session check, and cooldown/last-switch apply
  only after `verified`. Live acceptance still pending; full-auto stays
  disabled since the official modal always requires a click.

## Phase-5 polish (latest)

- `RotationStatusDto` now carries the full `config`, so the settings page
  round-trips every field (previously only mode/threshold/interval/pool
  survived a reload).
- Settings tab gained: sort-mode select, per-account priority (shown when
  sort = `priority_first`), post-switch cooldown, global min-switch
  interval. `auto` mode remains disabled in the UI.
- `docs/HOT_SWITCH_RESEARCH.md` — static analysis of the official 3.10.67
  extension: `devin://codeium.windsurf` URI handler is a real same-process
  login path (`devin_code` / `access_token` → `handleAuthToken`, official
  confirm modal), viable for `ott$`/`oidc$` accounts only; the
  `windsurf_auth.sessions` secret-write + `/refresh-authentication-session`
  path is flagged unreliable while the client runs (in-memory secret cache).
  `get_switch_capabilities` now reports the native adapter as `blocked`
  (candidate, unverified) instead of flat `unsupported`.

## Phase-1 write-path fixes (approved + implemented)

All six items from `AUTH_COMPATIBILITY.md` §5 are implemented and pinned
by tests (`auth_compat_tests.rs`, now 109 lib tests total):

1. `windsurf_auth-*` wildcard DELETE removed entirely — only the current
   label's two usage keys are touched; all other keys preserved.
2. `windsurf_auth.sessions` merged after decrypt: same-label entries
   replaced, foreign sessions + unknown fields kept; undecryptable /
   non-array → fail-closed.
3. Corrupt `codeium.windsurf` → fail-closed instead of `{}` fallback.
4. `codeium.installationId` never fabricated — absent stays absent.
5. `windsurfAuthStatus` merges over the client's own value.
6. `<label>-usages` merges extension entries; non-array left untouched.

New: `decrypt_secret_payload` (Win GCM v10 / macOS CBC v10 / Linux CBC
v10+v11) so merging can read existing secrets; probe census field renamed
`wouldDelete` → `preservedPrefixed` and now uses a literal-prefix range
query.

## Not done / gated

- `switch_adapter` real execution: `NativeAuthSwitchAdapter` is wired for
  `confirm_rotation` (official `devin://` URI login) but never run against
  a live client; `SafeRestartSwitchAdapter` stays `blocked` until the
  A→B→A round-trip passes on a real install.
- Official-client regression matrix — needs the isolated Windows test
  environment.
- Tray / background monitoring — explicitly deferred by plan.
