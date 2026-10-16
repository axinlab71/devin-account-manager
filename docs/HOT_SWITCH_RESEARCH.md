# L2 Hot-Switch Research — Devin Desktop 3.10.67 (extension `codeium.windsurf` 0.2.0)

Source: read-only static analysis of the official
`resources/app/extensions/windsurf/dist/extension.js` and `package.json`.
No client files were modified for this audit. All mechanisms below are
**findings, not verified capabilities** — each needs a real-environment test
before the corresponding adapter can report `supported`.

## 1. Where sessions live at runtime

`WindsurfAuthProvider` is a real `vscode.authentication` provider
(id `windsurf_auth`, label "Devin", `supportsMultipleAccounts: false`).
Sessions are stored via `context.secrets` under key
`windsurf_auth.sessions` (plus `windsurf_auth.apiServerUrl`) — the same
encrypted values our offline write path targets in `state.vscdb`.

## 2. Official change notification: `secrets.onDidChange`

`handleSecretChange` watches `windsurf_auth.sessions`, re-reads it, diffs
added/removed, fires `_sessionChangeEmitter` (`onDidChangeSessions`), and
restarts the language server when `apiServerUrl` changed.

**Critical caveat:** VS Code `SecretStorage`/`IStorageService` is
in-memory-cached inside the running process. An *external* write to
`state.vscdb` while the client runs is (a) not guaranteed to be observed and
(b) at risk of being overwritten by the next storage flush. Writing the
sessions key into a running client's DB is therefore **not** a reliable or
safe L2 primitive. Confirmed safe only while the client is closed (today's
restart path).

## 3. Official external trigger: `devin://` URI handler

`window.registerUriHandler` handles `devin://codeium.windsurf/<path>`:

| Path | Behaviour |
|---|---|
| `/refresh-authentication-session` | Fires `AuthSessionChangeType.AuthenticationRefreshEvent` — an official "auth changed elsewhere, re-sync" hook. Whether it makes `secrets.get` return fresh data after an external write needs real testing (see §2 caveat). |
| other paths with `devin_code` / `access_token` | `maybeHandleUriWithToken` → `parseAuthRedirectUri`. When `state` doesn't match a pending login it shows an **official modal**: "Are you sure you want to log in using a different account?" → Yes → `handleAuthToken` performs a real in-process login. |

`parseAuthRedirectUri` accepts:
- `devin_code=<code>` (query or fragment) → `kind: "devin"` → `exchangeDevinCode` → session token → session persisted in-process, LS restarted.
- `access_token=<token>` (fragment) → `kind: "codeium"` → `registerUser` → apiKey; token must start with `ott$`/`oidc$`.

## 4. L2 viability per account type

- **codeium-kind accounts** (`ott$`/`oidc$` token stored): a URI such as
  `devin://codeium.windsurf/?...#access_token=<tok>` can drive a real
  same-process login via the official handler. The modal requires a human
  click — this matches "smart-confirm" mode, and permanently blocks
  unattended full-auto (documented limitation, by design).
- **devin-session accounts** (`devin-session-token$...`): the URI path
  requires a *fresh* `devin_code` (consumed at exchange; cannot be derived
  from stored tokens). Same-process switching for these needs either a new
  interactive code or the secrets-write path — both unverified.
- `PROVIDE_DEVIN_AUTH_CODE_TO_AUTH_PROVIDER` command exists
  (`handleAuthToken({kind:"devin", devinCode})`) but `executeCommand` is
  in-process only — no supported external invocation.

## 5. What this means for `NativeAuthSwitchAdapter`

| Mechanism | Verdict |
|---|---|
| External DB write + `/refresh-authentication-session` | **Unverified, risky** — in-memory cache may ignore or clobber it. Not used. |
| `devin://` URI with stored `ott$`/`oidc$` token | **Implemented, unverified** — see §6. |
| `devin://` URI for `devin-session-token$` accounts | **Implemented via fresh `ott$`** — `GetOneTimeAuthToken(session_token, auth1, account_id, org_id)` mints a one-time `ott$` server-side (the same call our add-account flow already performs), which the handler accepts as `access_token`. No interactive `devin_code` needed. |
| In-process `executeCommand` / command palette automation | **Out of scope** — no supported external interface; UI automation is fragile and unsafe. |

## 6. Implemented path (`native_switch.rs`, live test pending)

`confirm_rotation` now: gate re-validates → adapter resolves a credential
(fresh `ott$` for devin-session accounts, stored `ott$`/`oidc$` otherwise)
→ launches `devin://codeium.windsurf/#access_token=<pct-encoded>` via
`rundll32 url.dll,FileProtocolHandler` → the client shows its own
different-account modal → `verify_native_login` (new IPC) read-only
decrypts `windsurf_auth.sessions` and compares the session label to the
target's known identities; on match the monitor marks the switch
`verified` and applies cooldown/last-switch.

Honest reporting: launching the URI is all we do — verification fields
stay `not_attempted` until the read-back confirms. If the official modal
is cancelled nothing changes; the suggestion stays retryable
(`awaiting_client` is not a terminal resolution).

**Not yet verified on a live client** — do not claim L2 until a real
A→B→A run confirms the session actually changes and AI requests use the
new account. Full-auto stays disabled regardless: the official modal
always needs a human click, which matches the "confirm" model.
