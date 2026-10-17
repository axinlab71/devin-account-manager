# Native switch responsiveness — 2026-10-17

Changes in this working tree:

- Return process-level URI dispatch evidence immediately instead of waiting
  an extra two seconds for optional extension error traces. This is not
  evidence of successful authentication.
- The manual dialog and pending recommendation automatically perform serial,
  read-only identity checks after 700 ms, then 1.5 seconds after each completed
  check, for at most 45 seconds of scheduling. An already-running request may
  finish after that deadline. Closing/changing the view cancels future checks
  and stale UI updates, not the official client's login operation.
- Concurrent checks for the same target share one IPC request. No URI is
  retried by the automatic verification loop.
- The optional remote credential probe is bounded to six seconds. Only a
  matched local identity AND an accepted remote credential complete the
  pending switch record. Rejection/offline results retain the pending record
  and manual verify/dismiss controls.

Verification covers synthetic UI completion without a second verify click
or URI, plus remote-result completion guards. Real-client switching, ACP
identity, organization correctness and official logout/relogin still require
manual acceptance. Full unattended rotation remains disabled; automatic
verification does not enable automatic account switching.

## Reminder and monitoring follow-up

- Confirmed low-quota notifications are independent of the switch interval
  and do not require a backup account. Smart switching retains its interval
  and candidate safety checks.
- Settings provide explicit save-and-enable, pause/resume errors, empty-pool
  guidance and readable warning text. Monitoring stops when the app exits.
- A transient unavailable remote probe continues bounded verification;
  accepted/rejected credentials stop it. This never launches another URI.
- Read-only inspection of installed Devin 3.10.67 confirms that an incoming
  auth URI bypasses the modal only if its state matches a client-owned pending
  login state. No public always-allow interface was identified. The switcher
  does not manufacture that state, modify the extension, or click the modal.

## Official login-service error follow-up

The installed renderer logs contained auth-redirect/login-service failures,
without a conclusive status or transport cause in the inspected tail. A
specific server-side cause has not been established.

Native switching no longer accepts stored `ott$` credentials or falls back
to older credentials after a mint error. Session-based switching must obtain
a fresh one-time credential within a 15-second bound before dispatch. OIDC
imports retain their prior path, but availability is not a validity guarantee.
Standard switching and account data remain unchanged. Offline tests check
that old OTT-only accounts cannot enter the native path; real server/client
login-service recovery still needs a live retry by the user.

## Account workspace and polling acceptance

The reference-inspired light palette, circular avatars, grouped filters and
quota panels live in `src/account-theme.css`; the three/two/one-column grid,
dark mode, keyboard controls and account operations are retained.

The production scan pipeline is tested with synthetic consecutive snapshots:
first low observation, confirmed-low recommendation, then network failure
revoking the old offer. These scans do not launch the switch adapter. This
is offline pipeline coverage, not a live timed account-rotation acceptance.
Unattended switching is still disabled, and the official Yes dialog remains.

## Manager lifecycle and settings consistency

- A lifetime OS file lock in the manager's own data directory prevents
  multiple manager processes from running separate monitors against the same
  state. Duplicate Windows launches restore/activate the existing window.
  This lock is separate from the existing per-operation client lock.
- Settings, pause and resume stage a cloned state, persist it, then replace
  live state. Failed writes leave live settings and the failure breaker
  unchanged. Config changes now persist invalidation of old suggestions and
  observations together, and clear the old displayed decision.
- Offline regression coverage includes lock contention/release and failed
  state writes. None of these changes alter official authentication storage.

## Single-click native flow

Account-card native actions launch directly and show a progress dialog, with
no second manager confirmation. The official Yes modal remains mandatory
when requested by Devin. A synchronous frontend guard prevents duplicate
same-tick launches; backend durable in-flight and process locks still apply.
Matched local identity plus accepted remote credential closes the progress
dialog and refreshes the account list. If the user closes the progress view,
the pending banner continues read-only verification. Explicit abandon-and-
retry authorizes one new request; unknown outcomes are never auto-retried.
