//! Synthetic auth-compatibility tests for the official-client write path.
//!
//! These tests run against throwaway profiles only. They document what the
//! current `write_windsurf_auth_data` / `upsert_windsurf_extension_state`
//! actually do to `ItemTable` — including destructive behaviors — so a future
//! fix has a verified baseline. Passing tests here mean "behavior is pinned",
//! NOT "the behavior is proven safe against the real official client".
//! Real-account login/logout compatibility still requires the isolated
//! Windows acceptance matrix in docs/REAL-ACCOUNT-CHECKLIST.md.

use crate::modules::{auth_compatibility, windsurf_instance};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("devin-auth-compat-{}-{}", name, nanos));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn db_path(profile: &Path) -> PathBuf {
    profile
        .join("User")
        .join("globalStorage")
        .join("state.vscdb")
}

/// Create profile/User/globalStorage/state.vscdb with an ItemTable, seeded
/// with `keys` (name → raw value string).
fn seed_profile_db(profile: &Path, keys: &[(&str, &str)]) -> PathBuf {
    let db = db_path(profile);
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB);")
        .unwrap();
    for (k, v) in keys {
        conn.execute("INSERT INTO ItemTable (key, value) VALUES (?1, ?2)", (k, v))
            .unwrap();
    }
    db
}

fn read_key(db: &Path, key: &str) -> Option<String> {
    let conn = Connection::open(db).unwrap();
    conn.query_row("SELECT value FROM ItemTable WHERE key=?1", [key], |r| {
        r.get(0)
    })
    .ok()
}

fn all_keys(db: &Path) -> Vec<String> {
    let conn = Connection::open(db).unwrap();
    let mut stmt = conn.prepare("SELECT key FROM ItemTable ORDER BY key").unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .flatten()
        .collect()
}

// ---------- Literal-prefix census tests (no crypto needed) ----------
// The write path no longer deletes `windsurf_auth-*` keys at all. These
// tests pin the literal-prefix range query used by the read-only probe so
// the census reports exactly the intended key family.

fn prefixed_keys(db: &Path) -> Vec<String> {
    let conn = Connection::open(db).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT key FROM ItemTable \
             WHERE key >= 'windsurf_auth-' AND key < 'windsurf_auth.' ORDER BY key",
        )
        .unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .flatten()
        .collect()
}

#[test]
fn literal_prefix_census_matches_only_dash_prefixed_keys() {
    let root = temp_root("prefix-census");
    let profile = root.join("P");
    let db = seed_profile_db(
        &profile,
        &[
            ("windsurf_auth-a@example.invalid", "[]"),
            ("windsurf_auth-a@example.invalid-usages", "[]"),
            // Unknown future-style key under the same prefix.
            ("windsurf_auth-someFutureKey", "{}"),
            // Literal-underscore keys that do NOT match: no '-' separator.
            ("windsurf_auth", "{}"),
            ("windsurf_authx", "{}"),
            ("windsurf_auth_status", "{}"),
            // Keys outside the prefix family entirely.
            ("windsurfAuthStatus", "{}"),
            ("windsurfOnboarding", "{}"),
            (
                r#"secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.sessions"}"#,
                "{}",
            ),
            ("codeium.windsurf", "{}"),
        ],
    );

    let found = prefixed_keys(&db);
    assert_eq!(
        found,
        vec![
            "windsurf_auth-a@example.invalid",
            "windsurf_auth-a@example.invalid-usages",
            "windsurf_auth-someFutureKey",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    );
    let _ = fs::remove_dir_all(root);
}

/// Look-alike keys where the `_` position holds another character
/// (`windsurf.auth-x`, `windsurfXauth-y`, `windsurf-auth-*`) must NOT fall
/// under the literal prefix — the old `LIKE` pattern over-matched them.
#[test]
fn literal_prefix_census_ignores_lookalike_variants() {
    let root = temp_root("prefix-lookalike");
    let profile = root.join("P");
    let db = seed_profile_db(
        &profile,
        &[
            ("windsurf.auth-foreign", "1"),
            ("windsurfXauth-foreign", "1"),
            ("windsurf_auth-normal", "1"),
            ("windsurf-auth-dash-only", "1"),
        ],
    );
    let found = prefixed_keys(&db);
    assert_eq!(found, vec!["windsurf_auth-normal".to_string()]);
    let _ = fs::remove_dir_all(root);
}

// ---------- Read-only probe tests (no crypto needed) ----------

#[test]
fn probe_missing_database_reports_missing_and_creates_nothing() {
    let root = temp_root("probe-missing");
    let profile = root.join("P");
    fs::create_dir_all(&profile).unwrap();
    let report = auth_compatibility::probe_profile(&profile, Default::default());
    assert_eq!(
        report.database,
        auth_compatibility::DatabaseProbe::Missing
    );
    assert!(!report.item_table_present);
    // Nothing was created under the profile.
    assert!(fs::read_dir(&profile).unwrap().next().is_none());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn probe_corrupt_database_reports_open_failed() {
    let root = temp_root("probe-corrupt");
    let profile = root.join("P");
    let db = db_path(&profile);
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    fs::write(&db, b"this is not a sqlite database").unwrap();
    let report = auth_compatibility::probe_profile(&profile, Default::default());
    assert_eq!(
        report.database,
        auth_compatibility::DatabaseProbe::OpenFailed
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn probe_masks_labels_and_reports_census_without_secret_values() {
    let root = temp_root("probe-census");
    let profile = root.join("P");
    let secret_label = "user@probe.invalid";
    let sessions_key =
        r#"secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.sessions"}"#;
    let db = seed_profile_db(
        &profile,
        &[
            ("windsurfAuthStatus", r#"{"status":"SignedIn"}"#),
            (sessions_key, r#"{"type":"Buffer","data":[118,49,48,1,2,3]}"#),
            ("codeium.windsurf-windsurf_auth", secret_label),
            ("windsurf_auth-user@probe.invalid", "[]"),
            ("windsurf_auth-user@probe.invalid-usages", "[]"),
            // Survives cleanup: no '-' right after "windsurf_auth".
            ("windsurf_auth", "{}"),
            (
                "codeium.windsurf",
                r#"{"codeium.installationId":"inst-1","future.field":42}"#,
            ),
            ("windsurfOnboarding", "{}"),
            ("codeium.windsurf.newUnknownThing", "1"),
        ],
    );
    let before = fs::read(&db).unwrap();
    let report = auth_compatibility::probe_profile(&profile, Default::default());
    let after = fs::read(&db).unwrap();

    assert_eq!(report.database, auth_compatibility::DatabaseProbe::Opened);
    assert!(report.item_table_present);
    assert!(report.auth_status_present);
    assert_eq!(
        report.sessions_secret,
        auth_compatibility::SecretShape::Encrypted {
            prefix: "v10".into()
        }
    );
    assert!(report.selected_auth_key_present);
    assert!(report.extension_state.present);
    assert!(report.extension_state.object);
    assert!(report.extension_state.has_installation_id);
    assert!(report
        .extension_state
        .field_names
        .contains(&"future.field".to_string()));
    assert!(report.onboarding_present);

    // Two per-account prefixed keys are now reported as preserved; the bare
    // "windsurf_auth" key stays in the survivor list.
    assert_eq!(report.cleanup_targets.preserved_prefixed, 2);
    assert!(report
        .cleanup_targets
        .masked_keys
        .iter()
        .all(|k| !k.contains(secret_label)));
    assert!(report
        .cleanup_targets
        .masked_keys
        .contains(&"windsurf_auth-<label>".to_string()));
    assert!(report
        .cleanup_targets
        .survivor_keys
        .contains(&"windsurf_auth".to_string()));

    // Unknown auth-like key surfaced by name; label never appears anywhere.
    assert!(report
        .unknown_auth_like_keys
        .contains(&"codeium.windsurf.newUnknownThing".to_string()));
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains(secret_label));

    // Read-only guarantee: database bytes and siblings unchanged.
    assert_eq!(before, after);
    assert!(fs::read_dir(db.parent().unwrap())
        .unwrap()
        .all(|e| e.unwrap().file_name() == "state.vscdb"));
    let _ = fs::remove_dir_all(root);
}

// ---------- Full write-path tests (Windows: needs DPAPI Local State) ----------

#[cfg(target_os = "windows")]
mod windows_write_path {
    use super::*;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit};
    use base64::{engine::general_purpose, Engine as _};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

    const TEST_KEY: [u8; 32] = [0x42u8; 32];

    fn dpapi_encrypt(plain: &[u8]) -> Vec<u8> {
        unsafe {
            let mut input = CRYPT_INTEGER_BLOB {
                cbData: plain.len() as u32,
                pbData: plain.as_ptr() as *mut u8,
            };
            let mut output = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            CryptProtectData(&mut input, None, None, None, None, 0, &mut output)
                .expect("CryptProtectData");
            let out =
                std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(HLOCAL(output.pbData as *mut _));
            out
        }
    }

    /// Write a synthetic `Local State` carrying a DPAPI-wrapped AES key so the
    /// production encryption path runs end-to-end inside a temp profile.
    fn write_local_state(profile: &Path) {
        let mut blob = b"DPAPI".to_vec();
        blob.extend_from_slice(&dpapi_encrypt(&TEST_KEY));
        let json = json!({"os_crypt": {"encrypted_key": general_purpose::STANDARD.encode(blob)}});
        fs::write(profile.join("Local State"), json.to_string()).unwrap();
    }

    fn decrypt_buffer_secret(raw: &str) -> Vec<u8> {
        let value: Value = serde_json::from_str(raw).unwrap();
        let bytes: Vec<u8> = value["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        assert!(bytes.starts_with(b"v10"), "expected v10 prefix");
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&TEST_KEY));
        cipher
            .decrypt(aes_gcm::Nonce::from_slice(&bytes[3..15]), &bytes[15..])
            .unwrap()
    }

    const SESSIONS_KEY: &str =
        r#"secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.sessions"}"#;
    const API_URL_KEY: &str =
        r#"secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.apiServerUrl"}"#;

    fn run_write(profile: &Path, db: &Path, label: &str, token: &str) {
        let conn = Connection::open(db).unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        windsurf_instance::write_windsurf_auth_data(
            &tx,
            profile,
            &json!({"apiKey": token}),
            label,
            token,
            "https://server.self-serve.windsurf.com",
        )
        .unwrap();
        tx.commit().unwrap();
    }

    fn profile_with_db(name: &str, keys: &[(&str, &str)]) -> (PathBuf, PathBuf, PathBuf) {
        let root = temp_root(name);
        let profile = root.join("P");
        fs::create_dir_all(&profile).unwrap();
        write_local_state(&profile);
        let db = seed_profile_db(&profile, keys);
        (root, profile, db)
    }

    #[test]
    fn sessions_secret_merges_keeping_other_accounts_and_unknown_fields() {
        // Seed an official-looking sessions array with another account and an
        // unknown per-session field; the write path must merge — our session
        // goes first, foreign sessions and their unknown fields survive.
        let (root, profile, db) = profile_with_db("sessions-merge", &[]);
        {
            let conn = Connection::open(&db).unwrap();
            let seed = serde_json::to_string(&json!([
                {"id":"old-1","accessToken":"old-token","account":{"label":"a","id":"a"},
                 "scopes":["x"],"unknownFutureField":{"y":1}},
                {"id":"old-2","accessToken":"old-token-2","account":{"label":"new@example.invalid","id":"new@example.invalid"},
                 "scopes":[]}
            ]))
            .unwrap();
            let enc = windsurf_instance::encode_encrypted_buffer_json(
                seed.as_bytes(),
                None,
                &profile,
            )
            .unwrap();
            conn.execute("INSERT INTO ItemTable VALUES (?1, ?2)", (SESSIONS_KEY, enc))
                .unwrap();
        }

        run_write(&profile, &db, "new@example.invalid", "devin-session-token$synthetic");

        let raw = read_key(&db, SESSIONS_KEY).unwrap();
        let plain = decrypt_buffer_secret(&raw);
        let sessions: Value = serde_json::from_slice(&plain).unwrap();
        let arr = sessions.as_array().unwrap();
        // Our new session first; the same-label stale entry is replaced;
        // the foreign account's session survives with its unknown field.
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["account"]["label"], "new@example.invalid");
        assert_eq!(arr[0]["accessToken"], "devin-session-token$synthetic");
        assert_eq!(arr[1]["account"]["label"], "a");
        assert_eq!(arr[1]["accessToken"], "old-token");
        assert_eq!(arr[1]["unknownFutureField"], json!({"y":1}));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn undecryptable_sessions_secret_fails_closed_without_writes() {
        let (root, profile, db) = profile_with_db("sessions-corrupt", &[]);
        {
            let conn = Connection::open(&db).unwrap();
            // Valid Buffer JSON but undecryptable payload (wrong key content).
            conn.execute(
                "INSERT INTO ItemTable VALUES (?1, ?2)",
                (SESSIONS_KEY, r#"{"type":"Buffer","data":[118,49,48,9,9,9]}"#),
            )
            .unwrap();
        }
        let conn = Connection::open(&db).unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        let err = windsurf_instance::write_windsurf_auth_data(
            &tx,
            &profile,
            &json!({"apiKey": "devin-session-token$synthetic"}),
            "lbl",
            "devin-session-token$synthetic",
            "https://server.self-serve.windsurf.com",
        )
        .expect_err("undecryptable sessions must abort the write");
        assert!(err.contains("中止"));
        tx.rollback().unwrap();
        drop(conn);
        // The corrupt secret is untouched.
        assert_eq!(
            read_key(&db, SESSIONS_KEY).as_deref(),
            Some(r#"{"type":"Buffer","data":[118,49,48,9,9,9]}"#)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn write_preserves_other_accounts_usage_keys_and_merges_current_label() {
        let (root, profile, db) = profile_with_db(
            "usage-keys",
            &[
                ("windsurf_auth-old@example.invalid", "[]"),
                ("windsurf_auth-old@example.invalid-usages", "[]"),
                ("windsurf_auth-unknownFuture", "{}"),
                // Foreign extension's usage entry on the new label.
                (
                    "windsurf_auth-new@example.invalid-usages",
                    r#"[{"extensionId":"other.ext","extensionName":"Other","lastUsed":1}]"#,
                ),
                // Existing client-recorded value on the login key: preserved.
                ("windsurf_auth-new@example.invalid", r#"[{"x":1}]"#),
            ],
        );
        run_write(&profile, &db, "new@example.invalid", "devin-session-token$synthetic");
        let keys = all_keys(&db);
        // Other accounts' usage keys are preserved — no bulk delete.
        assert!(keys.contains(&"windsurf_auth-old@example.invalid".to_string()));
        assert!(keys.contains(&"windsurf_auth-old@example.invalid-usages".to_string()));
        assert!(keys.contains(&"windsurf_auth-unknownFuture".to_string()));
        // Existing login-key value kept verbatim, not reset to "[]".
        assert_eq!(
            read_key(&db, "windsurf_auth-new@example.invalid").as_deref(),
            Some(r#"[{"x":1}]"#)
        );
        let usages = read_key(&db, "windsurf_auth-new@example.invalid-usages").unwrap();
        let usages: Value = serde_json::from_str(&usages).unwrap();
        let arr = usages.as_array().unwrap();
        // Foreign extension entry preserved; ours appended.
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["extensionId"], "other.ext");
        assert_eq!(arr[1]["extensionId"], "codeium.windsurf");
        assert_eq!(arr[1]["extensionName"], "Devin");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn auth_status_merges_over_existing_client_value() {
        let (root, profile, db) = profile_with_db(
            "auth-status-merge",
            &[(
                "windsurfAuthStatus",
                r#"{"status":"SignedIn","officialFutureField":{"keep":1},"apiKey":"stale"}"#,
            )],
        );
        run_write(&profile, &db, "lbl", "devin-session-token$synthetic");
        let status: Value =
            serde_json::from_str(&read_key(&db, "windsurfAuthStatus").unwrap()).unwrap();
        // Our identity fields win; unknown official fields are preserved.
        assert_eq!(status["apiKey"], "devin-session-token$synthetic");
        assert_eq!(status["officialFutureField"], json!({"keep":1}));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn extension_state_preserves_unknown_fields_and_existing_installation_id() {
        let (root, profile, db) = profile_with_db(
            "ext-state-keep",
            &[(
                "codeium.windsurf",
                r#"{"codeium.installationId":"keep-me","future.unknown":{"a":1},"apiServerUrl":"https://old.example"}"#,
            )],
        );
        run_write(&profile, &db, "lbl", "devin-session-token$synthetic");
        let state: Value =
            serde_json::from_str(&read_key(&db, "codeium.windsurf").unwrap()).unwrap();
        assert_eq!(state["codeium.installationId"], "keep-me");
        assert_eq!(state["future.unknown"], json!({"a":1}));
        assert_eq!(
            state["apiServerUrl"],
            "https://server.self-serve.windsurf.com"
        );
        assert_eq!(
            state["windsurf.pendingApiKeyMigration"],
            "devin-session-token$synthetic"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_extension_state_fails_closed_and_key_unchanged() {
        let (root, profile, db) = profile_with_db(
            "ext-state-corrupt",
            &[("codeium.windsurf", "{{{ not json")],
        );
        let conn = Connection::open(&db).unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        let err = windsurf_instance::write_windsurf_auth_data(
            &tx,
            &profile,
            &json!({"apiKey": "devin-session-token$synthetic"}),
            "lbl",
            "devin-session-token$synthetic",
            "https://server.self-serve.windsurf.com",
        )
        .expect_err("corrupt extension state must abort the write");
        assert!(err.contains("损坏"));
        tx.rollback().unwrap();
        drop(conn);
        assert_eq!(
            read_key(&db, "codeium.windsurf").as_deref(),
            Some("{{{ not json")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_installation_id_stays_missing_and_unsupported_token_removes_migration() {
        let (root, profile, db) =
            profile_with_db("inst-id-gen", &[("codeium.windsurf", "{}")]);
        // Unsupported token shape (not sk-ws-01-/devin-session-token$/cog_)
        // → pendingApiKeyMigration removed, not written.
        run_write(&profile, &db, "lbl", "legacy-token-shape");
        let state: Value =
            serde_json::from_str(&read_key(&db, "codeium.windsurf").unwrap()).unwrap();
        // Never fabricate a device identifier: absent stays absent.
        assert!(state.get("codeium.installationId").is_none());
        assert!(state.get("windsurf.pendingApiKeyMigration").is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn api_server_secret_and_onboarding_are_written() {
        let (root, profile, db) = profile_with_db("api-url", &[]);
        run_write(&profile, &db, "lbl", "devin-session-token$synthetic");
        let raw = read_key(&db, API_URL_KEY).unwrap();
        let plain = decrypt_buffer_secret(&raw);
        assert_eq!(
            String::from_utf8(plain).unwrap(),
            "https://server.self-serve.windsurf.com"
        );
        let onboarding: Value =
            serde_json::from_str(&read_key(&db, "windsurfOnboarding").unwrap()).unwrap();
        assert_eq!(onboarding["completed"], true);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn read_profile_session_auth_status_roundtrips_written_session() {
        let (root, profile, db) = profile_with_db("read-back", &[]);
        run_write(&profile, &db, "name@example.invalid", "devin-session-token$synthetic");
        let status = windsurf_instance::read_profile_session_auth_status(&profile)
            .unwrap()
            .expect("session present");
        assert_eq!(status["status"], "SignedIn");
        assert_eq!(status["apiKey"], "devin-session-token$synthetic");
        assert_eq!(status["sessionToken"], "devin-session-token$synthetic");
        assert_eq!(status["authMethod"], "auth1");
        assert_eq!(status["name"], "name@example.invalid");
        let _ = fs::remove_dir_all(root);
    }
}
