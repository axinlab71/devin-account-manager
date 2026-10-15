//! Offline tests use synthetic credentials and isolated temporary profiles.
//! They do not prove a real Devin account can authenticate or send requests.
use crate::{models::windsurf::WindsurfOAuthCompletePayload, modules::*};
use serde_json::{json, Value};

struct IsolatedData(std::path::PathBuf);
impl IsolatedData {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "devin-switcher-regression-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        std::env::set_var("COCKPIT_TOOLS_TEST_DATA_DIR", &path);
        Self(path)
    }
}
impl Drop for IsolatedData {
    fn drop(&mut self) {
        std::env::remove_var("COCKPIT_TOOLS_TEST_DATA_DIR");
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn payload(token: &str) -> WindsurfOAuthCompletePayload {
    WindsurfOAuthCompletePayload {
        github_login: "offline-fixture".into(),
        github_id: 42,
        github_email: Some("fixture@example.invalid".into()),
        github_access_token: token.into(),
        copilot_token: token.into(),
        windsurf_api_key: Some(token.into()),
        windsurf_api_server_url: Some("https://server.self-serve.windsurf.com".into()),
        windsurf_auth_status_raw: Some(json!({"apiKey":token})),
        ..Default::default()
    }
}

#[test]
fn upstream_json_roundtrip_persistence_encryption_and_delete() {
    let _lock = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let data = IsolatedData::new();
    let token = "devin-session-token$offline-test-only";
    let saved = windsurf_account::upsert_account(payload(token)).unwrap();
    let id = saved.id;
    let raw = std::fs::read_to_string(
        data.0
            .join("windsurf_accounts")
            .join(format!("{}.json", id)),
    )
    .unwrap();
    assert!(!raw.contains(token));
    assert!(raw.contains("AES-256-GCM"));
    #[cfg(target_os = "windows")]
    assert!(
        std::fs::read_to_string(data.0.join("secure-account-storage.key"))
            .unwrap()
            .starts_with("dpapi:")
    );
    // Force a fresh read from disk, rather than a React/in-memory cache.
    assert_eq!(
        windsurf_account::load_account(&id)
            .unwrap()
            .github_access_token,
        token
    );
    // A new test process has no parent memory caches and reads the persisted account.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "regression_tests::child_process_reads_persisted_account",
            "--test-threads=1",
        ])
        .env("DEVIN_SWITCHER_READBACK_ID", &id)
        .output()
        .unwrap();
    assert!(child.status.success(), "fresh-process account read failed");
    let exported = windsurf_account::export_accounts(&[id.clone()]).unwrap();
    windsurf_account::remove_account(&id).unwrap();
    assert!(windsurf_account::list_accounts_checked()
        .unwrap()
        .is_empty());
    let imported = windsurf_account::import_from_json(&exported).unwrap();
    assert_eq!(imported[0].id, id);
    assert_eq!(imported[0].github_access_token, token);
    assert_eq!(windsurf_account::list_accounts_checked().unwrap().len(), 1);
    windsurf_account::remove_account(&id).unwrap();
    assert!(windsurf_account::load_account(&id).is_none());
}

#[test]
fn child_process_reads_persisted_account() {
    let Ok(id) = std::env::var("DEVIN_SWITCHER_READBACK_ID") else {
        return;
    };
    let saved = windsurf_account::load_account(&id).expect("persisted fixture");
    assert_eq!(
        saved.github_access_token,
        "devin-session-token$offline-test-only"
    );
}

#[test]
fn imported_account_id_cannot_escape_storage() {
    let _lock = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _data = IsolatedData::new();
    let mut value =
        serde_json::to_value(windsurf_account::upsert_account(payload("synthetic")).unwrap())
            .unwrap();
    value["id"] = json!("../outside-account");
    assert!(windsurf_account::import_from_json(&value.to_string()).is_err());
    assert!(windsurf_account::load_account("../outside-account").is_none());
    assert!(windsurf_account::remove_account("../outside-account").is_err());
}

#[tokio::test]
async fn direct_browser_auth_starts_without_a_client_and_can_be_cancelled() {
    let _lock = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let data = IsolatedData::new();
    let start = windsurf_oauth::start_login().await.unwrap();
    assert!(start.callback_url.as_deref().unwrap().ends_with("/auth"));
    windsurf_oauth::cancel_login(Some(&start.login_id)).unwrap();
    assert!(windsurf_oauth::poll_login(&start.login_id).await.is_err());
    assert!(!data.0.join("windsurf_oauth_pending.json").exists());
    assert!(windsurf_oauth::build_payload_from_token("").await.is_err());
    assert!(
        windsurf_oauth::build_payload_from_token("unsupported-fixture")
            .await
            .is_err()
    );
}

#[cfg(target_os = "windows")]
#[test]
fn upstream_injection_encrypts_electron_session_and_rolls_back_on_failure() {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use base64::{engine::general_purpose::STANDARD, Engine};
    let _lock = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let data = IsolatedData::new();
    let profile = data.0.join("fake-client");
    let storage = profile.join("User/globalStorage");
    std::fs::create_dir_all(&storage).unwrap();
    let db = storage.join("state.vscdb");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch("CREATE TABLE ItemTable (key TEXT PRIMARY KEY,value TEXT); INSERT INTO ItemTable VALUES ('unrelated.setting','preserved'); INSERT INTO ItemTable VALUES ('windsurfAuthStatus','{\"status\":\"SignedOut\"}');").unwrap();
    let token = "devin-session-token$synthetic-ide-token";
    let saved = windsurf_account::upsert_account(payload(token)).unwrap();
    // Missing Local State causes encryption to fail after auth status preparation.
    assert!(windsurf_instance::inject_account_to_profile(&profile, &saved.id).is_err());
    let raw: String = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key='windsurfAuthStatus'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&raw).unwrap()["status"],
        "SignedOut"
    );
    let key = [23u8; 32];
    let mut protected = b"DPAPI".to_vec();
    protected.extend(key_protection::protect(&key).unwrap());
    std::fs::write(
        profile.join("Local State"),
        json!({"os_crypt":{"encrypted_key":STANDARD.encode(protected)}}).to_string(),
    )
    .unwrap();
    windsurf_instance::inject_account_to_profile(&profile, &saved.id).unwrap();
    let raw: String = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key='windsurfAuthStatus'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let status: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(status["status"], "SignedIn");
    assert_eq!(status["apiKey"], token);
    let secret_key =
        r#"secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.sessions"}"#;
    let raw: String = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key=?1",
            [secret_key],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!raw.contains(token));
    let buffer: Value = serde_json::from_str(&raw).unwrap();
    let bytes: Vec<u8> = buffer["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(&bytes[..3], b"v10");
    let decrypted = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(Nonce::from_slice(&bytes[3..15]), &bytes[15..])
        .unwrap();
    let sessions: Value = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(sessions[0]["accessToken"], token);
    let reread = windsurf_instance::read_profile_session_auth_status(&profile)
        .unwrap()
        .unwrap();
    assert_eq!(reread["sessionToken"], token);
    assert_eq!(reread["authMethod"], "auth1");
    let untouched: String = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key='unrelated.setting'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(untouched, "preserved");
}
