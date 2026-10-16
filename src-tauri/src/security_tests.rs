//! Synthetic security and recovery regressions; never touches installed client profiles.
use crate::{models::windsurf::WindsurfAccount, modules::*};
use serde_json::json;
use std::path::PathBuf;
struct Data(PathBuf);
impl Data {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("devin-security-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        std::env::set_var("COCKPIT_TOOLS_TEST_DATA_DIR", &p);
        Self(p)
    }
}
impl Drop for Data {
    fn drop(&mut self) {
        std::env::remove_var("COCKPIT_TOOLS_TEST_DATA_DIR");
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> WindsurfAccount {
    serde_json::from_value(json!({"id":"synthetic-id","github_login":"fixture","github_id":42,"github_access_token":"auth1_SECRET","copilot_token":"session_SECRET","created_at":1,"last_used":7})).unwrap()
}
fn profile(d: &Data) -> PathBuf {
    let p = d.0.join("client");
    std::fs::create_dir_all(p.join("User/globalStorage")).unwrap();
    let c = rusqlite::Connection::open(p.join("User/globalStorage/state.vscdb")).unwrap();
    c.execute_batch("PRAGMA journal_mode=WAL;CREATE TABLE ItemTable(key TEXT PRIMARY KEY,value TEXT);INSERT INTO ItemTable VALUES('session','synthetic-old-secret');INSERT INTO ItemTable VALUES('setting','keep');").unwrap();
    p
}
fn read(p: &std::path::Path) -> String {
    rusqlite::Connection::open(p.join("User/globalStorage/state.vscdb"))
        .unwrap()
        .query_row("SELECT value FROM ItemTable WHERE key='session'", [], |r| {
            r.get(0)
        })
        .unwrap()
}
fn mutate(p: &std::path::Path) {
    rusqlite::Connection::open(p.join("User/globalStorage/state.vscdb"))
        .unwrap()
        .execute(
            "UPDATE ItemTable SET value='synthetic-new-secret' WHERE key='session'",
            [],
        )
        .unwrap();
}
#[test]
fn ipc_view_excludes_every_credential_and_nested_unknown_field() {
    let mut a = fixture();
    a.devin_auth1_token = Some("auth1_SECRET".into());
    a.devin_session_token = Some("session_SECRET".into());
    a.windsurf_auth_status_raw = Some(
        json!({"apiKey":"api_SECRET","sessionToken":"session_SECRET","userStatusProtoBinaryBase64":"invalid"}),
    );
    a.windsurf_plan_status = Some(
        json!({"dailyQuotaRemainingPercent":0,"planInfo":{"planName":"PRO","apiKey":"nested_SECRET","opaque":{"token":"opaque_SECRET"}},"apiKey":"api_SECRET","planName":"token_SECRET"}),
    );
    a.quota_query_last_error = Some("request echoed SECRET".into());
    let view = serde_json::to_value(account_view::AccountView::from(&a)).unwrap();
    let text = view.to_string();
    assert!(!text.contains("SECRET"));
    for key in [
        "github_access_token",
        "copilot_token",
        "windsurf_api_key",
        "windsurf_auth_status_raw",
        "devin_auth1_token",
        "devin_session_token",
    ] {
        assert!(view.get(key).is_none());
    }
    assert_eq!(
        view["windsurf_plan_status"]["dailyQuotaRemainingPercent"],
        0
    );
    assert_eq!(view["windsurf_plan_status"]["planInfo"]["planName"], "PRO");
}
#[test]
fn ipc_proto_preserves_usage_but_discards_unknown_auth_fields() {
    use crate::utils::protobuf::{
        encode_len_delim_field, encode_string_field, encode_varint_field,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut a = fixture();
    let mut plan = encode_varint_field(14, 100);
    plan.extend(encode_varint_field(15, 25));
    plan.extend(encode_string_field(99, "SECRET"));
    let mut raw = encode_string_field(1, "SECRET");
    raw.extend(encode_len_delim_field(13, &plan));
    a.devin_user_status_proto_b64 = Some(STANDARD.encode(raw));
    let view = account_view::AccountView::from(&a);
    let clean = STANDARD.decode(view.usage_proto_b64.unwrap()).unwrap();
    assert!(!clean.windows(6).any(|s| s == b"SECRET"));
    assert_eq!(
        clean,
        encode_len_delim_field(
            13,
            &[encode_varint_field(14, 100), encode_varint_field(15, 25)].concat()
        )
    );
}
#[test]
fn endpoint_policy_accepts_only_exact_official_https_destinations() {
    for good in [
        "https://server.codeium.com",
        "https://server.self-serve.windsurf.com/",
        "https://windsurf.com/_backend",
        "https://register.windsurf.com",
    ] {
        auth_endpoint::validate_base(good).unwrap();
    }
    for bad in [
        "http://server.codeium.com",
        "https://server.codeium.com.evil.invalid",
        "https://server.codeium.com@evil.invalid",
        "https://evil.invalid@server.codeium.com",
        "https://server.codeium.com:444",
        "https://127.0.0.1",
        "https://server.codeium.com/?token=SECRET",
        "https://server.codeium.com/#x",
        "https://windsurf.com/other",
    ] {
        assert!(auth_endpoint::validate_base(bad).is_err(), "{bad}");
    }
}
#[test]
fn malicious_json_batch_is_rejected_before_any_account_is_written() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _d = Data::new();
    let good = fixture();
    let mut bad = good.clone();
    bad.id = "bad".into();
    bad.windsurf_auth_status_raw = Some(json!({"apiServerUrl":"https://evil.invalid"}));
    assert!(
        windsurf_account::import_from_json(&serde_json::to_string(&vec![good, bad]).unwrap())
            .is_err()
    );
    assert!(windsurf_account::list_accounts_checked()
        .unwrap()
        .is_empty());
}
#[tokio::test]
async fn existing_untrusted_endpoint_is_blocked_before_refresh() {
    let mut a = fixture();
    a.windsurf_api_key = Some("synthetic".into());
    a.windsurf_api_server_url = Some("http://127.0.0.1:1".into());
    let e = windsurf_oauth::refresh_payload_for_account(&a)
        .await
        .unwrap_err();
    assert!(e.contains("非官方"));
}
#[test]
fn same_email_organizations_survive_import_list_and_persistence() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _d = Data::new();
    let mut a = fixture();
    a.devin_account_id = Some("account-1".into());
    a.devin_org_id = Some("org-1".into());
    a.github_email = Some("same@example.invalid".into());
    let mut b = a.clone();
    b.devin_org_id = Some("org-2".into());
    assert!(!account_identity::same(&a, &b));
    let saved =
        windsurf_account::import_from_json(&serde_json::to_string(&vec![a, b]).unwrap()).unwrap();
    assert_ne!(saved[0].id, saved[1].id);
    let all = windsurf_account::list_accounts_checked().unwrap();
    assert_eq!(all.len(), 2);
}
#[test]
fn refresh_cannot_silently_replace_the_saved_organization() {
    let mut a = fixture();
    a.devin_account_id = Some("account-1".into());
    a.devin_org_id = Some("org-1".into());
    let b = crate::models::windsurf::WindsurfOAuthCompletePayload {
        devin_account_id: Some("account-1".into()),
        devin_org_id: Some("org-2".into()),
        ..Default::default()
    };
    assert!(account_identity::validate_refresh(&a, &b).is_err());
}
#[test]
fn encrypted_snapshot_rolls_back_post_commit_verification_and_launch_failures() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let d = Data::new();
    let p = profile(&d);
    for error in ["verification failed", "launch failed"] {
        let result = client_recovery::guarded_operation(&p, || {
            mutate(&p);
            Err(error.into())
        });
        assert!(result.unwrap_err().contains("已恢复"));
        assert_eq!(read(&p), "synthetic-old-secret");
        assert!(!client_recovery::status().unwrap().pending);
    }
    let encrypted =
        std::fs::read_to_string(d.0.join("client-backups/last-switch.encrypted.json")).unwrap();
    assert!(!encrypted.contains("synthetic-old-secret"));
    assert!(encrypted.contains("AES-256-GCM"));
    let c = rusqlite::Connection::open(p.join("User/globalStorage/state.vscdb")).unwrap();
    assert_eq!(
        c.query_row("SELECT value FROM ItemTable WHERE key='setting'", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "keep"
    );
}
#[test]
fn successful_operation_retains_a_manual_recovery_point() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let d = Data::new();
    let p = profile(&d);
    client_recovery::guarded_operation(&p, || {
        mutate(&p);
        Ok(())
    })
    .unwrap();
    assert_eq!(read(&p), "synthetic-new-secret");
    assert!(!client_recovery::status().unwrap().pending);
    client_recovery::restore(&p).unwrap();
    assert_eq!(read(&p), "synthetic-old-secret");
}
#[test]
fn crashed_or_blocked_operation_preserves_pending_snapshot_without_overwriting_running_client() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let d = Data::new();
    let p = profile(&d);
    let e = client_recovery::guarded_with_close(
        &p,
        || {
            mutate(&p);
            Err("failed".into())
        },
        || Err("still running".into()),
    )
    .unwrap_err();
    assert!(e.message.contains("未覆盖数据库"));
    assert!(!e.safe_to_restart);
    assert_eq!(read(&p), "synthetic-new-secret");
    assert!(client_recovery::status().unwrap().pending);
    client_recovery::restore(&p).unwrap();
    assert_eq!(read(&p), "synthetic-old-secret");
}
#[test]
fn tampered_foreign_and_rotated_key_backups_are_rejected_before_writes() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let d = Data::new();
    let p = profile(&d);
    client_recovery::create(&p).unwrap();
    mutate(&p);
    std::fs::write(
        p.join("Local State"),
        json!({"os_crypt":{"encrypted_key":"rotated"}}).to_string(),
    )
    .unwrap();
    assert!(client_recovery::restore(&p).is_err());
    assert_eq!(read(&p), "synthetic-new-secret");
    std::fs::remove_file(p.join("Local State")).unwrap();
    let foreign = d.0.join("other");
    std::fs::create_dir_all(&foreign).unwrap();
    assert!(client_recovery::restore(&foreign).is_err());
    std::fs::write(
        d.0.join("client-backups/last-switch.encrypted.json"),
        "invalid",
    )
    .unwrap();
    assert!(client_recovery::restore(&p).is_err());
    assert_eq!(read(&p), "synthetic-new-secret");
}
#[test]
fn cleanup_only_removes_legacy_uuid_backups_after_a_valid_encrypted_point_exists() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let d = Data::new();
    let p = profile(&d);
    assert!(client_recovery::cleanup_legacy(&p).is_err());
    client_recovery::create(&p).unwrap();
    let dir = d.0.join("client-backups");
    std::fs::write(
        dir.join(format!("state-{}.vscdb", uuid::Uuid::new_v4())),
        "legacy",
    )
    .unwrap();
    std::fs::write(dir.join("unrelated.vscdb"), "keep").unwrap();
    assert_eq!(client_recovery::cleanup_legacy(&p).unwrap(), 1);
    assert!(dir.join("unrelated.vscdb").exists());
    assert!(dir.join("last-switch.encrypted.json").exists());
}

#[test]
fn same_session_cannot_misidentify_the_current_organization() {
    let mut a = fixture();
    a.devin_account_id = Some("account-1".into());
    a.devin_org_id = Some("org-1".into());
    let mut b = a.clone();
    b.id = "org-two".into();
    b.devin_org_id = Some("org-2".into());
    let list = vec![a.clone(), b];
    assert_eq!(
        account_identity::current_id(
            &json!({"apiKey":a.github_access_token,"accountId":"account-1","primaryOrgId":"org-1"}),
            &list
        ),
        Some(a.id)
    );
    assert!(account_identity::current_id(&json!({"apiKey":"auth1_SECRET"}), &list).is_none());
}
#[test]
fn refresh_metadata_does_not_change_the_last_switch_record() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _d = Data::new();
    let a = fixture();
    windsurf_account::import_from_json(&serde_json::to_string(&a).unwrap()).unwrap();
    let tagged = windsurf_account::update_account_tags(&a.id, vec!["tag".into()]).unwrap();
    assert_eq!(tagged.last_used, 7);
    assert_eq!(tagged.last_switched_at, None);
    windsurf_account::mark_switched(&a.id).unwrap();
    let saved = windsurf_account::load_account(&a.id).unwrap();
    assert!(saved.last_switched_at.unwrap() > 7);
    assert_eq!(saved.last_used, saved.last_switched_at.unwrap());
}

#[test]
fn raw_usage_json_preserves_credits_timestamps_and_known_tiers_only() {
    let mut a = fixture();
    a.windsurf_plan_status = Some(
        json!({"planInfo":{"planName":"Windsurf Pro","monthlyPromptCredits":5000,"privateToken":"SECRET"},"availablePromptCredits":5000,"usedPromptCredits":1200,"planEnd":{"seconds":1900000000},"teamsTier":"TEAMS_TIER_PRO"}),
    );
    let view = serde_json::to_value(account_view::AccountView::from(&a)).unwrap();
    assert_eq!(view["windsurf_plan_status"]["planInfo"]["planName"], "PRO");
    assert_eq!(view["windsurf_plan_status"]["usedPromptCredits"], 1200);
    assert_eq!(
        view["windsurf_plan_status"]["planEnd"]["seconds"],
        1900000000
    );
    assert!(!view.to_string().contains("SECRET"));
}

#[test]
fn client_operations_are_locked_across_distinct_file_handles() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _d = Data::new();
    let first = process::lock_client_operation().unwrap();
    assert!(process::lock_client_operation().is_err());
    drop(first);
    assert!(process::lock_client_operation().is_ok());
}

#[test]
fn legacy_raw_scope_is_preserved_for_identity_and_current_account_matching() {
    let mut a = fixture();
    a.windsurf_auth_status_raw = Some(json!({"accountId":"account-raw","primaryOrgId":"org-raw"}));
    let b = crate::models::windsurf::WindsurfOAuthCompletePayload {
        windsurf_auth_status_raw: a.windsurf_auth_status_raw.clone(),
        ..Default::default()
    };
    assert!(account_identity::matches_payload(&a, &b));
    assert_eq!(
        account_identity::current_id(
            &json!({"apiKey":a.github_access_token,"accountId":"account-raw","primaryOrgId":"org-raw"}),
            &[a.clone()]
        ),
        Some(a.id)
    );
}
#[test]
fn rotating_long_term_credentials_update_the_existing_scoped_account() {
    let _l = test_support::env_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _d = Data::new();
    let mut p = crate::models::windsurf::WindsurfOAuthCompletePayload {
        github_login: "fixture".into(),
        github_id: 42,
        github_access_token: "old-ide".into(),
        copilot_token: "old-ide".into(),
        devin_account_id: Some("account-1".into()),
        devin_org_id: Some("org-1".into()),
        devin_auth1_token: Some("auth1_OLD".into()),
        devin_session_token: Some("old-session".into()),
        ..Default::default()
    };
    let first = windsurf_account::upsert_account(p.clone()).unwrap();
    p.github_access_token = "new-ide".into();
    p.devin_auth1_token = Some("auth1_NEW".into());
    p.devin_session_token = Some("new-session".into());
    let saved = windsurf_account::upsert_account(p).unwrap();
    assert_eq!(saved.id, first.id);
    assert_eq!(saved.devin_auth1_token.as_deref(), Some("auth1_NEW"));
    assert_eq!(saved.devin_session_token.as_deref(), Some("new-session"));
    assert_eq!(windsurf_account::list_accounts_checked().unwrap().len(), 1);
}
