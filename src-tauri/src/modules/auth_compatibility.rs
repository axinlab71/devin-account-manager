//! Read-only audit probe for the official client's state.vscdb.
//!
//! Phase-1 deliverable: report which authentication-related keys exist in the
//! official profile without writing anything, without decrypting secrets, and
//! without creating files. Missing data reports `unavailable`; the probe never
//! fabricates an official database, `Local State`, or key material.
//!
//! Output is a sanitized summary: key names and presence flags only. Secret
//! values, tokens, and account labels inside `windsurf_auth-*` keys are masked.

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::path::Path;

use super::client_version::{self, WindsurfVersionMetadata};

const SESSIONS_SECRET_KEY: &str =
    r#"secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.sessions"}"#;
const API_SERVER_SECRET_KEY: &str =
    r#"secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.apiServerUrl"}"#;
const AUTH_STATUS_KEY: &str = "windsurfAuthStatus";
const SELECTED_AUTH_KEY: &str = "codeium.windsurf-windsurf_auth";
const EXTENSION_STATE_KEY: &str = "codeium.windsurf";
const ONBOARDING_KEY: &str = "windsurfOnboarding";

/// Whether the official state database could be inspected.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum DatabaseProbe {
    /// Database file exists and was opened strictly read-only.
    Opened,
    /// Database file does not exist. Nothing was created.
    Missing,
    /// File exists but could not be opened read-only (locked WAL without shm,
    /// corrupt header, permission denied, ...). Nothing was modified.
    OpenFailed,
}

/// Observed shape of an encrypted `secret://` ItemTable value, without ever
/// decrypting or returning secret material.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum SecretShape {
    /// Key absent from ItemTable.
    Missing,
    /// Value present and looks like an Electron `{"type":"Buffer","data":[...]}`
    /// blob with a known encryption prefix.
    Encrypted { prefix: String },
    /// Value present but not a recognized encrypted Buffer (plaintext, "null",
    /// unexpected shape). Content is never echoed back.
    Unrecognized,
}

/// Sanitized summary of the `codeium.windsurf` extension-state JSON value.
/// Field *names* are returned; values never are.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionStateProbe {
    pub present: bool,
    /// Value parsed as a JSON object (the only shape the writer preserves).
    pub object: bool,
    pub has_installation_id: bool,
    pub has_pending_api_key_migration: bool,
    pub api_server_url_present: bool,
    /// Top-level member names, sorted. Member names are schema vocabulary,
    /// not user data; values are never included.
    pub field_names: Vec<String>,
}

impl Default for ExtensionStateProbe {
    fn default() -> Self {
        Self {
            present: false,
            object: false,
            has_installation_id: false,
            has_pending_api_key_migration: false,
            api_server_url_present: false,
            field_names: Vec::new(),
        }
    }
}

/// Census of per-account auth-usage keys (`windsurf_auth-` literal prefix).
/// Labels (usually e-mail addresses) are masked. Since the write path no
/// longer bulk-deletes these keys, the census reports what is *preserved*.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleanupTargetCensus {
    /// Number of keys with the literal `windsurf_auth-` prefix. The write
    /// path preserves all of them (other accounts' usage data, future keys).
    pub preserved_prefixed: usize,
    /// Masked names: `windsurf_auth-<label>` / `windsurf_auth-<label>-usages`.
    /// Included so the audit can distinguish per-account usage keys from
    /// unknown future keys without leaking the label.
    pub masked_keys: Vec<String>,
    /// Keys that start with `windsurf_auth` but do NOT carry the `-`
    /// separator (e.g. `windsurf_authx`) — reported separately since they
    /// are a different schema family entirely.
    pub survivor_keys: Vec<String>,
}

/// Full read-only probe report. Contains no credential material.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthCompatibilityReport {
    pub profile_dir: String,
    pub database: DatabaseProbe,
    pub client: WindsurfVersionMetadata,
    /// True when `ItemTable` exists and could be queried.
    pub item_table_present: bool,
    pub auth_status_present: bool,
    pub sessions_secret: SecretShape,
    pub api_server_url_secret: SecretShape,
    pub selected_auth_key_present: bool,
    pub extension_state: ExtensionStateProbe,
    pub onboarding_present: bool,
    pub cleanup_targets: CleanupTargetCensus,
    /// Other keys whose name mentions windsurf/codeium/devin auth that this
    /// build does not know about. Names only, only if ASCII-schema-shaped;
    /// anything else is reported as `<non-schema-key>` to avoid leaking
    /// unexpected payloads.
    pub unknown_auth_like_keys: Vec<String>,
}

fn classify_secret(conn: &Connection, key: &str) -> SecretShape {
    let raw: Option<String> = conn
        .query_row("SELECT value FROM ItemTable WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .ok();
    let Some(raw) = raw else {
        return SecretShape::Missing;
    };
    let trimmed = raw.trim();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return SecretShape::Unrecognized;
    };
    let Some(bytes) = value
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect::<Vec<u8>>()
        })
    else {
        return SecretShape::Unrecognized;
    };
    let prefix = if bytes.starts_with(b"v10") {
        "v10"
    } else if bytes.starts_with(b"v11") {
        "v11"
    } else {
        return SecretShape::Unrecognized;
    };
    SecretShape::Encrypted {
        prefix: prefix.to_string(),
    }
}

fn key_present(conn: &Connection, key: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM ItemTable WHERE key = ?1 LIMIT 1",
        [key],
        |_| Ok(()),
    )
    .ok()
    .is_some()
}

fn mask_labelled_key(key: &str) -> String {
    // windsurf_auth-<label> and windsurf_auth-<label>-usages: mask the label.
    if let Some(rest) = key.strip_prefix("windsurf_auth-") {
        if rest.ends_with("-usages") {
            return "windsurf_auth-<label>-usages".to_string();
        }
        return "windsurf_auth-<label>".to_string();
    }
    // Keys where the `_` wildcard matched a non-underscore byte
    // (windsurf.auth-x, windsurfXauth-y, ...) keep their literal form only if
    // they look like schema names; otherwise mask entirely.
    if key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '{' | '}' | '"'))
    {
        key.to_string()
    } else {
        "<masked-key>".to_string()
    }
}

fn census_cleanup_targets(conn: &Connection) -> CleanupTargetCensus {
    let mut prefixed = Vec::new();
    // Literal-prefix range match — what the old `LIKE 'windsurf_auth-%'`
    // wildcard *intended* (but over-matched). `key >= 'windsurf_auth-'`
    // and `key < 'windsurf_auth.'` covers exactly the literal prefix, since
    // '.' is '-' + 1 in byte order.
    if let Ok(mut stmt) = conn.prepare(
        "SELECT key FROM ItemTable \
         WHERE key >= 'windsurf_auth-' AND key < 'windsurf_auth.' ORDER BY key",
    ) {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
            for row in rows.flatten() {
                prefixed.push(row);
            }
        }
    }
    let mut survivor_keys = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT key FROM ItemTable WHERE key LIKE 'windsurf\\_auth%' ESCAPE '\\' \
         AND NOT (key >= 'windsurf_auth-' AND key < 'windsurf_auth.') ORDER BY key",
    ) {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
            for row in rows.flatten() {
                survivor_keys.push(mask_labelled_key(&row));
            }
        }
    }
    CleanupTargetCensus {
        preserved_prefixed: prefixed.len(),
        masked_keys: prefixed.iter().map(|k| mask_labelled_key(k)).collect(),
        survivor_keys,
    }
}

fn probe_extension_state(conn: &Connection) -> ExtensionStateProbe {
    let mut probe = ExtensionStateProbe::default();
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key = ?1",
            [EXTENSION_STATE_KEY],
            |row| row.get(0),
        )
        .ok();
    let Some(raw) = raw else {
        return probe;
    };
    probe.present = true;
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return probe;
    };
    let Some(obj) = value.as_object() else {
        return probe;
    };
    probe.object = true;
    probe.has_installation_id = obj
        .get("codeium.installationId")
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    probe.has_pending_api_key_migration = obj.contains_key("windsurf.pendingApiKeyMigration");
    probe.api_server_url_present = obj.contains_key("apiServerUrl");
    probe.field_names = obj.keys().cloned().collect();
    probe.field_names.sort();
    probe
}

fn unknown_auth_like_keys(conn: &Connection, known: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(mut stmt) = conn.prepare(
        "SELECT key FROM ItemTable WHERE \
         (key LIKE '%windsurf%' OR key LIKE '%codeium%' OR key LIKE '%devin%') \
         ORDER BY key",
    ) else {
        return out;
    };
    let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) else {
        return out;
    };
    for row in rows.flatten() {
        if known.iter().any(|k| *k == row) || row.starts_with("windsurf_auth") {
            continue;
        }
        if row
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '{' | '}' | '"'))
        {
            out.push(row);
        } else {
            out.push("<non-schema-key>".to_string());
        }
    }
    out
}

/// Inspect one profile directory strictly read-only.
///
/// Never creates directories, databases, `Local State`, or any file. Missing
/// or unreadable data is reported, not fabricated.
pub fn probe_profile(profile_dir: &Path, client: WindsurfVersionMetadata) -> AuthCompatibilityReport {
    let db_path = profile_dir
        .join("User")
        .join("globalStorage")
        .join("state.vscdb");
    let mut report = AuthCompatibilityReport {
        profile_dir: profile_dir.to_string_lossy().to_string(),
        database: DatabaseProbe::Missing,
        client,
        item_table_present: false,
        auth_status_present: false,
        sessions_secret: SecretShape::Missing,
        api_server_url_secret: SecretShape::Missing,
        selected_auth_key_present: false,
        extension_state: ExtensionStateProbe::default(),
        onboarding_present: false,
        cleanup_targets: CleanupTargetCensus {
            preserved_prefixed: 0,
            masked_keys: Vec::new(),
            survivor_keys: Vec::new(),
        },
        unknown_auth_like_keys: Vec::new(),
    };
    if !db_path.is_file() {
        return report;
    }
    let conn = match Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(conn) => conn,
        Err(_) => {
            report.database = DatabaseProbe::OpenFailed;
            return report;
        }
    };
    report.database = DatabaseProbe::Opened;

    match conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ItemTable'",
        [],
        |_| Ok(()),
    ) {
        Ok(()) => report.item_table_present = true,
        // Valid database that simply lacks the table.
        Err(rusqlite::Error::QueryReturnedNoRows) => return report,
        // Header/page unreadable etc.: report failure, touch nothing.
        Err(_) => {
            report.database = DatabaseProbe::OpenFailed;
            return report;
        }
    }
    report.auth_status_present = key_present(&conn, AUTH_STATUS_KEY);
    report.sessions_secret = classify_secret(&conn, SESSIONS_SECRET_KEY);
    report.api_server_url_secret = classify_secret(&conn, API_SERVER_SECRET_KEY);
    report.selected_auth_key_present = key_present(&conn, SELECTED_AUTH_KEY);
    report.extension_state = probe_extension_state(&conn);
    report.onboarding_present = key_present(&conn, ONBOARDING_KEY);
    report.cleanup_targets = census_cleanup_targets(&conn);
    report.unknown_auth_like_keys = unknown_auth_like_keys(
        &conn,
        &[
            AUTH_STATUS_KEY,
            SESSIONS_SECRET_KEY,
            API_SERVER_SECRET_KEY,
            SELECTED_AUTH_KEY,
            EXTENSION_STATE_KEY,
            ONBOARDING_KEY,
        ],
    );
    report
}

/// Probe the resolved default official user-data dir, with client version
/// metadata when a launch path is configured or detectable.
pub fn probe_default_profile(configured_client_path: Option<&str>) -> Result<AuthCompatibilityReport, String> {
    let profile = super::windsurf_instance::get_default_windsurf_user_data_dir()?;
    let client = client_version::detect_windsurf_version_metadata("Devin", configured_client_path);
    Ok(probe_profile(&profile, client))
}
