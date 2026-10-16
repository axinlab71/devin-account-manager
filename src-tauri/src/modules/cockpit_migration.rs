//! Read-only migration of Cockpit account files; never modifies the source key or files.
use crate::{
    models::windsurf::WindsurfAccount,
    modules::{secure_account_storage, windsurf_account},
};
use serde::Serialize;
use std::{fs, path::PathBuf};
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MigrationReport {
    pub imported: usize,
    pub skipped: usize,
    pub failed: usize,
    pub source_path: String,
}
pub fn import(source_path: Option<String>) -> Result<MigrationReport, String> {
    let root = if let Some(path) = source_path.filter(|p| !p.trim().is_empty()) {
        PathBuf::from(path.trim())
    } else {
        let home = dirs::home_dir().ok_or("无法定位用户目录，请填写 Cockpit 数据目录")?;
        [
            home.join(".cockpit_tools"),
            home.join(".antigravity_cockpit"),
        ]
        .into_iter()
        .find(|p| p.join("windsurf_accounts").is_dir())
        .ok_or("未找到 Cockpit 账号，请填写其数据目录，或导入 Cockpit 导出的 JSON")?
    };
    let folder = root.join("windsurf_accounts");
    let canonical = folder
        .canonicalize()
        .map_err(|_| "该目录没有 windsurf_accounts 文件夹")?;
    let mut existing = windsurf_account::list_accounts_checked()?;
    let mut report = MigrationReport {
        source_path: root.to_string_lossy().into(),
        ..Default::default()
    };
    let entries = fs::read_dir(&folder).map_err(|_| "无法读取 Cockpit 账号目录")?;
    for (count, entry) in entries.enumerate() {
        if count >= 10000 {
            return Err("账号目录文件过多，请改用导出的 JSON".into());
        }
        let Ok(entry) = entry else {
            report.failed += 1;
            continue;
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        // Reject symlinks and oversized input before reading credentials.
        if entry.file_type().map(|t| !t.is_file()).unwrap_or(true)
            || path
                .canonicalize()
                .map(|p| p.parent() != Some(canonical.as_path()))
                .unwrap_or(true)
            || entry
                .metadata()
                .map(|m| m.len() > 5 * 1024 * 1024)
                .unwrap_or(true)
        {
            report.failed += 1;
            continue;
        }
        let account = match secure_account_storage::read_account_file_readonly::<WindsurfAccount>(
            &path,
            &root.join("secure-account-storage.key"),
        ) {
            Ok(value) => value,
            Err(_) => {
                report.failed += 1;
                continue;
            }
        };
        if existing.iter().any(|a| {
            a.id == account.id
                || (a.github_id > 0 && a.github_id == account.github_id)
                || a.github_email
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .zip(account.github_email.as_ref())
                    .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
        }) {
            report.skipped += 1;
            continue;
        }
        match windsurf_account::import_from_json(
            &serde_json::to_string(&account).map_err(|_| "账号格式无效")?,
        ) {
            Ok(saved) => {
                existing.extend(saved);
                report.imported += 1;
            }
            Err(_) => report.failed += 1,
        }
    }
    Ok(report)
}
