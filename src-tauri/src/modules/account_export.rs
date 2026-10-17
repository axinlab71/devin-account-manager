//! Explicit plaintext credential export. Secrets never cross the IPC boundary.
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;
use crate::models::windsurf::WindsurfAccount;
use super::{account, atomic_write, windsurf_account};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOutcome { pub path: String, pub count: usize, pub format: String, pub short_lived_count: usize }

fn reusable_token(account: &WindsurfAccount) -> Option<(&str, bool)> {
    if let Some(value) = account.devin_auth1_token.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        return Some((value, false));
    }
    [account.windsurf_api_key.as_deref(), Some(account.github_access_token.as_str()), account.devin_session_token.as_deref()]
        .into_iter().flatten().map(str::trim)
        .find(|v| !v.is_empty() && !v.starts_with("ott$") && !v.starts_with("oidc$"))
        .map(|v| (v, account.windsurf_token_type.as_deref() == Some("devin-session") || v.starts_with("devin-session-token$")))
}

fn write_export(accounts: &[WindsurfAccount], format: &str, dir: &Path) -> Result<ExportOutcome, String> {
    if accounts.is_empty() { return Err("请至少选择一个账号".into()); }
    let mut short_lived_count = 0;
    let content = match format {
        "json" => serde_json::to_string_pretty(accounts).map_err(|_| "无法生成账号导出文件")?,
        "txt" => {
            let mut lines = Vec::new();
            for account in accounts {
                let (token, short) = reusable_token(account).ok_or("选中账号缺少可导出的可重复使用凭据，请改用 JSON 或重新授权；未生成文件")?;
                if token.contains(['\n', '\r']) { return Err("凭据包含异常换行，已中止导出".into()); }
                lines.push(token);
                short_lived_count += usize::from(short);
            }
            format!("{}\n", lines.join("\n"))
        }
        _ => return Err("不支持的导出格式".into()),
    };
    let path = dir.join(format!("devin-accounts-{}.{}", uuid::Uuid::new_v4(), format));
    // A unique destination and the private writer avoid plaintext .bak files.
    atomic_write::replace_secret_string_if_matches(&path, None, Some(&content))?
        .then_some(()).ok_or("导出文件名冲突，请重试")?;
    Ok(ExportOutcome {path:path.to_string_lossy().into_owned(),count:accounts.len(),format:format.into(),short_lived_count})
}

#[tauri::command]
pub async fn export_account_credentials(account_ids: Vec<String>, format: String, confirmed: bool) -> Result<ExportOutcome, String> {
    if !confirmed { return Err("请先确认导出文件包含明文登录凭据".into()); }
    if account_ids.is_empty() || account_ids.len() > 2000 { return Err("请选择 1～2000 个账号".into()); }
    tokio::task::spawn_blocking(move || {
        let mut seen = HashSet::new();
        let mut selected = Vec::new();
        for id in account_ids {
            if !seen.insert(id.clone()) { continue; }
            selected.push(windsurf_account::load_account(&id).ok_or("部分选中账号无法读取，已中止；请刷新列表后重试")?);
        }
        write_export(&selected, &format, &account::get_data_dir()?.join("exports/credentials"))
    }).await.map_err(|_| "账号导出任务失败".to_string())?
}

#[tauri::command]
pub fn open_account_exports_folder() -> Result<(), String> {
    let dir=account::get_data_dir()?.join("exports/credentials");
    if !dir.is_dir() { return Err("请先导出账号".into()); }
    open::that_detached(dir).map_err(|_| "无法打开导出目录，请复制文件路径".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> WindsurfAccount { WindsurfAccount { id:"synthetic-id".into(),github_login:"synthetic@example.com".into(),devin_auth1_token:Some("auth1_synthetic-export-secret".into()),devin_account_id:Some("account-synthetic".into()),devin_org_id:Some("org-synthetic".into()),..Default::default() } }
    fn dir() -> std::path::PathBuf { std::env::temp_dir().join(format!("devin-export-test-{}",uuid::Uuid::new_v4())) }
    #[test]
    fn json_preserves_credentials_and_scope_but_ipc_outcome_does_not() {
        let a=fixture();let out=write_export(&[a],"json",&dir()).unwrap();
        let loaded: Vec<WindsurfAccount>=serde_json::from_str(&std::fs::read_to_string(&out.path).unwrap()).unwrap();
        assert_eq!(loaded[0].devin_org_id.as_deref(),Some("org-synthetic"));assert_eq!(loaded[0].devin_auth1_token.as_deref(),Some("auth1_synthetic-export-secret"));
        assert!(!serde_json::to_string(&out).unwrap().contains("synthetic-export-secret"));
        assert!(!Path::new(&format!("{}.bak",out.path)).exists());
    }
    #[test]
    fn txt_prefers_refresh_credential_and_rejects_one_time_only_accounts() {
        let out=write_export(&[fixture()],"txt",&dir()).unwrap();assert_eq!(std::fs::read_to_string(out.path).unwrap(),"auth1_synthetic-export-secret\n");
        let path=dir();let a=WindsurfAccount {github_access_token:"ott$synthetic".into(),..Default::default()};assert!(write_export(&[a],"txt",&path).is_err());assert!(!path.exists());
    }
    #[test]
    fn short_lived_tokens_are_reported_and_invalid_formats_write_nothing() {
        let a=WindsurfAccount {github_access_token:"devin-session-token$synthetic".into(),..Default::default()};let out=write_export(&[a],"txt",&dir()).unwrap();assert_eq!(out.short_lived_count,1);
        let path=dir();assert!(write_export(&[fixture()],"exe",&path).is_err());assert!(!path.exists());
    }
    #[tokio::test]
    async fn unconfirmed_export_is_rejected_before_reading_accounts() {
        assert!(export_account_credentials(vec!["missing".into()],"json".into(),false).await.unwrap_err().contains("确认"));
    }
}
