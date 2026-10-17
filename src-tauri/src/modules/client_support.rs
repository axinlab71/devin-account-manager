//! User-triggered support tools. Never change authentication or delete caches.
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use serde::Serialize;
use super::{account, connection_diagnostics::redact_text, windsurf_instance as client};

const FILE_LIMIT: u64 = 512 * 1024;
const MAX_FILES: usize = 40;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogExport {
    pub archive_path: String,
    pub folder_path: String,
    pub files: usize,
    pub truncated_files: usize,
    pub skipped_files: usize,
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { return true; }
    }
    metadata.file_type().is_symlink()
}

fn collect_logs(root: &Path, current: &Path, depth: usize, visited: &mut usize, found: &mut Vec<PathBuf>) {
    if depth > 8 || *visited >= 1500 { return; }
    let Ok(metadata) = fs::symlink_metadata(current) else { return; };
    if is_reparse(&metadata) { return; }
    let Ok(entries) = fs::read_dir(current) else { return; };
    for entry in entries.flatten() {
        *visited += 1;
        if *visited > 1500 { break; }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else { continue; };
        if is_reparse(&metadata) { continue; }
        if metadata.is_dir() {
            collect_logs(root, &path, depth + 1, visited, found);
        } else if metadata.is_file() && path.starts_with(root)
            && matches!(path.extension().and_then(|s| s.to_str()), Some("log" | "txt" | "jsonl")) {
            found.push(path);
        }
    }
}

fn read_sanitized_tail(path: &Path) -> Result<(String, bool), String> {
    let mut file = fs::File::open(path).map_err(|_| "日志无法读取")?;
    let size = file.metadata().map_err(|_| "日志属性无法读取")?.len();
    let start = size.saturating_sub(FILE_LIMIT);
    file.seek(SeekFrom::Start(start)).map_err(|_| "日志定位失败")?;
    let mut bytes = Vec::new();
    file.take(FILE_LIMIT).read_to_end(&mut bytes).map_err(|_| "日志读取失败")?;
    // Do not export an incomplete leading credential when taking a tail.
    if start > 0 {
        bytes = match bytes.iter().position(|b| *b == b'\n') {
            Some(index) => bytes[index + 1..].to_vec(), None => Vec::new(),
        };
    }
    if bytes.contains(&0) { return Err("跳过非文本日志".into()); }
    let text = String::from_utf8_lossy(&bytes);
    // Avoid exporting common structured conversation bodies, beyond credential redaction.
    let filtered: String = text.lines().map(|line| {
        let lower = line.to_ascii_lowercase();
        if ["\"messages\"", "\"prompt\"", "\"content\"", "\"completion\""].iter().any(|p| lower.contains(p)) {
            "[omitted: possible conversation payload]\n".to_string()
        } else { format!("{}\n", redact_text(line)) }
    }).collect();
    Ok((filtered, start > 0))
}

fn export_logs_from_profile(profile: &Path, output: &Path) -> Result<LogExport, String> {
    let mut candidates = Vec::new();
    for (group, root) in [("agent", profile.join("cli/logs")), ("ide", profile.join("logs"))] {
        let mut found = Vec::new();
        collect_logs(&root, &root, 0, &mut 0, &mut found);
        candidates.extend(found.into_iter().map(|p| (group, p)));
    }
    candidates.sort_by_key(|(_, p)| std::cmp::Reverse(fs::metadata(p).and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH)));
    if candidates.is_empty() { return Err("未找到可导出的 Devin 日志，请先在客户端复现问题后重试".into()); }
    let limited = candidates.len().saturating_sub(MAX_FILES);
    let id = format!("devin-support-{}", uuid::Uuid::new_v4());
    let folder = output.join(&id);
    fs::create_dir_all(&folder).map_err(|_| "无法创建日志导出目录")?;
    let mut entries = Vec::new();
    let mut truncated = 0;
    let mut skipped = limited;
    for (index, (group, source)) in candidates.into_iter().take(MAX_FILES).enumerate() {
        match read_sanitized_tail(&source) {
            Ok((text, cut)) => {
                let name = format!("{group}-{:03}.log", index + 1);
                fs::write(folder.join(&name), text).map_err(|_| "写入脱敏日志失败")?;
                truncated += usize::from(cut);
                // Include only a redacted relative source, never a full user path.
                entries.push(serde_json::json!({"file":name,"source":redact_text(&source.strip_prefix(profile).unwrap_or(&source).to_string_lossy().replace('\\',"/")),"tailOnly":cut}));
            }
            Err(_) => skipped += 1,
        }
    }
    if entries.is_empty() { return Err("日志均不可读取或不是文本，未生成日志包".into()); }
    let manifest = serde_json::json!({"appVersion":env!("CARGO_PKG_VERSION"),"exportedAt":chrono::Utc::now().to_rfc3339(),"files":entries,"skippedFiles":skipped,"maxFiles":MAX_FILES,"maxBytesPerFile":FILE_LIMIT,"note":"Only recent text logs; redacted, not a full backup. Review before sharing."});
    fs::write(folder.join("manifest.json"), serde_json::to_vec_pretty(&manifest).map_err(|_| "日志清单生成失败")?).map_err(|_| "日志清单写入失败")?;
    fs::write(folder.join("README.txt"), "本包仅包含官方 IDE/agent 日志的近期文本片段，不包含账号数据库、密钥或配置。已自动脱敏并省略常见结构化对话行，但仍可能含项目名称、代码或其他私人信息，请检查后再分享。截取范围与跳过数量见 manifest.json。解压前可先查看同名目录。\n").map_err(|_| "说明文件写入失败")?;
    let archive = output.join(format!("{id}.zip"));
    create_zip(&folder, &archive)?;
    Ok(LogExport { archive_path:archive.to_string_lossy().into_owned(),folder_path:folder.to_string_lossy().into_owned(),files:entries.len(),truncated_files:truncated,skipped_files:skipped })
}

#[cfg(windows)]
fn create_zip(folder: &Path, archive: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let status = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "Add-Type -AssemblyName System.IO.Compression.FileSystem; try { [System.IO.Compression.ZipFile]::CreateFromDirectory($env:DEVIN_SUPPORT_STAGE, $env:DEVIN_SUPPORT_ZIP); exit 0 } catch { exit 1 }"])
        .env("DEVIN_SUPPORT_STAGE", folder).env("DEVIN_SUPPORT_ZIP", archive)
        .creation_flags(0x08000000).status().map_err(|_| "无法启动日志压缩任务")?;
    if !status.success() { return Err(format!("ZIP 压缩失败，脱敏日志仍在 {}", folder.display())); }
    Ok(())
}
#[cfg(not(windows))]
fn create_zip(_folder: &Path, _archive: &Path) -> Result<(), String> { Err("日志 ZIP 导出暂仅支持 Windows".into()) }

fn export_current_logs() -> Result<LogExport, String> {
    let profile = client::get_default_windsurf_user_data_dir()?;
    export_logs_from_profile(&profile, &account::get_data_dir()?.join("diagnostics/exports"))
}

#[tauri::command]
pub async fn export_devin_logs() -> Result<LogExport, String> {
    tokio::task::spawn_blocking(export_current_logs).await.map_err(|_| "日志导出任务失败".to_string())?
}

#[tauri::command]
pub fn open_log_export_folder() -> Result<(), String> {
    let path = account::get_data_dir()?.join("diagnostics/exports");
    if !path.is_dir() { return Err("请先导出日志包".into()); }
    open::that_detached(path).map_err(|_| "无法打开日志导出目录".into())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteRestart { pub log_export: LogExport, pub terminated_processes: usize, pub message: String }

#[tauri::command]
pub async fn complete_restart_devin(confirmed: bool) -> Result<CompleteRestart, String> {
    if !confirmed { return Err("请先确认已保存工作并接受终端与 AI 任务中断风险".into()); }
    let _guard = crate::CLIENT_LOCK.try_lock().map_err(|_| "正在操作客户端，请稍后重试")?;
    tokio::task::spawn_blocking(|| {
        let _file_guard = super::process::lock_client_operation()?;
        super::quota_monitor::global().ensure_no_in_flight_switch()
            .map_err(|code| super::quota_monitor::confirm_error_message(&code))?;
        client::ensure_windsurf_launch_path_configured()?;
        let profile = client::get_default_windsurf_user_data_dir()?;
        // A failed export must stop before any process is terminated.
        let logs = export_logs_from_profile(&profile, &account::get_data_dir()?.join("diagnostics/exports"))?;
        #[cfg(windows)]
        let count = client::force_close_for_support(&profile).map_err(|e| format!("{e}；现场日志已保存在 {}", logs.archive_path))?;
        #[cfg(not(windows))]
        let count: usize = { let _ = profile; return Err("彻底重启暂仅支持 Windows".into()); };
        client::start_windsurf_default_with_args_with_new_window(&[], true)
            .map_err(|_| format!("客户端进程已结束，但启动失败，请手动打开；日志位于 {}", logs.archive_path))?;
        Ok(CompleteRestart {log_export:logs,terminated_processes:count,message:"已完成进程彻底重启，登录文件未清理。请在 Devin 中验证模型和消息是否恢复。".into()})
    }).await.map_err(|_| "彻底重启任务失败，请检查客户端状态".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp() -> PathBuf { let p=std::env::temp_dir().join(format!("devin-support-test-{}",uuid::Uuid::new_v4()));fs::create_dir_all(&p).unwrap();p }
    #[test]
    fn export_redacts_logs_and_excludes_credentials_and_payloads() {
        let dir=temp();let profile=dir.join("profile");fs::create_dir_all(profile.join("cli/logs")).unwrap();fs::create_dir_all(profile.join("User")).unwrap();
        fs::write(profile.join("cli/logs/agent.log"), "Authorization: Bearer sk-ws-01-abcdef1234567890123456789\nalice@example.com\n{\"content\":\"private-prompt\"}\nnormal diagnostic\n").unwrap();
        fs::write(profile.join("cli/logs/state.vscdb"),"must-not-export").unwrap();fs::write(profile.join("User/secret.log"),"must-not-export").unwrap();
        let out=export_logs_from_profile(&profile,&dir.join("out")).unwrap();assert_eq!(out.files,1);assert!(Path::new(&out.archive_path).is_file());
        let text=fs::read_to_string(Path::new(&out.folder_path).join("agent-001.log")).unwrap();assert!(!text.contains("abcdef1234567890123456789"));assert!(!text.contains("alice@example.com"));assert!(!text.contains("private-prompt"));assert!(text.contains("normal diagnostic"));
    }
    #[test]
    fn large_log_uses_bounded_tail_and_missing_logs_fail() {
        let dir=temp();let file=dir.join("big.log");fs::write(&file,format!("{}\nlatest useful error\n","x".repeat(FILE_LIMIT as usize+100))).unwrap();let (text,cut)=read_sanitized_tail(&file).unwrap();assert!(cut);assert_eq!(text,"latest useful error\n");assert!(export_logs_from_profile(&dir.join("missing"),&dir.join("out")).is_err());
    }
    #[tokio::test]
    async fn complete_restart_requires_confirmation_before_any_side_effect() { assert!(complete_restart_devin(false).await.unwrap_err().contains("确认")); }
    #[test]
    #[ignore = "只读采集本机官方日志，仅在用户授权本机检查时显式运行"]
    fn live_export_current_logs_without_client_mutation() {
        let result = export_current_logs().unwrap();
        assert!(result.files > 0 && result.files <= MAX_FILES);
        println!("{}", serde_json::to_string(&result).unwrap());
    }
}
