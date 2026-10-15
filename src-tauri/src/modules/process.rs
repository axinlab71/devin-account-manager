//! Minimal process glue; account injection and client lifecycle remain upstream code.
use std::path::PathBuf;
use std::process::{Command, Stdio};
use sysinfo::{ProcessRefreshKind, System, UpdateKind};

pub fn is_pid_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let mut system = System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    system.process(sysinfo::Pid::from_u32(pid)).is_some()
}

pub fn close_pid(pid: u32, timeout_secs: u64) -> Result<(), String> {
    if pid == 0 {
        return Err("PID 无效".into());
    }
    if !is_pid_running(pid) {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() && is_pid_running(pid) {
            return Err("关闭客户端进程失败".into());
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("kill")
            .args(["-15", &pid.to_string()])
            .status()
            .map_err(|e| e.to_string())?;
    }
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < timeout_secs {
        if !is_pid_running(pid) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    Err("客户端进程未退出，已中止账号注入".into())
}

pub fn summarize_text_for_process_log(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}
pub fn summarize_pid_list_for_log(pids: &[u32]) -> String {
    format!("{:?}", pids)
}
pub fn normalize_windows_user_facing_path(raw: &str) -> String {
    let path = raw.trim().trim_matches('"');
    if path.to_ascii_lowercase().starts_with(r"\\?\unc\") {
        format!(r"\\{}", &path[8..])
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
    }
}

pub fn detect_windows_exec_path_by_signatures(
    _app: &str,
    exes: &[&str],
    _path_hints: &[&str],
    _product_hints: &[&str],
    _publisher_hints: &[&str],
) -> Option<PathBuf> {
    for base in [
        std::env::var_os("ProgramFiles"),
        std::env::var_os("ProgramFiles(x86)"),
    ]
    .into_iter()
    .flatten()
    {
        for folder in ["Devin", "Windsurf"] {
            for exe in exes {
                let path = PathBuf::from(&base).join(folder).join(exe);
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        use winreg::{
            enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
            RegKey,
        };
        for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
            let root = RegKey::predef(hive);
            for key_path in [
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ] {
                if let Ok(uninstall) = root.open_subkey(key_path) {
                    for name in uninstall.enum_keys().flatten() {
                        let Ok(app) = uninstall.open_subkey(name) else {
                            continue;
                        };
                        let display: String = app.get_value("DisplayName").unwrap_or_default();
                        if !display.to_ascii_lowercase().starts_with("devin")
                            && !display.to_ascii_lowercase().starts_with("windsurf")
                        {
                            continue;
                        }
                        let location: String = app.get_value("InstallLocation").unwrap_or_default();
                        if location.is_empty() {
                            continue;
                        }
                        for exe in ["Devin.exe", "Windsurf.exe"] {
                            let path = PathBuf::from(&location).join(exe);
                            if path.is_file() {
                                return Some(path);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
