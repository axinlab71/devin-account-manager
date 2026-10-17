//! 连接诊断与修复（只读诊断引擎 + 保守恢复操作）。
//!
//! 诊断引擎完全只读：不写任何文件、不改注册表、不改代理设置。
//! 所有进入结果与报告的文本都必须经过 [`redact_text`] 脱敏。
//! 唯一的写操作是三个显式确认的恢复命令，每个都先备份、可回退。

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::modules::windsurf_instance as client;

// ---------------------------------------------------------------------------
// 脱敏
// ---------------------------------------------------------------------------

mod redaction {
    use regex::Regex;
    use std::sync::OnceLock;

    fn known_token_prefix() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(concat!(
                r"\b(?:",
                "windsurf_[A-Za-z0-9]+",
                "|sk-ws-[A-Za-z0-9-]+",
                "|cog_[A-Za-z0-9]+",
                "|auth1_[A-Za-z0-9._-]+",
                "|ghp_[A-Za-z0-9]+",
                "|gho_[A-Za-z0-9]+",
                "|github_pat_[A-Za-z0-9_]+",
                "|devin-session-token\\$[^\\s\"',;]+",
                r")"
            ))
            .expect("token prefix regex")
        })
    }

    fn long_opaque_string() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\b[A-Za-z0-9+/_=-]{32,}\b").expect("long string regex"))
    }

    fn secret_assignment() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(concat!(
                r"(?i)\b(token|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|",
                r"secret|password|passwd|session[_-]?token|auth[_-]?token|signature|sig|",
                r"credential)([=:])[A-Za-z0-9._~+/-]{3,}")
            )
            .expect("secret assignment regex")
        })
    }

    fn json_secret_value() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(concat!(
                r#"(?i)("[^"]*(?:api[_-]?key|apikey|access[_-]?token|token|secret|password|"#,
                r#"sessiontoken|session[_-]?token|authorization)[^"]*"\s*:\s*")[^"]*(")"#
            ))
            .expect("json secret regex")
        })
    }

    fn authorization_header() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]+")
                .expect("authorization regex")
        })
    }

    fn email_address() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
                .expect("email regex")
        })
    }

    fn user_profile_dir() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)([A-Za-z]:[/\\]Users[/\\]|/Users/|/home/)[^/\\\s]+")
                .expect("user profile dir regex")
        })
    }

    /// 对任意要进入诊断结果/报告的文本做脱敏。宁可过度脱敏，不可漏。
    pub fn redact_text(input: &str) -> String {
        let mut out = user_profile_dir()
            .replace_all(input, "${1}<redacted>")
            .into_owned();
        out = json_secret_value().replace_all(&out, "${1}<redacted>${2}").into_owned();
        out = authorization_header().replace_all(&out, "${1}<redacted>").into_owned();
        out = secret_assignment()
            .replace_all(&out, "${1}${2}<redacted>")
            .into_owned();
        out = known_token_prefix()
            .replace_all(&out, |caps: &regex::Captures| {
                let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                // 保留 windsurf_/auth1_ 等前缀便于排查；分隔符取 '_' 或 '$'，
                // 二者都没有时整条替换，绝不留出令牌体
                let split_at = matched
                    .find(['_', '$'])
                    .map(|i| i + 1)
                    .unwrap_or(matched.len());
                if split_at >= matched.len() {
                    "<redacted>".to_string()
                } else {
                    let (head, _) = matched.split_at(split_at);
                    format!("{}<redacted>", head)
                }
            })
            .into_owned();
        out = long_opaque_string()
            .replace_all(&out, "<redacted>")
            .into_owned();
        out = email_address()
            .replace_all(&out, |caps: &regex::Captures| {
                let email = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                match email.split_once('@') {
                    Some((local, domain)) => {
                        let first = local.chars().next().unwrap_or('x');
                        format!("{}***@{}", first, domain)
                    }
                    None => "<redacted>".to_string(),
                }
            })
            .into_owned();
        out
    }
}

pub use redaction::redact_text;

// ---------------------------------------------------------------------------
// 结果结构（全部字段在填充前已脱敏）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    ConfirmedIssue,
    Ok,
    Unknown,
}

impl CheckStatus {
    fn label(&self) -> &'static str {
        match self {
            CheckStatus::ConfirmedIssue => "已确认异常",
            CheckStatus::Ok => "检查正常",
            CheckStatus::Unknown => "无法判断",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticItem {
    pub id: String,
    pub group: String,
    pub title: String,
    pub status: CheckStatus,
    pub detail: String,
    pub evidence: Vec<String>,
}

impl DiagnosticItem {
    fn new(id: &str, group: &str, title: &str, status: CheckStatus, detail: String) -> Self {
        DiagnosticItem {
            id: id.into(),
            group: group.into(),
            title: title.into(),
            status,
            detail: redact_text(&detail),
            evidence: Vec::new(),
        }
    }

    fn with_evidence(mut self, evidence: impl IntoIterator<Item = String>) -> Self {
        self.evidence = evidence
            .into_iter()
            .map(|line| redact_text(&line))
            .collect();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientDiagnostics {
    pub exe_path: Option<String>,
    pub exe_exists: bool,
    pub product_version: Option<String>,
    pub product_commit: Option<String>,
    pub file_version: Option<String>,
    pub data_dir: Option<String>,
    pub data_dir_exists: bool,
    pub user_settings_exists: bool,
    pub cli_log_dir_exists: bool,
    pub ide_processes_running: usize,
    pub agent_processes_running: usize,
    /// 客户端注册的 `*reloadAcpConnections` 命令（本版实测无 reconnect 命令）
    pub acp_reload_available: bool,
    pub acp_reconnect_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxySection {
    pub system_proxy_enabled: bool,
    pub system_proxy_server: Option<String>,
    pub system_proxy_listening: Option<bool>,
    /// blob 中存在 PAC URL 字符串（含未启用的残留）
    pub pac_configured: bool,
    /// 代理模式当前正启用 PAC（flags 含 PROXY_TYPE_AUTO_PROXY_URL 0x04）
    pub pac_active: bool,
    pub pac_target: Option<String>,
    pub pac_listening: Option<bool>,
    pub env_proxies: Vec<String>,
    pub devin_settings_proxy: Option<String>,
    pub devin_agent_env_keys: Vec<String>,
    pub confirmed_proxy_issue: bool,
    pub stale_pac_confirmed: bool,
    pub ineffective_proxy_confirmed: bool,
    pub listening_local_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeTiming {
    pub attempts: u8,
    pub successes: u8,
    pub min_ms: u64,
    pub max_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProbeResult {
    pub host: String,
    pub dns_ok: bool,
    pub resolved_ip: Option<String>,
    pub tcp: Option<ProbeTiming>,
    pub tls: Option<ProbeTiming>,
    pub classification: String,
    /// 探测路径：direct=管理器直连（不代表 Devin 实际走路径）/ proxy / unknown
    pub path: String,
    pub risk_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogDiagnostics {
    pub log_dir: String,
    pub total_log_files: usize,
    pub logs_examined: usize,
    pub agent_starts: usize,
    pub authenticate_attempts: usize,
    pub authenticate_with_credentials: usize,
    pub team_settings_failures: usize,
    pub timeout_failures: usize,
    pub zdr_timeouts: usize,
    pub remote_config_failures: usize,
    pub last_failure_at: Option<String>,
    pub agent_versions: Vec<String>,
    pub running_agent_pids: Vec<u32>,
    pub running_agents_authenticated: Option<bool>,
    pub newest_log_has_auth_failure: bool,
    /// 近期日志中出现的失败类别（不互相归并）：network_timeout /
    /// auth_failed / permission / config / unknown
    pub failure_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedFix {
    pub id: String,
    pub label: String,
    pub requires_restart: bool,
    pub affects_login: bool,
    pub manual: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummarySection {
    pub category: String,
    pub confidence: String,
    pub overview: String,
    pub recommended_fixes: Vec<RecommendedFix>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsResult {
    pub generated_at_ms: i64,
    pub app_version: String,
    pub items: Vec<DiagnosticItem>,
    pub client: ClientDiagnostics,
    pub proxy: ProxySection,
    pub network: Vec<NetworkProbeResult>,
    pub logs: LogDiagnostics,
    pub summary: SummarySection,
}

// ---------------------------------------------------------------------------
// 通用小工具
// ---------------------------------------------------------------------------

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn timestamp_slug() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let secs_of_day = secs % 86400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        year,
        month,
        day,
        secs_of_day / 3600,
        (secs_of_day / 60) % 60,
        secs_of_day % 60
    )
}

/// Howard Hinnant 的 civil-from-days 算法（仅用于本地文件名时间戳）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 从代理字符串中提取 主机:端口（支持 http://host:port、host:port、
/// http=host:port;https=host:port 等形态）。凭据部分被丢弃。
fn extract_host_port(raw: &str) -> Option<(String, u16)> {
    let trimmed = raw.trim().trim_matches(|c| c == '"' || c == '\'');
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(url) = url::Url::parse(trimmed) {
        if let Some(host) = url.host_str() {
            let port = url.port().unwrap_or(match url.scheme() {
                "https" => 443,
                "socks5" | "socks" | "socks5h" => 1080,
                _ => 80,
            });
            return Some((host.to_string(), port));
        }
    }
    // "http=127.0.0.1:7897;https=..." 形态：取第一段
    let first_segment = trimmed.split(';').next().unwrap_or(trimmed);
    let candidate = first_segment
        .split_once('=')
        .map(|(_, value)| value)
        .unwrap_or(first_segment)
        .trim();
    // 去掉可能的 scheme
    let candidate = candidate
        .strip_prefix("http://")
        .or_else(|| candidate.strip_prefix("https://"))
        .or_else(|| candidate.strip_prefix("socks5h://"))
        .or_else(|| candidate.strip_prefix("socks5://"))
        .or_else(|| candidate.strip_prefix("socks://"))
        .unwrap_or(candidate);
    let (host, port) = candidate.rsplit_once(':')?;
    let port: u16 = port.trim().parse().ok()?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

fn is_loopback_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower == "localhost"
        || lower == "::1"
        || lower.starts_with("127.")
        || lower == "[::1]"
}

/// 探测本机端口是否在监听（1 秒超时）。
fn is_local_port_listening(port: u16) -> bool {
    if port == 0 {
        return false;
    }
    let addrs: Vec<SocketAddr> = match format!("127.0.0.1:{port}").to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(_) => return false,
    };
    addrs
        .iter()
        .any(|addr| TcpStream::connect_timeout(addr, Duration::from_secs(1)).is_ok())
}

fn diagnostics_dir() -> Result<PathBuf, String> {
    let dir = crate::modules::account::get_data_dir()?.join("diagnostics");
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建诊断目录失败: {e}"))?;
    Ok(dir)
}

fn devin_settings_path(profile: &Path) -> PathBuf {
    profile.join("User").join("settings.json")
}

// ---------------------------------------------------------------------------
// A. 客户端环境
// ---------------------------------------------------------------------------

/// 只读检测：当前客户端扩展注册的 ACP 恢复命令。
/// 读 `resources/app/extensions/windsurf/package.json` 的
/// `contributes.commands`；没有外部调用入口，仅用于决定是否提供
/// 命令面板手动指引。（1.126.0 实测：reload 存在，reconnect 不存在）
fn detect_acp_commands(exe_path: Option<&str>) -> (bool, bool) {
    let Some(pkg) = exe_path
        .map(|p| Path::new(p).parent().map(|b| b.to_path_buf()))
        .flatten()
        .map(|base| base.join("resources/app/extensions/windsurf/package.json"))
        .filter(|p| p.is_file())
    else {
        return (false, false);
    };
    let Ok(text) = std::fs::read_to_string(&pkg) else {
        return (false, false);
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return (false, false);
    };
    let mut reload = false;
    let mut reconnect = false;
    if let Some(commands) = value
        .get("contributes")
        .and_then(|c| c.get("commands"))
        .and_then(|c| c.as_array())
    {
        for cmd in commands {
            let id = cmd.get("command").and_then(|v| v.as_str()).unwrap_or("");
            if id.ends_with("reloadAcpConnections") {
                reload = true;
            }
            if id.ends_with("reconnectAcpConnections") {
                reconnect = true;
            }
        }
    }
    (reload, reconnect)
}

fn collect_client_info() -> (ClientDiagnostics, Vec<DiagnosticItem>) {
    let mut items = Vec::new();
    let app_path = client::detect_and_save_windsurf_launch_path(false);
    let exe_exists = app_path
        .as_ref()
        .map(|p| Path::new(p).is_file())
        .unwrap_or(false);
    let product_json = app_path
        .as_ref()
        .and_then(|p| Path::new(p).parent().map(|base| base.join("resources/app/product.json")));
    let (product_version, product_commit) = product_json
        .as_ref()
        .filter(|p| p.is_file())
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .map(|value| {
            let version = value
                .get("version")
                .or_else(|| value.get("productVersion"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let commit = value
                .get("commit")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            (version, commit)
        })
        .unwrap_or((None, None));
    let file_version = app_path
        .as_deref()
        .and_then(|p| client_version_probe(Path::new(p)));

    let data_dir = client::get_default_windsurf_user_data_dir()
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let data_dir_exists = data_dir.as_ref().map(|d| Path::new(d).is_dir()).unwrap_or(false);
    let cli_log_dir = data_dir
        .as_ref()
        .map(|d| PathBuf::from(d).join("cli").join("logs"));
    let cli_log_dir_exists = cli_log_dir
        .as_ref()
        .map(|p| p.is_dir())
        .unwrap_or(false);
    let user_settings_exists = data_dir
        .as_ref()
        .map(|d| devin_settings_path(Path::new(d)).is_file())
        .unwrap_or(false);

    let (ide_count, agent_count) = count_client_processes();
    let (acp_reload_available, acp_reconnect_available) =
        detect_acp_commands(app_path.as_deref());

    let info = ClientDiagnostics {
        exe_path: app_path.clone().map(|p| redact_text(&p)),
        exe_exists,
        product_version: product_version.clone(),
        product_commit: product_commit.clone().map(|c| redact_text(&c)),
        file_version: file_version.clone(),
        data_dir: data_dir.clone().map(|d| redact_text(&d)),
        data_dir_exists,
        user_settings_exists,
        cli_log_dir_exists,
        ide_processes_running: ide_count,
        agent_processes_running: agent_count,
        acp_reload_available,
        acp_reconnect_available,
    };

    items.push(if exe_exists {
        let item = DiagnosticItem::new(
            "client.exe",
            "client",
            "客户端程序",
            CheckStatus::Ok,
            format!(
                "已找到 Devin Desktop{}",
                product_version
                    .as_ref()
                    .map(|v| format!("，版本 {v}"))
                    .unwrap_or_default()
            ),
        );
        let mut evidence = Vec::new();
        if let Some(p) = &app_path {
            evidence.push(format!("path={p}"));
        }
        if let Some(v) = &file_version {
            evidence.push(format!("fileVersion={v}"));
        }
        if let Some(c) = &product_commit {
            evidence.push(format!("commit={c}"));
        }
        item.with_evidence(evidence)
    } else {
        DiagnosticItem::new(
            "client.exe",
            "client",
            "客户端程序",
            CheckStatus::Unknown,
            "未检测到 Devin Desktop 安装路径，部分诊断项无法判断".to_string(),
        )
    });

    items.push(if data_dir_exists {
        let item = DiagnosticItem::new(
            "client.data_dir",
            "client",
            "客户端数据目录",
            CheckStatus::Ok,
            "用户数据目录存在".to_string(),
        );
        let mut evidence = Vec::new();
        if let Some(d) = &data_dir {
            evidence.push(format!("dir={d}"));
        }
        evidence.push(format!(
            "settings.json={}",
            if user_settings_exists { "存在" } else { "不存在" }
        ));
        evidence.push(format!(
            "cli/logs={}",
            if cli_log_dir_exists { "存在" } else { "不存在" }
        ));
        item.with_evidence(evidence)
    } else {
        DiagnosticItem::new(
            "client.data_dir",
            "client",
            "客户端数据目录",
            CheckStatus::Unknown,
            "用户数据目录不存在（客户端可能尚未启动过）".to_string(),
        )
    });

    items.push(
        if ide_count > 0 {
            DiagnosticItem::new(
                "client.processes",
                "client",
                "客户端进程状态",
                CheckStatus::Ok,
                format!("Devin Desktop 正在运行（{ide_count} 个主进程，{agent_count} 个 agent 子进程）"),
            )
        } else {
            DiagnosticItem::new(
                "client.processes",
                "client",
                "客户端进程状态",
                CheckStatus::Unknown,
                "当前没有 Devin Desktop 主进程在运行".to_string(),
            )
        }
        .with_evidence([format!("ide={ide_count}, agent={agent_count}")]),
    );

    (info, items)
}

#[cfg(target_os = "windows")]
fn client_version_probe(path: &Path) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let script = r#"$p=[Environment]::GetEnvironmentVariable('DIAG_CLIENT_EXE','Process'); if ([string]::IsNullOrWhiteSpace($p)) { exit 2 }; $v=(Get-Item $p).VersionInfo; $value=$v.ProductVersion; if ([string]::IsNullOrWhiteSpace($value)) { $value=$v.FileVersion }; [Console]::Write($value)"#;
    let out = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .env("DIAG_CLIENT_EXE", path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(not(target_os = "windows"))]
fn client_version_probe(_path: &Path) -> Option<String> {
    None
}

/// 统计 IDE 主进程与 agent 子进程数量。agent 特征：exe 位于
/// `extensions\windsurf\devin\bin\devin.exe`。
fn count_client_processes() -> (usize, usize) {
    #[cfg(target_os = "macos")]
    {
        return (client::collect_windsurf_process_entries().len(), 0);
    }
    #[cfg(not(target_os = "macos"))]
    {
        use sysinfo::{ProcessRefreshKind, System, UpdateKind};
        let mut system = System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet),
        );
        let current_pid = std::process::id();
        let mut ide = 0usize;
        let mut agent = 0usize;
        for (pid, process) in system.processes() {
            if pid.as_u32() == current_pid {
                continue;
            }
            let name = process.name().to_string_lossy().to_lowercase();
            let exe = process
                .exe()
                .map(|p| p.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let is_client_exe = name == "devin.exe"
                || name == "windsurf.exe"
                || exe.ends_with("\\devin.exe")
                || exe.ends_with("\\windsurf.exe")
                || (name == "electron.exe" && (exe.contains("\\devin\\") || exe.contains("\\windsurf\\")));
            if !is_client_exe {
                continue;
            }
            if exe.contains("\\extensions\\windsurf\\devin\\bin\\devin.exe")
                || exe.contains("/extensions/windsurf/devin/bin/devin.exe")
            {
                agent += 1;
            } else {
                ide += 1;
            }
        }
        (ide, agent)
    }
}

// ---------------------------------------------------------------------------
// B. 代理状态
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct RegistryProxyInfo {
    proxy_enable: Option<bool>,
    proxy_server: Option<String>,
    pac_configured: bool,
    pac_active: bool,
    pac_target: Option<(String, u16)>,
    pac_hidden_query: bool,
    read_error: Option<String>,
}

#[cfg(target_os = "windows")]
fn read_windows_proxy_registry() -> RegistryProxyInfo {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let mut info = RegistryProxyInfo::default();
    let root = RegKey::predef(HKEY_CURRENT_USER);
    let settings = match root.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        winreg::enums::KEY_READ,
    ) {
        Ok(key) => key,
        Err(e) => {
            info.read_error = Some(format!("打开注册表失败: {e}"));
            return info;
        }
    };
    info.proxy_enable = settings.get_value::<u32, _>("ProxyEnable").ok().map(|v| v != 0);
    info.proxy_server = settings
        .get_value::<String, _>("ProxyServer")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if let Ok(connections) = settings.open_subkey_with_flags("Connections", winreg::enums::KEY_READ) {
        if let Ok(raw) = connections.get_raw_value("DefaultConnectionSettings") {
            if let Some(parsed) = parse_default_connection_settings(&raw.bytes) {
                info.pac_configured = parsed.pac_configured;
                info.pac_active = parsed.pac_active;
                info.pac_target = parsed.pac_target;
                info.pac_hidden_query = parsed.pac_hidden_query;
            }
        }
    }
    info
}

#[cfg(not(target_os = "windows"))]
fn read_windows_proxy_registry() -> RegistryProxyInfo {
    RegistryProxyInfo {
        read_error: Some("当前平台不支持读取系统代理注册表".to_string()),
        ..Default::default()
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionSettingsInfo {
    /// blob 尾部存在 PAC URL 字符串（无论当前是否启用）
    pub pac_configured: bool,
    /// options 标志含 0x04（PROXY_TYPE_AUTO_PROXY_URL），PAC 正生效中
    pub pac_active: bool,
    pub pac_target: Option<(String, u16)>,
    pub pac_hidden_query: bool,
}

/// 解析 `HKCU\...\Internet Settings\Connections\DefaultConnectionSettings`
/// 注册表字节。只提取“是否配置了/启用了 PAC + PAC 目标主机:端口”，
/// PAC URL 的 path/query/secret 绝不进入返回值。
///
/// 字节布局（版本 0x3C/0x46）：version(4) counter(4) options(4)
/// proxyServer(str+null) bypass(str+null) pacUrl(str+null) ...
/// 注意 PAC URL 在 bypass 之后；旧实现漏掉 bypass，把 bypass 误当 PAC。
///
/// WinInet PROXY_TYPE 标志：0x01=DIRECT、0x02=手动代理(PROXY_TYPE_PROXY)、
/// 0x04=PAC 自动配置(PROXY_TYPE_AUTO_PROXY_URL)、0x08=自动检测。
/// blob 尾部残留 PAC URL 字符串不代表 PAC 生效——只有 flags 含 0x04 才算。
pub fn parse_default_connection_settings(data: &[u8]) -> Option<ConnectionSettingsInfo> {
    if data.len() < 12 {
        return None;
    }
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // 常见版本 0x3C/0x46；不一致的字节直接判为无法解析
    if version != 0x3C && version != 0x46 {
        return None;
    }
    let flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let pac_active = flags & 0x04 != 0;
    let mut offset = 12usize;

    let read_len = |offset: usize| -> Option<usize> {
        if offset + 4 > data.len() {
            return None;
        }
        Some(u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize)
    };

    // 跳过一根长度前缀的字符串（proxyServer / bypass），内容不进入结果
    let skip_string = |offset: &mut usize| -> Option<()> {
        let len = read_len(*offset)?;
        *offset += 4;
        if len > data.len().saturating_sub(*offset) {
            return None;
        }
        *offset += len;
        Some(())
    };

    // 静态代理字符串（跳过，不进入结果）
    skip_string(&mut offset)?;
    // bypass 例外列表字符串（跳过，不进入结果）
    skip_string(&mut offset)?;

    // PAC URL 字符串（在 bypass 之后的尾部区域）：只提取 host:port
    let pac_len = read_len(offset)?;
    offset += 4;
    if pac_len > data.len().saturating_sub(offset) {
        return None;
    }
    let pac_bytes = &data[offset..offset + pac_len];
    let pac_text = String::from_utf8_lossy(pac_bytes);
    let pac_text = pac_text.trim_end_matches('\0').trim();

    let mut info = ConnectionSettingsInfo {
        pac_configured: false,
        pac_active,
        pac_target: None,
        pac_hidden_query: false,
    };
    if !pac_text.is_empty() {
        info.pac_configured = true;
        if let Ok(url) = url::Url::parse(pac_text) {
            if let Some(host) = url.host_str() {
                let port = url.port().unwrap_or(80);
                info.pac_target = Some((host.to_string(), port));
                info.pac_hidden_query = url.query().is_some();
            }
        } else {
            // 非 URL 形态（极少见）：不回传原文，仅标记存在
            info.pac_hidden_query = true;
        }
    }
    Some(info)
}

fn collect_env_proxies() -> Vec<String> {
    let mut out = Vec::new();
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"] {
        if let Ok(value) = std::env::var(key) {
            let display = extract_host_port(&value)
                .map(|(host, port)| format!("{key}={host}:{port}"))
                .unwrap_or_else(|| format!("{key}=<无法解析，已隐藏>"));
            out.push(display);
        }
    }
    out
}

/// 保守的 JSONC 预处理：去掉 `//` 与 `/* */` 注释、去掉对象/数组尾逗号。
/// 字符串字面量（含转义）内的内容原样保留，URL 中的 `//` 不受影响；
/// 不做任何其他规范化。settings.json 合法地包含注释和尾逗号（VS Code JSONC）。
fn strip_jsonc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' => match chars.peek() {
                Some('/') => {
                    // 行注释：吃到换行为止
                    for n in chars.by_ref() {
                        if n == '\n' {
                            out.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next();
                    let mut prev = '\0';
                    for n in chars.by_ref() {
                        if prev == '*' && n == '/' {
                            break;
                        }
                        prev = n;
                    }
                }
                _ => out.push(c),
            },
            ',' => {
                // 尾逗号：跳过空白后紧跟 } 或 ] 则丢弃该逗号
                let mut pending_ws = Vec::new();
                let mut trailing = false;
                while let Some(&n) = chars.peek() {
                    if n.is_whitespace() {
                        pending_ws.push(chars.next().expect("peeked"));
                    } else if n == '}' || n == ']' {
                        trailing = true;
                        break;
                    } else {
                        break;
                    }
                }
                if !trailing {
                    out.push(',');
                }
                for w in pending_ws {
                    out.push(w);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// 解析 settings.json 文本（容忍 JSONC 注释与尾逗号）；失败返回 None。
fn parse_settings_jsonc(content: &str) -> Option<serde_json::Value> {
    if content.trim().is_empty() {
        return Some(serde_json::json!({}));
    }
    serde_json::from_str(&strip_jsonc(content)).ok()
}

// ---------------------------------------------------------------------------
// JSONC 局部编辑：只改顶层指定键，注释 / 其他字段 / 原始格式逐字节保留。
// ---------------------------------------------------------------------------

/// 顶层成员在原文中的位置（含相邻逗号，供删除用）。
#[derive(Debug, Clone)]
struct JsoncMember {
    key: String,
    key_start: usize,
    value_end: usize,
    /// 成员前面的 `,`（位于前一个成员与本成员之间）。
    comma_before: Option<usize>,
    /// 成员后面的 `,`（位于本成员与后一个成员之间，含尾逗号）。
    comma_after: Option<usize>,
}

/// 扫描顶层对象的成员键与值区间。非对象/解析失败返回 None。
/// 只识别 `{` 起始的顶层对象；字符串/注释内容不参与结构判断。
fn jsonc_top_level_members(text: &str) -> Option<Vec<JsoncMember>> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();
    // 跳到第一个非空白字符，必须是 {
    while i < n && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= n || bytes[i] != b'{' {
        return None;
    }
    i += 1; // 跳过 '{'
    let mut members: Vec<JsoncMember> = Vec::new();
    let mut pending_comma: Option<usize> = None;
    let mut expect_member = true;
    while i < n {
        let c = bytes[i];
        match c {
            b'"' => {
                let key_start = i;
                let (key, key_end) = scan_jsonc_string(bytes, i)?;
                // 跳过空白与注释找冒号
                i = skip_ws_comments(bytes, key_end);
                if i >= n || bytes[i] != b':' {
                    return None;
                }
                i = skip_ws_comments(bytes, i + 1);
                let value_end = scan_jsonc_value_end(bytes, i)?;
                members.push(JsoncMember {
                    key,
                    key_start,
                    value_end,
                    comma_before: pending_comma,
                    comma_after: None,
                });
                pending_comma = None;
                expect_member = false;
                i = value_end;
            }
            b',' => {
                let pos = i;
                if let Some(last) = members.last_mut() {
                    last.comma_after = Some(pos);
                }
                pending_comma = Some(pos);
                expect_member = true;
                i += 1;
            }
            b'}' => {
                // 尾逗号后 expect_member 仍 true 也算合法结束
                let _ = expect_member;
                return Some(members);
            }
            b'/' => {
                i = skip_ws_comments(bytes, i);
            }
            _ => {
                if c.is_ascii_whitespace() {
                    i += 1;
                } else {
                    return None;
                }
            }
        }
    }
    None
}

/// 解析 `"..."` 字符串，返回 (解码后内容, 结束位置[引号后])。
fn scan_jsonc_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut i = start + 1;
    let mut decoded = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if i + 1 >= bytes.len() {
                    return None;
                }
                decoded.push(bytes[i] as char);
                decoded.push(bytes[i + 1] as char);
                i += 2;
            }
            b'"' => return Some((decoded, i + 1)),
            b => {
                decoded.push(b as char);
                i += 1;
            }
        }
    }
    None
}

/// 跳过空白与 // 和 /* */ 注释，返回下一有效字符位置。
fn skip_ws_comments(bytes: &[u8], mut i: usize) -> usize {
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            return i;
        }
    }
}

/// 从值起始位置扫描到值结束（不含尾部空白/逗号）。
fn scan_jsonc_value_end(bytes: &[u8], start: usize) -> Option<usize> {
    let first = *bytes.get(start)?;
    match first {
        b'"' => scan_jsonc_string(bytes, start).map(|(_, end)| end),
        b'{' | b'[' => {
            // 匹配括号，字符串/注释内不计数
            let open = first;
            let close = if open == b'{' { b'}' } else { b']' };
            let mut depth = 0usize;
            let mut i = start;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => {
                        i = scan_jsonc_string(bytes, i)?.1;
                        continue;
                    }
                    b'/' => {
                        let next = skip_ws_comments(bytes, i);
                        if next != i {
                            i = next;
                            continue;
                        }
                        i += 1;
                    }
                    b if b == open => {
                        depth += 1;
                        i += 1;
                    }
                    b if b == close => {
                        depth -= 1;
                        i += 1;
                        if depth == 0 {
                            return Some(i);
                        }
                    }
                    _ => i += 1,
                }
            }
            None
        }
        _ => {
            // 标量：到 , } ] 空白或注释起点为止
            let mut i = start;
            while i < bytes.len() {
                let b = bytes[i];
                if b == b',' || b == b'}' || b == b']' || b.is_ascii_whitespace() {
                    break;
                }
                if b == b'/' && i + 1 < bytes.len()
                    && (bytes[i + 1] == b'/' || bytes[i + 1] == b'*')
                {
                    break;
                }
                i += 1;
            }
            Some(i)
        }
    }
}

/// 在顶层对象写入/覆盖 `key = value_text`（value_text 为已序列化的 JSON 字面量）。
/// 保留注释与其他字段的原始文本：已有键就地替换值；新键插到首个成员前
/// （沿用其缩进），空对象则在花括号内单行写入。
fn jsonc_set_top_level(text: &str, key: &str, value_text: &str) -> Result<String, String> {
    let members = jsonc_top_level_members(text)
        .ok_or("顶层不是 JSONC 对象，无法局部编辑")?;
    let key_literal = serde_json::to_string(key)
        .map_err(|e| format!("序列化键名失败: {e}"))?;
    if let Some(member) = members.iter().find(|m| m.key == key) {
        // 就地替换值：冒号位置 = key 字符串结束后跳过空白注释
        let (_, key_end) = scan_jsonc_string(text.as_bytes(), member.key_start)
            .ok_or("键字符串解析失败")?;
        let colon = skip_ws_comments(text.as_bytes(), key_end);
        if text.as_bytes().get(colon) != Some(&b':') {
            return Err("键后未找到冒号，无法局部编辑".into());
        }
        let value_start = skip_ws_comments(text.as_bytes(), colon + 1);
        let mut out = String::with_capacity(text.len() + value_text.len());
        out.push_str(&text[..value_start]);
        out.push_str(value_text);
        out.push_str(&text[member.value_end..]);
        return Ok(out);
    }
    // 新键：插到首个成员之前，沿用其缩进
    let brace = text.find('{').expect("members exist implies {");
    if members.is_empty() {
        let mut out = String::with_capacity(text.len() + 64);
        out.push_str(&text[..=brace]);
        out.push_str(&format!(" {key_literal}: {value_text} "));
        out.push_str(&text[brace + 1..]);
        return Ok(out);
    }
    let first = &members[0];
    // 首个成员的缩进 = 其行首到 key_start 的空白；与 { 同行则退化为逗号空格
    let line_start = text[..first.key_start]
        .rfind('\n')
        .map(|p| p + 1)
        .unwrap_or(brace + 1);
    let indent = &text[line_start..first.key_start];
    let separator = if line_start > brace + 1 && indent.trim().is_empty() {
        format!(",\n{indent}")
    } else {
        ", ".to_string()
    };
    let mut out = String::with_capacity(text.len() + 64);
    out.push_str(&text[..first.key_start]);
    out.push_str(&format!("{key_literal}: {value_text}{separator}"));
    out.push_str(&text[first.key_start..]);
    Ok(out)
}

/// 删除顶层成员（含相邻逗号之一），其余文本保留。
fn jsonc_remove_top_level(text: &str, key: &str) -> Result<String, String> {
    let members = jsonc_top_level_members(text)
        .ok_or("顶层不是 JSONC 对象，无法局部编辑")?;
    let Some(idx) = members.iter().position(|m| m.key == key) else {
        return Ok(text.to_string());
    };
    let member = &members[idx];
    let (start, end) = if members.len() == 1 {
        // 唯一成员：连同前后逗号（若有，非严格 JSON 但容忍）整体移除
        let start = member.comma_before.unwrap_or(member.key_start);
        let end = member.comma_after.map(|p| p + 1).unwrap_or(member.value_end);
        (start, end)
    } else if idx == 0 {
        // 首成员：删到后一个成员的 key_start（带走中间逗号与空白）
        let next_start = members[1].key_start;
        (member.key_start, next_start)
    } else {
        // 中间/末成员：从前一个逗号删到本成员值结束
        let start = member.comma_before.unwrap_or(member.key_start);
        let end = member.value_end;
        (start, end)
    };
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..start]);
    out.push_str(&text[end..]);
    Ok(out)
}

#[derive(Debug, Clone, Default)]
struct DevinProxySettings {
    http_proxy: Option<String>,
    /// 旧版误写的嵌套 http.proxy 字段存在（仅提示，不删除）
    legacy_nested_proxy: bool,
    agent_env_keys: Vec<String>,
    parse_error: bool,
}

fn read_devin_proxy_settings(settings_path: &Path) -> DevinProxySettings {
    let mut result = DevinProxySettings::default();
    let content = match std::fs::read_to_string(settings_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return result,
        Err(_) => {
            result.parse_error = true;
            return result;
        }
    };
    let value: serde_json::Value = match parse_settings_jsonc(&content) {
        Some(value) => value,
        None => {
            result.parse_error = true;
            return result;
        }
    };
    // VS Code 系 settings.json 使用扁平键 "http.proxy"；嵌套对象形式是旧版
    // 误写，仅作读取兼容，不再写入。
    let as_proxy_string = |v: &serde_json::Value| {
        v.as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    result.http_proxy = value
        .get("http.proxy")
        .and_then(as_proxy_string)
        .or_else(|| {
            value
                .get("http")
                .and_then(|http| http.get("proxy"))
                .and_then(as_proxy_string)
        });
    result.legacy_nested_proxy = value
        .get("http")
        .and_then(|http| http.get("proxy"))
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    // agentEnv 可能挂在 "devin.acp.agentEnv" 或含 agentEnv 的键下
    let mut collect_agent_env = |value: &serde_json::Value| {
        if let Some(obj) = value.as_object() {
            for key in obj.keys() {
                if key == "devin.acp.agentEnv" || key.to_ascii_lowercase().contains("agentenv") {
                    if let Some(env_obj) = obj.get(key).and_then(|v| v.as_object()) {
                        for env_key in env_obj.keys() {
                            // 只列键名；PROXY 相关键额外带主机:端口，值本身不回传
                            if env_key.to_ascii_uppercase().contains("PROXY") {
                                if let Some((host, port)) = obj
                                    .get(key)
                                    .and_then(|v| v.get(env_key))
                                    .and_then(|v| v.as_str())
                                    .and_then(extract_host_port)
                                {
                                    result
                                        .agent_env_keys
                                        .push(format!("{env_key}={host}:{port}"));
                                    continue;
                                }
                            }
                            result.agent_env_keys.push(env_key.clone());
                        }
                    }
                }
            }
        }
    };
    collect_agent_env(&value);
    result.agent_env_keys.sort();
    result.agent_env_keys.dedup();
    result
}

/// PAC 诊断项（独立函数以便单测）。返回 (item, confirmed_issue, stale_pac)：
/// 只有“生效中的 PAC（flags 含 0x04）指向死端口”才是真故障；
/// 未启用的残留 PAC 字符串（如 flags=0x03）标 ok、无需处理。
fn build_pac_item(
    registry: &RegistryProxyInfo,
    pac_listening: Option<bool>,
) -> (DiagnosticItem, bool, bool) {
    if registry.pac_active {
        match (&registry.pac_target, pac_listening) {
            (Some((host, port)), Some(false)) => {
                let item = DiagnosticItem::new(
                    "proxy.pac_stale",
                    "proxy",
                    "PAC 自动配置脚本",
                    CheckStatus::ConfirmedIssue,
                    format!("当前代理模式已启用 PAC（自动配置脚本），但指向 {host}:{port}（无监听），走 PAC 的流量将被丢弃"),
                );
                let mut evidence = vec![format!("pac_active=true, pac_target={host}:{port}, listening=false")];
                if registry.pac_hidden_query {
                    evidence.push("PAC URL 含查询参数（已隐藏）".to_string());
                }
                (item.with_evidence(evidence), true, true)
            }
            (Some((host, port)), Some(true)) => {
                let item = DiagnosticItem::new(
                    "proxy.pac",
                    "proxy",
                    "PAC 自动配置脚本",
                    CheckStatus::Ok,
                    format!("当前代理模式已启用 PAC，{host}:{port} 端口在监听"),
                );
                let mut evidence = vec![format!("pac_active=true, {host}:{port} listening=true")];
                if registry.pac_hidden_query {
                    evidence.push("PAC URL 含查询参数（已隐藏）".to_string());
                }
                (item.with_evidence(evidence), false, false)
            }
            (Some((host, port)), None) => {
                let mut item = DiagnosticItem::new(
                    "proxy.pac",
                    "proxy",
                    "PAC 自动配置脚本",
                    CheckStatus::Unknown,
                    format!("当前代理模式已启用 PAC，指向 {host}:{port}（非本机地址，无法探测）"),
                );
                if registry.pac_hidden_query {
                    item = item.with_evidence(["PAC URL 含查询参数（已隐藏）".to_string()]);
                }
                (item, false, false)
            }
            (None, _) => (
                DiagnosticItem::new(
                    "proxy.pac",
                    "proxy",
                    "PAC 自动配置脚本",
                    CheckStatus::Unknown,
                    "当前代理模式已启用 PAC，但无法解析目标地址".to_string(),
                ),
                false,
                false,
            ),
        }
    } else if registry.pac_configured {
        // 仅残留字符串（如 flags=0x03 手动代理开、PAC 关）：不是故障
        let mut evidence = Vec::new();
        if let Some((host, port)) = &registry.pac_target {
            evidence.push(format!("pac_active=false, pac_target={host}:{port}"));
        }
        if registry.pac_hidden_query {
            evidence.push("PAC URL 含查询参数（已隐藏）".to_string());
        }
        (
            DiagnosticItem::new(
                "proxy.pac",
                "proxy",
                "PAC 自动配置脚本",
                CheckStatus::Ok,
                "存在未启用的 PAC 残留字符串（当前代理模式未启用 PAC），不影响代理行为，无需处理".to_string(),
            )
            .with_evidence(evidence),
            false,
            false,
        )
    } else {
        (
            DiagnosticItem::new(
                "proxy.pac",
                "proxy",
                "PAC 自动配置脚本",
                CheckStatus::Ok,
                "DefaultConnectionSettings 中没有 PAC 配置".to_string(),
            ),
            false,
            false,
        )
    }
}

/// “可能存在代理问题，待对照验证”项（独立函数以便单测）。
/// 这只是假设而非已确认故障：系统代理/TUN/环境变量可能已接管流量；
/// 端口监听不证明是可用 HTTP 代理；网络慢也可能与代理无关。
fn build_ineffective_item(listening_ports: &[u16]) -> DiagnosticItem {
    DiagnosticItem::new(
        "proxy.ineffective",
        "proxy",
        "可能存在代理问题，待对照验证",
        CheckStatus::Unknown,
        format!(
            "Devin 未配置 http.proxy，且到 codeium 服务的网络不稳定，本机检测到在监听的端口 {}。\
             这不构成已确认的故障：系统代理/TUN 模式/环境变量代理可能已接管流量；\
             端口在监听不能证明它是可用的 HTTP 代理；网络慢也可能与代理无关。\
             可尝试把代理写入 http.proxy 做对照验证（低成本、可回滚）。\
             该 agent 的 system 代理模式支持平台原生 PAC（官方 troubleshooting 文档），\
             但环境变量代理与设置文件代理是更明确的路径",
            listening_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    )
}

fn collect_proxy_info(profile: &Path, network: &[NetworkProbeResult]) -> (ProxySection, Vec<DiagnosticItem>) {
    let mut items = Vec::new();
    let registry = read_windows_proxy_registry();
    let env_proxies = collect_env_proxies();
    let devin_settings = read_devin_proxy_settings(&devin_settings_path(profile));

    let mut listening_ports: Vec<u16> = Vec::new();
    let mut check_listening = |host: &str, port: u16| -> Option<bool> {
        if !is_loopback_host(host) {
            return None;
        }
        if !listening_ports.contains(&port) {
            listening_ports.push(port);
        }
        Some(is_local_port_listening(port))
    };

    let system_endpoint = registry
        .proxy_server
        .as_deref()
        .and_then(extract_host_port);
    let system_listening = system_endpoint
        .as_ref()
        .and_then(|(host, port)| check_listening(host, *port));

    let pac_listening = registry
        .pac_target
        .as_ref()
        .and_then(|(host, port)| check_listening(host, *port));

    let devin_endpoint = devin_settings
        .http_proxy
        .as_deref()
        .and_then(extract_host_port);
    let devin_listening = devin_endpoint
        .as_ref()
        .and_then(|(host, port)| check_listening(host, *port));

    let env_endpoints: Vec<(String, u16)> = env_proxies
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .and_then(|(_, value)| extract_host_port(value))
        })
        .collect();
    for (host, port) in &env_endpoints {
        check_listening(host, *port);
    }

    listening_ports.retain(|p| is_local_port_listening(*p));
    listening_ports.sort_unstable();

    let mut confirmed_issue = false;
    let mut stale_pac = false;

    // 系统代理项
    items.push(match (&registry.proxy_enable, &system_endpoint, system_listening) {
        (Some(true), Some((host, port)), Some(false)) => {
            confirmed_issue = true;
            DiagnosticItem::new(
                "proxy.system_dead",
                "proxy",
                "系统代理",
                CheckStatus::ConfirmedIssue,
                format!("系统代理已启用并指向 {host}:{port}，但该端口无监听，代理流量将被丢弃"),
            )
            .with_evidence([format!("ProxyEnable=1, ProxyServer={host}:{port}, port_listening=false")])
        }
        (Some(true), Some((host, port)), Some(true)) => DiagnosticItem::new(
            "proxy.system",
            "proxy",
            "系统代理",
            CheckStatus::Ok,
            format!("系统代理已启用，{host}:{port} 端口在监听"),
        )
        .with_evidence([format!("ProxyEnable=1, {host}:{port} listening=true")]),
        (Some(true), Some((host, port)), None) => DiagnosticItem::new(
            "proxy.system",
            "proxy",
            "系统代理",
            CheckStatus::Ok,
            format!("系统代理已启用，指向 {host}:{port}（非本机地址，跳过端口探测）"),
        ),
        (Some(false), _, _) => DiagnosticItem::new(
            "proxy.system",
            "proxy",
            "系统代理",
            CheckStatus::Ok,
            "系统代理未启用".to_string(),
        ),
        (None, _, _) => DiagnosticItem::new(
            "proxy.system",
            "proxy",
            "系统代理",
            CheckStatus::Unknown,
            registry
                .read_error
                .clone()
                .unwrap_or_else(|| "无法读取系统代理注册表".to_string()),
        ),
        _ => DiagnosticItem::new(
            "proxy.system",
            "proxy",
            "系统代理",
            CheckStatus::Unknown,
            "系统代理配置无法解析".to_string(),
        ),
    });

    // PAC 项：区分“生效中的 PAC”（flags 含 0x04）与“未启用的残留字符串”。
    // 只有生效中的 PAC 指向死端口才是真故障；残留字符串本身不影响代理行为。
    let (pac_item, pac_issue, pac_stale) = build_pac_item(&registry, pac_listening);
    if pac_issue {
        confirmed_issue = true;
    }
    if pac_stale {
        stale_pac = true;
    }
    items.push(pac_item);

    // Devin settings.json 代理项
    items.push(if devin_settings.parse_error {
        DiagnosticItem::new(
            "proxy.devin_settings",
            "proxy",
            "Devin 代理设置",
            CheckStatus::Unknown,
            "Devin User/settings.json 无法解析（JSON 损坏或读取失败）".to_string(),
        )
    } else {
        match (&devin_endpoint, devin_listening) {
        (Some((host, port)), Some(false)) => {
            confirmed_issue = true;
            DiagnosticItem::new(
                "proxy.devin_dead",
                "proxy",
                "Devin 代理设置",
                CheckStatus::ConfirmedIssue,
                format!("Devin settings.json 的 http.proxy 指向 {host}:{port}，但该端口无监听"),
            )
            .with_evidence([format!("http.proxy=http://{host}:{port}, listening=false")])
        }
        (Some((host, port)), _) => {
            let mut evidence = vec![format!("http.proxy={host}:{port}")];
            if devin_settings.legacy_nested_proxy {
                evidence.push(
                    "检测到嵌套 http.proxy 字段（历史误写形式，已保留未动）".to_string(),
                );
            }
            DiagnosticItem::new(
                "proxy.devin_settings",
                "proxy",
                "Devin 代理设置",
                CheckStatus::Ok,
                format!("Devin settings.json 的 http.proxy 为 {host}:{port}"),
            )
            .with_evidence(evidence)
        }
        (None, _) => DiagnosticItem::new(
            "proxy.devin_settings",
            "proxy",
            "Devin 代理设置",
            CheckStatus::Ok,
            "Devin settings.json 未配置 http.proxy".to_string(),
        ),
        }
    });

    // 环境变量代理项
    items.push(if env_proxies.is_empty() {
        DiagnosticItem::new(
            "proxy.env",
            "proxy",
            "环境变量代理",
            CheckStatus::Ok,
            "进程环境变量中没有 HTTP(S)_PROXY".to_string(),
        )
    } else {
        DiagnosticItem::new(
            "proxy.env",
            "proxy",
            "环境变量代理",
            CheckStatus::Ok,
            "进程环境变量中存在代理设置（仅显示主机:端口）".to_string(),
        )
        .with_evidence(env_proxies.iter().cloned())
    });

    // 一致性项：多处代理指向不一致
    let mut endpoints: Vec<String> = Vec::new();
    if registry.proxy_enable == Some(true) {
        if let Some((host, port)) = &system_endpoint {
            endpoints.push(format!("{host}:{port}"));
        }
    }
    if let Some((host, port)) = &devin_endpoint {
        endpoints.push(format!("{host}:{port}"));
    }
    for (host, port) in &env_endpoints {
        endpoints.push(format!("{host}:{port}"));
    }
    endpoints.sort();
    endpoints.dedup();
    if endpoints.len() > 1 {
        items.push(DiagnosticItem::new(
            "proxy.inconsistent",
            "proxy",
            "代理配置一致性",
            CheckStatus::Unknown,
            "多处代理配置指向不同端口，Devin 实际走哪个代理取决于官方扩展的取值顺序".to_string(),
        )
        .with_evidence(endpoints.iter().map(|e| format!("endpoint={e}"))));
    }

    // 待对照验证项：Devin 未配 http.proxy + codeium 系网络差 + 本机有在监听端口。
    // 注意这只是一种假设——系统代理/TUN 模式/环境变量代理可能已接管流量，
    // 端口在监听不能证明它是可用的 HTTP 代理，网络慢也可能与代理无关——
    // 因此状态为 unknown，不升级为 confirmed_issue（confirmed_proxy_issue
    // 仍置位，供 summary 与修复入口做"对照验证"推荐）。
    let codeium_degraded = network.iter().any(|probe| {
        probe.host.ends_with("codeium.com")
            && matches!(
                probe.classification.as_str(),
                "tcp_failed" | "tls_failed" | "high_latency" | "unstable" | "tail_latency"
            )
    });
    let ineffective_proxy = devin_endpoint.is_none()
        && codeium_degraded
        && !listening_ports.is_empty();
    if ineffective_proxy {
        confirmed_issue = true;
        items.push(build_ineffective_item(&listening_ports));
    }

    let section = ProxySection {
        system_proxy_enabled: registry.proxy_enable.unwrap_or(false),
        system_proxy_server: system_endpoint
            .as_ref()
            .map(|(host, port)| format!("{host}:{port}")),
        system_proxy_listening: system_listening,
        pac_configured: registry.pac_configured,
        pac_active: registry.pac_active,
        pac_target: registry
            .pac_target
            .as_ref()
            .map(|(host, port)| format!("{host}:{port}")),
        pac_listening,
        env_proxies,
        devin_settings_proxy: devin_endpoint
            .as_ref()
            .map(|(host, port)| format!("{host}:{port}")),
        devin_agent_env_keys: devin_settings.agent_env_keys,
        confirmed_proxy_issue: confirmed_issue,
        stale_pac_confirmed: stale_pac,
        ineffective_proxy_confirmed: ineffective_proxy,
        listening_local_ports: listening_ports,
    };
    (section, items)
}

// ---------------------------------------------------------------------------
// C. 网络探测（TCP + TLS 计时，不发 HTTP 请求、不带凭据）
// ---------------------------------------------------------------------------

const PROBE_HOSTS: [&str; 4] = [
    "server.codeium.com",
    "api.codeium.com",
    "unleash.codeium.com",
    "app.devin.ai",
];

const PROBE_ATTEMPTS: usize = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

fn probe_host(host: &str) -> NetworkProbeResult {
    // DNS 解析（带超时；超时则放弃该线程结果）
    let (dns_ok, resolved_ip, addr) = {
        let host_owned = host.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(format!("{host_owned}:443").to_socket_addrs());
        });
        match rx.recv_timeout(Duration::from_secs(8)) {
            Ok(Ok(addrs)) => {
                let addrs: Vec<SocketAddr> = addrs.collect();
                match addrs.first() {
                    Some(addr) => (true, Some(addr.ip().to_string()), *addr),
                    None => (false, None, SocketAddr::from(([0, 0, 0, 0], 0))),
                }
            }
            Ok(Err(_)) => (false, None, SocketAddr::from(([0, 0, 0, 0], 0))),
            Err(_) => (false, None, SocketAddr::from(([0, 0, 0, 0], 0))),
        }
    };

    let mut tcp_times: Vec<u128> = Vec::new();
    let mut tls_times: Vec<u128> = Vec::new();
    let mut tls_attempted = false;

    if dns_ok {
        for _ in 0..PROBE_ATTEMPTS {
            let start = Instant::now();
            let stream = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            tcp_times.push(start.elapsed().as_millis());
            #[cfg(target_os = "windows")]
            if let Ok(()) = stream.set_read_timeout(Some(CONNECT_TIMEOUT))
                .and_then(|()| stream.set_write_timeout(Some(CONNECT_TIMEOUT)))
            {
                tls_attempted = true;
                let tls_start = Instant::now();
                if tls_handshake(host, stream).is_ok() {
                    tls_times.push(tls_start.elapsed().as_millis());
                }
            }
            #[cfg(not(target_os = "windows"))]
            let _ = stream;
        }
    }

    let classification = classify_probe(dns_ok, &tcp_times, tls_attempted, &tls_times);
    let risk_note = if classification == "tail_latency" {
        let all_max = tcp_times
            .iter()
            .chain(tls_times.iter())
            .copied()
            .max()
            .unwrap_or(0);
        let all_min = tcp_times
            .iter()
            .chain(tls_times.iter())
            .copied()
            .min()
            .unwrap_or(0);
        Some(format!(
            "检测到高延迟波动（单次连接/握手 max {}ms，波动 {}ms），认证类请求可能超时",
            all_max,
            all_max.saturating_sub(all_min)
        ))
    } else if host.ends_with("codeium.com") && classification != "ok" {
        Some("本地 agent 认证需要访问 codeium 服务（team settings 拉取 10 秒超时、失败即硬失败），当前网络状况可能导致模型列表为空 / ACP 断连".to_string())
    } else {
        None
    };

    NetworkProbeResult {
        host: host.to_string(),
        dns_ok,
        resolved_ip,
        tcp: (!tcp_times.is_empty()).then(|| ProbeTiming {
            attempts: PROBE_ATTEMPTS as u8,
            successes: tcp_times.len() as u8,
            min_ms: tcp_times.iter().min().copied().unwrap_or(0) as u64,
            max_ms: tcp_times.iter().max().copied().unwrap_or(0) as u64,
        }),
        tls: if tls_attempted {
            Some(ProbeTiming {
                attempts: tcp_times.len() as u8,
                successes: tls_times.len() as u8,
                min_ms: tls_times.iter().min().copied().unwrap_or(0) as u64,
                max_ms: tls_times.iter().max().copied().unwrap_or(0) as u64,
            })
        } else {
            None
        },
        classification,
        // 管理器探测始终走 TcpStream 直连，不代表 Devin 子进程的实际路径
        path: "direct".to_string(),
        risk_note,
    }
}

#[cfg(target_os = "windows")]
fn tls_handshake(host: &str, stream: TcpStream) -> Result<(), String> {
    let connector = native_tls::TlsConnector::builder()
        .build()
        .map_err(|e| format!("构建 TLS connector 失败: {e}"))?;
    connector
        .connect(host, stream)
        .map(|_| ())
        .map_err(|e| format!("TLS 握手失败: {e}"))
}

#[cfg(not(target_os = "windows"))]
fn tls_handshake(_host: &str, _stream: TcpStream) -> Result<(), String> {
    Err("当前平台暂不支持 TLS 握手计时".to_string())
}

/// 判定逻辑（独立函数以便单测）：
/// dns_failed / tcp_failed / tls_failed / high_latency(tcp max≥5s) /
/// unstable(tcp 波动≥3s) / tail_latency(尾部延迟或波动，见下) / ok
///
/// 尾部延迟维度：认证类请求（team settings 10 秒超时）对单次高延迟敏感，
/// TLS 握手时间与 TCP 一起计入——
/// - 任一样本 max ≥ 5000ms → tail_latency
/// - max ≥ 3000ms 且 max−min ≥ 3000ms → tail_latency（波动）
/// - 3000ms ≤ max < 5000ms（无大幅波动）也不允许 ok，保守标 tail_latency
/// 只有全部成功且 max < 3000ms 才是 ok。
pub fn classify_probe(
    dns_ok: bool,
    tcp_times_ms: &[u128],
    tls_attempted: bool,
    tls_times_ms: &[u128],
) -> String {
    if !dns_ok {
        return "dns_failed".to_string();
    }
    if tcp_times_ms.is_empty() {
        return "tcp_failed".to_string();
    }
    if tls_attempted && tls_times_ms.is_empty() {
        return "tls_failed".to_string();
    }
    let max = *tcp_times_ms.iter().max().unwrap_or(&0);
    let min = *tcp_times_ms.iter().min().unwrap_or(&0);
    if max >= 5000 {
        return "high_latency".to_string();
    }
    if tcp_times_ms.len() >= 2 && max.saturating_sub(min) >= 3000 {
        return "unstable".to_string();
    }
    // 尾部延迟维度（计入 TLS 握手）
    let all_times: Vec<u128> = tcp_times_ms
        .iter()
        .chain(tls_times_ms.iter())
        .copied()
        .collect();
    let all_max = all_times.iter().max().copied().unwrap_or(0);
    let all_min = all_times.iter().min().copied().unwrap_or(0);
    if all_max >= 5000 {
        return "tail_latency".to_string();
    }
    if all_max >= 3000 && all_max.saturating_sub(all_min) >= 3000 {
        return "tail_latency".to_string();
    }
    if all_max >= 3000 {
        return "tail_latency".to_string();
    }
    "ok".to_string()
}

fn run_network_probes() -> (Vec<NetworkProbeResult>, Vec<DiagnosticItem>) {
    let mut handles = Vec::new();
    for host in PROBE_HOSTS {
        handles.push(std::thread::spawn(move || probe_host(host)));
    }
    let mut results = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(result) => results.push(result),
            Err(_) => results.push(NetworkProbeResult {
                host: "<unknown>".to_string(),
                dns_ok: false,
                resolved_ip: None,
                tcp: None,
                tls: None,
                classification: "unknown".to_string(),
                path: "unknown".to_string(),
                risk_note: None,
            }),
        }
    }
    results.sort_by_key(|r| {
        PROBE_HOSTS.iter().position(|h| *h == r.host).unwrap_or(usize::MAX)
    });

    let items = results
        .iter()
        .map(|probe| {
            let (status, detail) = match probe.classification.as_str() {
                "ok" => (CheckStatus::Ok, format!("{} 连接正常", probe.host)),
                "dns_failed" => (
                    CheckStatus::ConfirmedIssue,
                    format!("{} DNS 解析失败，本地网络/DNS 异常", probe.host),
                ),
                "tcp_failed" => (
                    CheckStatus::ConfirmedIssue,
                    format!("{} TCP 443 三次探测全部失败，链路不可达", probe.host),
                ),
                "tls_failed" => (
                    CheckStatus::ConfirmedIssue,
                    format!("{} TCP 可连但 TLS 握手失败（可能被中间设备拦截）", probe.host),
                ),
                "high_latency" => (
                    CheckStatus::ConfirmedIssue,
                    format!(
                        "{} 延迟过高（max {}ms），超过 agent 的 10 秒超时风险阈值",
                        probe.host,
                        probe.tcp.as_ref().map(|t| t.max_ms).unwrap_or(0)
                    ),
                ),
                "unstable" => (
                    CheckStatus::Unknown,
                    format!("{} 延迟波动大，高峰时段可能超时", probe.host),
                ),
                "tail_latency" => (
                    CheckStatus::Unknown,
                    format!(
                        "{} 检测到高延迟波动（单次连接/握手 max {}ms），认证类请求可能超时",
                        probe.host,
                        probe
                            .tcp
                            .iter()
                            .chain(probe.tls.iter())
                            .map(|t| t.max_ms)
                            .max()
                            .unwrap_or(0)
                    ),
                ),
                _ => (CheckStatus::Unknown, format!("{} 无法判断", probe.host)),
            };
            let item = DiagnosticItem::new(
                &format!("network.{}", probe.host.replace('.', "_")),
                "network",
                &format!("网络探测 {}", probe.host),
                status,
                detail,
            );
            let mut evidence = Vec::new();
            if let Some(ip) = &probe.resolved_ip {
                evidence.push(format!("resolved={ip}"));
            }
            if let Some(tcp) = &probe.tcp {
                evidence.push(format!(
                    "tcp attempts={} successes={} min={}ms max={}ms",
                    tcp.attempts, tcp.successes, tcp.min_ms, tcp.max_ms
                ));
            }
            if let Some(tls) = &probe.tls {
                evidence.push(format!(
                    "tls attempts={} successes={} min={}ms max={}ms",
                    tls.attempts, tls.successes, tls.min_ms, tls.max_ms
                ));
            }
            if let Some(note) = &probe.risk_note {
                evidence.push(note.clone());
            }
            item.with_evidence(evidence)
        })
        .collect();
    (results, items)
}

// ---------------------------------------------------------------------------
// D. Agent 日志分析（只读）
// ---------------------------------------------------------------------------

const LOG_TAIL_BYTES: u64 = 256 * 1024;
const LOGS_EXAMINED: usize = 10;

/// 失败行分类：网络超时 / 认证失败 / 权限 / 配置 / 未知。
/// 分别展示、互不吞并——尤其不得把未知错误默认归为"额度耗尽"。
fn classify_failure_line(line: &str) -> &'static str {
    let lower = line.to_ascii_lowercase();
    if line.contains("timed out") || lower.contains("timeout") {
        "network_timeout"
    } else if line.contains(" 401")
        || line.contains(" 403")
        || lower.contains("unauthorized")
        || lower.contains("forbidden")
        || lower.contains("invalid auth")
    {
        "auth_failed"
    } else if lower.contains("eacces") || lower.contains("permission denied") {
        "permission"
    } else if lower.contains("config") {
        "config"
    } else {
        "unknown"
    }
}

fn analyze_logs(profile: &Path) -> (LogDiagnostics, Vec<DiagnosticItem>) {
    let log_dir = profile.join("cli").join("logs");
    let mut files: Vec<(PathBuf, u64, SystemTime)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if !name.starts_with("devin_") || !name.ends_with(".log") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                files.push((path, meta.len(), meta.modified().unwrap_or(UNIX_EPOCH)));
            }
        }
    }
    files.sort_by(|a, b| b.2.cmp(&a.2));
    let total_files = files.len();
    let examined: Vec<&(PathBuf, u64, SystemTime)> = files.iter().take(LOGS_EXAMINED).collect();

    let mut agent_starts = 0usize;
    let mut authenticate_attempts = 0usize;
    let mut authenticate_with_credentials = 0usize;
    let mut team_settings_failures = 0usize;
    let mut timeout_failures = 0usize;
    let mut zdr_timeouts = 0usize;
    let mut remote_config_failures = 0usize;
    let mut last_failure_at: Option<String> = None;
    let mut agent_versions: Vec<String> = Vec::new();
    let mut sample_failure_line: Option<String> = None;
    let mut failure_categories: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();

    for (path, len, _) in &examined {
        for line in tail_lines(path, *len).iter().map(|l| l.as_str()) {
            if let Some(version) = parse_agent_version(line) {
                if !agent_versions.contains(&version) {
                    agent_versions.push(version);
                }
            }
            let timestamp = parse_log_timestamp(line);
            if line.contains("ACP server ready") {
                agent_starts += 1;
            }
            if let Some(auth) = parse_authenticate_line(line) {
                authenticate_attempts += 1;
                if auth.had_credentials {
                    authenticate_with_credentials += 1;
                }
            }
            let is_team_settings_failure = line.contains("Team settings refresh failed");
            if is_team_settings_failure {
                team_settings_failures += 1;
                if sample_failure_line.is_none() {
                    sample_failure_line = Some(truncate_evidence(line));
                }
                failure_categories.insert(classify_failure_line(line).to_string());
            }
            if is_team_settings_failure && line.contains("timed out") {
                timeout_failures += 1;
            }
            if line.contains("ZDR status refresh timed out") {
                zdr_timeouts += 1;
                failure_categories.insert("network_timeout".to_string());
            }
            if line.contains("remote config revalidation failed") {
                remote_config_failures += 1;
                failure_categories.insert("config".to_string());
            }
            // 认证/权限类失败（401/403 与凭据被拒、权限错误分列展示）
            let lower = line.to_ascii_lowercase();
            if line.contains(" 401") || line.contains(" 403")
                || lower.contains("unauthorized") || lower.contains("forbidden")
            {
                failure_categories.insert("auth_failed".to_string());
            }
            if lower.contains("eacces") || lower.contains("permission denied") {
                failure_categories.insert("permission".to_string());
            }
            if is_team_settings_failure {
                if let Some(ts) = timestamp {
                    last_failure_at = Some(ts);
                }
            }
        }
    }

    // 当前在跑的 agent：日志文件名中带 PID
    let mut running_agent_pids: Vec<u32> = examined
        .iter()
        .filter_map(|(path, _, _)| log_file_pid(path))
        .filter(|pid| crate::modules::process::is_pid_running(*pid))
        .collect();
    running_agent_pids.sort_unstable();
    running_agent_pids.dedup();

    // 最新一份在跑 PID 对应日志的认证状态
    let newest_running_log = examined.iter().find(|(path, _, _)| {
        log_file_pid(path)
            .map(|pid| running_agent_pids.contains(&pid))
            .unwrap_or(false)
    });
    let (running_agents_authenticated, newest_log_has_auth_failure) = match newest_running_log {
        Some((path, len, _)) => {
            let lines = tail_lines(path, *len);
            let has_auth = lines.iter().any(|l| parse_authenticate_line(l).is_some());
            let has_failure = lines.iter().any(|l| l.contains("Team settings refresh failed"));
            (has_auth.then_some(!has_failure), has_failure)
        }
        None => (None, false),
    };

    let diag = LogDiagnostics {
        log_dir: redact_text(&log_dir.to_string_lossy()),
        total_log_files: total_files,
        logs_examined: examined.len(),
        agent_starts,
        authenticate_attempts,
        authenticate_with_credentials,
        team_settings_failures,
        timeout_failures,
        zdr_timeouts,
        remote_config_failures,
        last_failure_at: last_failure_at.map(|ts| redact_text(&ts)),
        agent_versions,
        running_agent_pids,
        running_agents_authenticated,
        newest_log_has_auth_failure,
        failure_categories: failure_categories.into_iter().collect(),
    };

    let mut items = Vec::new();
    items.push(if total_files == 0 {
        DiagnosticItem::new(
            "logs.presence",
            "logs",
            "Agent 日志",
            CheckStatus::Unknown,
            "未找到 agent 日志（客户端可能从未启动 agent 或日志目录不存在）".to_string(),
        )
    } else {
        DiagnosticItem::new(
            "logs.presence",
            "logs",
            "Agent 日志",
            CheckStatus::Ok,
            format!("日志目录存在，共 {total_files} 个日志文件，分析了最近 {} 个（每个取尾部 256KB）", examined.len()),
        )
        .with_evidence([format!("dir={}", diag.log_dir)])
    });

    let auth_status = if team_settings_failures > 0 {
        CheckStatus::ConfirmedIssue
    } else if authenticate_attempts > 0 {
        CheckStatus::Ok
    } else {
        CheckStatus::Unknown
    };
    let mut auth_item = DiagnosticItem::new(
        "logs.auth",
        "logs",
        "Agent 认证记录",
        auth_status,
        format!(
            "agent 启动 {agent_starts} 次，认证尝试 {authenticate_attempts} 次（含凭据 {authenticate_with_credentials} 次），team settings 失败 {team_settings_failures} 次（超时 {timeout_failures} 次）"
        ),
    );
    let mut evidence = Vec::new();
    if !diag.agent_versions.is_empty() {
        evidence.push(format!("agent_versions={}", diag.agent_versions.join(", ")));
    }
    if let Some(ts) = &diag.last_failure_at {
        evidence.push(format!("last_failure_at={ts}"));
    }
    if let Some(sample) = sample_failure_line {
        evidence.push(format!("sample={sample}"));
    }
    if zdr_timeouts > 0 {
        evidence.push(format!("zdr_timeouts={zdr_timeouts}"));
    }
    if remote_config_failures > 0 {
        evidence.push(format!("remote_config_failures={remote_config_failures}"));
    }
    auth_item = auth_item.with_evidence(evidence);
    items.push(auth_item);

    items.push(match diag.running_agents_authenticated {
        Some(true) => DiagnosticItem::new(
            "logs.running_agent",
            "logs",
            "在跑 Agent 状态",
            CheckStatus::Ok,
            format!("PID {} 对应的日志中认证未出现失败", diag.running_agent_pids.first().copied().unwrap_or(0)),
        ),
        Some(false) => DiagnosticItem::new(
            "logs.running_agent",
            "logs",
            "在跑 Agent 状态",
            CheckStatus::ConfirmedIssue,
            format!(
                "PID {} 对应的最新日志中出现 team settings 认证失败；该 agent 进程认证失败后仍在运行，可尝试重启 Devin 让 agent 重新认证",
                diag.running_agent_pids.first().copied().unwrap_or(0)
            ),
        ),
        None => DiagnosticItem::new(
            "logs.running_agent",
            "logs",
            "在跑 Agent 状态",
            CheckStatus::Unknown,
            if diag.running_agent_pids.is_empty() {
                "没有与日志 PID 匹配的正在运行的 agent 进程".to_string()
            } else {
                "在跑 agent 的日志中没有认证记录，无法判断".to_string()
            },
        ),
    });

    (diag, items)
}

fn truncate_evidence(line: &str) -> String {
    let trimmed = line.trim();
    let cut: String = trimmed.chars().take(240).collect();
    if trimmed.chars().count() > 240 {
        format!("{cut}…")
    } else {
        cut
    }
}

fn tail_lines(path: &Path, len: u64) -> Vec<String> {
    use std::io::{Seek, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return Vec::new(),
    };
    let start = len.saturating_sub(LOG_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let reader = BufReader::new(file);
    reader.lines().map_while(|line| line.ok()).collect()
}

/// 从日志行解析时间戳前缀（`2026-10-17T06:42:06.416191Z`）。
pub fn parse_log_timestamp(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.len() < 20 {
        return None;
    }
    // 用 .get() 避免多字节字符处按字节切片导致 panic
    let date = trimmed.get(..10)?;
    let rest = trimmed.get(10..)?;
    if date.chars().filter(|c| *c == '-').count() == 2
        && date.chars().take(4).all(|c| c.is_ascii_digit())
        && rest.starts_with('T')
    {
        let window_len = trimmed.len().min(40);
        let window = trimmed.get(..window_len)?;
        match window.find('Z') {
            // 时间戳包含结尾的 'Z'
            Some(i) => Some(trimmed.get(..=i)?.to_string()),
            None => Some(window.to_string()),
        }
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateLine {
    pub had_credentials: bool,
    pub method_id: Option<String>,
}

/// 解析 `authenticate #N ... had_credentials=true/false, method_id=...` 行。
pub fn parse_authenticate_line(line: &str) -> Option<AuthenticateLine> {
    if !line.contains("authenticate #") {
        return None;
    }
    let had_credentials = line
        .split("had_credentials=")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .map(|value| value.trim() == "true");
    let method_id = line
        .split("method_id=")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .map(|value| value.trim().trim_matches('"').to_string());
    match had_credentials {
        Some(had_credentials) => Some(AuthenticateLine {
            had_credentials,
            method_id,
        }),
        None => None,
    }
}

/// 从日志文件名解析 PID：`devin_20261017-143113_18508.log` → 18508。
pub fn log_file_pid(path: &Path) -> Option<u32> {
    let stem = path.file_stem()?.to_str()?;
    stem.rsplit('_').next()?.parse().ok()
}

/// 从日志行提取 agent 版本：`version=3000.10.67`。
pub fn parse_agent_version(line: &str) -> Option<String> {
    let rest = line.split("version=").nth(1)?;
    let version: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if version.is_empty() {
        None
    } else {
        Some(version.trim_end_matches('.').to_string())
    }
}

// ---------------------------------------------------------------------------
// E. 综合结论
// ---------------------------------------------------------------------------

fn build_summary(
    client: &ClientDiagnostics,
    proxy: &ProxySection,
    network: &[NetworkProbeResult],
    logs: &LogDiagnostics,
) -> SummarySection {
    let codeium_degraded = network.iter().any(|probe| {
        probe.host.ends_with("codeium.com")
            && matches!(
                probe.classification.as_str(),
                "dns_failed" | "tcp_failed" | "tls_failed" | "high_latency" | "unstable" | "tail_latency"
            )
    });

    let (category, confidence, overview): (String, String, String) = if proxy.confirmed_proxy_issue {
        (
            "proxy_config".to_string(),
            "高：代理相关异常已由端口探测确认".to_string(),
            "诊断发现已确认的代理配置异常（死端口 / 生效中的 PAC 指向死端口 / 代理未接入 Devin），这是模型列表为空的最常见原因之一。".to_string(),
        )
    } else if codeium_degraded {
        (
            "network_timeout".to_string(),
            "中：网络探测显示到 codeium 服务的链路不稳定，但根因（运营商链路/时段拥塞/DNS）无法从本机完全确认".to_string(),
            "到 codeium 认证服务的网络超时或高延迟；agent 拉取 team settings 有 10 秒超时且失败即硬失败，高峰时段表现为模型列表为空。".to_string(),
        )
    } else if logs.team_settings_failures > 0 || logs.running_agents_authenticated == Some(false) {
        (
            "auth_state".to_string(),
            "中：日志中存在认证失败记录，但当前网络探测正常，可能是历史残留".to_string(),
            "日志中存在 team settings 认证失败记录；若问题仍在持续，可尝试重启 Devin 让 agent 重新认证。".to_string(),
        )
    } else {
        (
            "none".to_string(),
            "低：未发现明确的异常证据".to_string(),
            "本次诊断未发现网络、代理或认证日志方面的明确异常。若模型列表仍为空，请在故障发生时段重新运行诊断。".to_string(),
        )
    };

    let mut fixes = Vec::new();
    if proxy.stale_pac_confirmed {
        fixes.push(RecommendedFix {
            id: "clear_stale_pac_config".into(),
            label: "清除指向死端口的 PAC 配置（手动步骤，提供指引）".into(),
            requires_restart: false,
            affects_login: false,
            manual: true,
        });
    }
    if proxy.confirmed_proxy_issue {
        fixes.push(RecommendedFix {
            id: "apply_client_proxy_fix".into(),
            label: "把可用的本机代理端口写入 Devin 的 http.proxy（对照验证用，可回滚）".into(),
            requires_restart: false,
            affects_login: false,
            manual: false,
        });
    }
    // ACP 连接重载：客户端注册的官方命令，但无外部调用入口——
    // 只能给命令面板手动指引，不模拟执行结果。
    // 涉及元数据缓存刷新，提示可能影响会话显示。
    let acp_issue_likely = logs.team_settings_failures > 0
        || logs.running_agents_authenticated == Some(false)
        || logs.newest_log_has_auth_failure;
    if acp_issue_likely && client.acp_reload_available {
        fixes.push(RecommendedFix {
            id: "reload_acp_connections".into(),
            label: "在客户端执行「Devin: Reload ACP Connections」（命令面板手动步骤）".into(),
            requires_restart: false,
            affects_login: false,
            manual: true,
        });
    }
    if logs.team_settings_failures > 0
        || logs.running_agents_authenticated == Some(false)
        || codeium_degraded
    {
        fixes.push(RecommendedFix {
            id: "restart_devin_client".into(),
            label: "温和重启官方客户端（让 agent 子进程重新认证）".into(),
            requires_restart: true,
            affects_login: false,
            manual: false,
        });
    }

    SummarySection {
        category,
        confidence,
        overview,
        recommended_fixes: fixes,
    }
}

// ---------------------------------------------------------------------------
// 引擎入口 + 缓存
// ---------------------------------------------------------------------------

static LAST_DIAGNOSTICS: Mutex<Option<DiagnosticsResult>> = Mutex::new(None);

pub fn run_full_diagnostics() -> Result<DiagnosticsResult, String> {
    let started = Instant::now();
    let profile = client::get_default_windsurf_user_data_dir()?;

    let (client_info, mut client_items) = collect_client_info();
    let (network, mut network_items) = run_network_probes();
    let (proxy_section, mut proxy_items) = collect_proxy_info(&profile, &network);
    let (log_diag, mut log_items) = analyze_logs(&profile);
    let summary = build_summary(&client_info, &proxy_section, &network, &log_diag);

    let mut items = Vec::new();
    items.append(&mut client_items);
    items.append(&mut proxy_items);
    items.append(&mut network_items);
    items.append(&mut log_items);

    let result = DiagnosticsResult {
        generated_at_ms: now_ms(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        items,
        client: client_info,
        proxy: proxy_section,
        network,
        logs: log_diag,
        summary,
    };

    // 本机缓存（内容已全部脱敏）
    if let Ok(dir) = diagnostics_dir() {
        let cache_path = dir.join("last.json");
        if let Ok(json) = serde_json::to_string_pretty(&result) {
            let _ = crate::modules::atomic_write::write_string_atomic(&cache_path, &json);
        }
    }
    if let Ok(mut slot) = LAST_DIAGNOSTICS.lock() {
        *slot = Some(result.clone());
    }
    crate::modules::logger::log_info(&format!(
        "[Diagnostics] 诊断完成，耗时 {}ms",
        started.elapsed().as_millis()
    ));
    Ok(result)
}

fn load_last_diagnostics() -> Option<DiagnosticsResult> {
    if let Ok(slot) = LAST_DIAGNOSTICS.lock() {
        if let Some(result) = slot.as_ref() {
            return Some(result.clone());
        }
    }
    let cache = diagnostics_dir()
        .ok()?
        .join("last.json");
    let content = std::fs::read_to_string(cache).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn render_markdown_report(result: &DiagnosticsResult) -> String {
    let mut md = String::new();
    md.push_str("# Devin Desktop 连接诊断报告\n\n");
    md.push_str("> 本报告已自动脱敏（Token / API Key / 邮箱 / URL 查询参数均已隐藏），仅保存于本机，未上传。\n\n");
    md.push_str(&format!("- 生成时间: {}\n", result.generated_at_ms));
    md.push_str(&format!("- 管理器版本: {}\n", result.app_version));
    md.push_str(&format!("- 综合结论: **{}**（{}）\n", result.summary.category, result.summary.confidence));
    md.push_str(&format!("- 概述: {}\n\n", result.summary.overview));

    md.push_str("## 客户端环境\n\n");
    let client = &result.client;
    md.push_str(&format!(
        "- 客户端: {}（存在: {}）版本: {} commit: {}\n",
        client.exe_path.as_deref().unwrap_or("未知"),
        client.exe_exists,
        client.product_version.as_deref().unwrap_or("未知"),
        client.product_commit.as_deref().unwrap_or("未知")
    ));
    md.push_str(&format!(
        "- 数据目录: {}（存在: {}）settings.json: {} CLI 日志目录: {}\n",
        client.data_dir.as_deref().unwrap_or("未知"),
        client.data_dir_exists,
        client.user_settings_exists,
        client.cli_log_dir_exists
    ));
    md.push_str(&format!(
        "- 进程: IDE x{} / agent x{}；ACP 命令: reload={} reconnect={}\n\n",
        client.ide_processes_running,
        client.agent_processes_running,
        client.acp_reload_available,
        client.acp_reconnect_available
    ));

    md.push_str("## 检查项明细\n\n");
    for item in &result.items {
        md.push_str(&format!(
            "### [{}] {}（{}）\n\n{}\n\n",
            item.status.label(),
            item.title,
            item.group,
            item.detail
        ));
        if !item.evidence.is_empty() {
            md.push_str("证据：\n\n");
            for line in &item.evidence {
                md.push_str(&format!("- `{}`\n", line.replace('`', "'")));
            }
            md.push('\n');
        }
    }

    md.push_str("## 代理快照\n\n");
    md.push_str(&format!(
        "- 系统代理: enabled={} server={:?} listening={:?}\n",
        result.proxy.system_proxy_enabled,
        result.proxy.system_proxy_server,
        result.proxy.system_proxy_listening
    ));
    md.push_str(&format!(
        "- PAC: configured={} active={} target={:?} listening={:?}\n",
        result.proxy.pac_configured,
        result.proxy.pac_active,
        result.proxy.pac_target,
        result.proxy.pac_listening
    ));
    md.push_str(&format!(
        "- Devin http.proxy: {:?}\n",
        result.proxy.devin_settings_proxy
    ));
    md.push_str(&format!(
        "- Devin agentEnv 键: {:?}\n",
        result.proxy.devin_agent_env_keys
    ));
    md.push_str(&format!(
        "- 环境变量代理: {:?}\n",
        result.proxy.env_proxies
    ));
    md.push_str(&format!(
        "- 本机在监听端口: {:?}\n\n",
        result.proxy.listening_local_ports
    ));

    md.push_str("## 网络探测\n\n");
    md.push_str("说明：探测由管理器发起、路径标为 direct 时代表直连，不能等同于 Devin 子进程业务请求的实际路径。\n\n");
    for probe in &result.network {
        md.push_str(&format!(
            "- {}: path={} dns_ok={} classification={} resolved={:?} tcp={:?} tls={:?}\n",
            probe.host, probe.path, probe.dns_ok, probe.classification, probe.resolved_ip, probe.tcp, probe.tls
        ));
    }
    md.push('\n');

    md.push_str("## Agent 日志统计\n\n");
    let logs = &result.logs;
    md.push_str(&format!("- 日志目录: {}\n", logs.log_dir));
    md.push_str(&format!("- 文件总数 / 分析数: {} / {}\n", logs.total_log_files, logs.logs_examined));
    md.push_str(&format!("- agent 启动次数: {}\n", logs.agent_starts));
    md.push_str(&format!("- 认证尝试 / 含凭据: {} / {}\n", logs.authenticate_attempts, logs.authenticate_with_credentials));
    md.push_str(&format!("- team settings 失败 / 其中超时: {} / {}\n", logs.team_settings_failures, logs.timeout_failures));
    md.push_str(&format!("- ZDR 超时 / remote config 失败: {} / {}\n", logs.zdr_timeouts, logs.remote_config_failures));
    md.push_str(&format!("- 失败类别: {:?}\n", logs.failure_categories));
    md.push_str(&format!("- 最近一次失败时间: {:?}\n", logs.last_failure_at));
    md.push_str(&format!("- agent 版本: {:?}\n", logs.agent_versions));
    md.push_str(&format!("- 在跑 agent PID: {:?}（认证正常: {:?}）\n\n", logs.running_agent_pids, logs.running_agents_authenticated));

    md.push_str("## 建议的恢复操作\n\n");
    for fix in &result.summary.recommended_fixes {
        md.push_str(&format!(
            "- `{}`：{}{}{}\n",
            fix.id,
            fix.label,
            if fix.requires_restart { "（需要重启客户端）" } else { "" },
            if fix.manual { "（手动步骤）" } else { "" }
        ));
    }
    md.push('\n');
    redact_text(&md)
}

// ---------------------------------------------------------------------------
// Tauri 命令
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn run_connection_diagnostics() -> Result<DiagnosticsResult, String> {
    tokio::task::spawn_blocking(run_full_diagnostics)
        .await
        .map_err(|e| format!("诊断任务执行失败: {e}"))?
}

#[tauri::command]
pub async fn get_last_diagnostics() -> Result<Option<DiagnosticsResult>, String> {
    tokio::task::spawn_blocking(load_last_diagnostics)
        .await
        .map_err(|e| format!("读取诊断缓存失败: {e}"))
}

/// 导出前预览：返回完整脱敏后的 Markdown 文本，不落盘。
#[tauri::command]
pub async fn preview_diagnostics_report() -> Result<String, String> {
    tokio::task::spawn_blocking(|| {
        let result = load_last_diagnostics()
            .ok_or("尚无诊断结果，请先运行诊断")?;
        // 反馈记录独立于诊断结果持久化，拼接后整体再过一遍脱敏
        Ok(redact_text(&format!(
            "{}{}",
            render_markdown_report(&result),
            render_feedback_section()
        )))
    })
    .await
    .map_err(|e| format!("预览任务执行失败: {e}"))?
}

#[tauri::command]
pub async fn export_diagnostics_report() -> Result<String, String> {
    tokio::task::spawn_blocking(|| -> Result<String, String> {
        let result = load_last_diagnostics()
            .ok_or("尚无诊断结果，请先运行诊断")?;
        let dir = diagnostics_dir()?;
        let path = dir.join(format!("diagnostics-report-{}.md", timestamp_slug()));
        let markdown = redact_text(&format!(
            "{}{}",
            render_markdown_report(&result),
            render_feedback_section()
        ));
        crate::modules::atomic_write::write_string_atomic(&path, &markdown)?;
        Ok(path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|e| format!("导出任务执行失败: {e}"))?
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyFixOutcome {
    pub settings_path: String,
    pub new_proxy: String,
    pub backup_path: String,
    /// 检测到旧版误写的嵌套 "http":{"proxy":…} 字段（未删除，仅提示）
    pub legacy_nested_proxy_present: bool,
    /// 写后回读验证：当前文件里的 http.proxy 与写入值一致
    pub write_verified: bool,
    /// 本工具记录的写入状态文件（供「恢复本次代理修改」比对）
    pub state_path: String,
}

fn default_true() -> bool {
    true
}

/// 撤销恢复操作的凭据：仅当当前值仍等于我们上次写入的值时才允许还原。
/// 记录写入前的原值与文件原本是否存在，恢复是「还原原状」而非简单删除。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyFixState {
    written_value: String,
    /// 写入前 settings.json 里原有的 http.proxy 值；原本没有该键时为 None。
    /// 旧版记录没有该字段：默认为 None 配合 settings_existed=true → 退化为
    /// 原来的"移除该键"行为。
    #[serde(default)]
    previous_value: Option<String>,
    /// 写入前 settings.json 是否已存在（本工具新建的文件恢复时应删回）。
    /// 旧版记录没有该字段：默认为 true → 只移除键、保留文件。
    #[serde(default = "default_true")]
    settings_existed: bool,
    settings_path: String,
    backup_path: String,
    written_at_ms: i64,
    app_version: String,
}

/// 给前端的撤销入口信息（不暴露多余数据，路径用于提示）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyFixStateInfo {
    pub written_value: String,
    pub previous_value: Option<String>,
    pub written_at_ms: i64,
    pub settings_path: String,
    pub backup_path: String,
}

/// 展示用脱敏：代理值可能含 `user:pass@` 认证信息或带敏感查询参数，
/// 前端只拿脱敏后的形态；恢复用的完整原值只留在后端状态文件里。
fn mask_proxy_display(value: &str) -> String {
    let mut out = value.to_string();
    // userinfo：scheme:// 之后、第一个 @ 之前
    if let Some(scheme_end) = out.find("://") {
        if let Some(at) = out.find('@') {
            if at > scheme_end + 3 {
                out = format!("{}***{}", &out[..scheme_end + 3], &out[at..]);
            }
        }
    }
    // 查询参数可能带 token/key
    if let Some(q) = out.find('?') {
        out.truncate(q);
        out.push_str("?<redacted>");
    }
    out
}

fn state_info(s: &ProxyFixState) -> ProxyFixStateInfo {
    ProxyFixStateInfo {
        written_value: mask_proxy_display(&s.written_value),
        previous_value: s.previous_value.as_deref().map(mask_proxy_display),
        written_at_ms: s.written_at_ms,
        settings_path: s.settings_path.clone(),
        backup_path: s.backup_path.clone(),
    }
}

/// 只读查询：是否存在本工具写入、尚未恢复的代理修改记录。
/// 跨页面/重启应用后撤销入口据此保留。
#[tauri::command]
pub fn get_proxy_fix_state() -> Option<ProxyFixStateInfo> {
    load_proxy_fix_state().map(|s| state_info(&s))
}

fn proxy_fix_state_path() -> Result<PathBuf, String> {
    Ok(diagnostics_dir()?.join("proxy-fix-state.json"))
}

fn load_proxy_fix_state() -> Option<ProxyFixState> {
    let path = proxy_fix_state_path().ok()?;
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

// ---- 恢复结果用户反馈（持久化，纳入报告） ----

/// 用户在执行恢复操作后对结果的人工确认。verdict ∈ confirmed/unresolved。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryFeedback {
    pub recorded_at_ms: i64,
    /// 可读时间戳（与日志/报告一致口径）。
    pub recorded_at: String,
    pub verdict: String,
}

fn recovery_feedback_path() -> Result<PathBuf, String> {
    Ok(diagnostics_dir()?.join("recovery-feedback.json"))
}

fn load_recovery_feedback() -> Vec<RecoveryFeedback> {
    recovery_feedback_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// 把反馈追加进 JSON 数组文件（保留最近 50 条）。供命令与测试共用。
fn append_recovery_feedback(path: &Path, verdict: &str) -> Result<(), String> {
    let mut list: Vec<RecoveryFeedback> = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    list.push(RecoveryFeedback {
        recorded_at_ms: now_ms(),
        recorded_at: timestamp_slug(),
        verdict: verdict.to_string(),
    });
    if list.len() > 50 {
        list.drain(..list.len() - 50);
    }
    let json = serde_json::to_string_pretty(&list)
        .map_err(|e| format!("序列化反馈记录失败: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建反馈目录失败: {e}"))?;
    }
    crate::modules::atomic_write::write_string_atomic(path, &json)
}

/// 持久化记录用户对恢复结果的人工确认；写失败如实报错，
/// 前端据此决定能否显示「已记录」。
#[tauri::command]
pub async fn record_recovery_feedback(verdict: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        match verdict.as_str() {
            "confirmed" | "unresolved" => {}
            other => return Err(format!("无效的反馈类型: {other}")),
        }
        append_recovery_feedback(&recovery_feedback_path()?, &verdict)
    })
    .await
    .map_err(|e| format!("反馈记录任务失败: {e}"))?
}

/// 报告小节：渲染持久化的恢复反馈记录（无记录时如实说明）。
fn feedback_section_md(list: &[RecoveryFeedback]) -> String {
    let mut md = String::from("## 恢复结果反馈记录\n\n");
    if list.is_empty() {
        md.push_str("- （尚无用户确认记录）\n\n");
        return md;
    }
    for fb in list {
        let label = match fb.verdict.as_str() {
            "confirmed" => "已显示且消息正常",
            "unresolved" => "仍未恢复",
            other => other,
        };
        md.push_str(&format!("- {} → {}\n", fb.recorded_at, label));
    }
    md.push('\n');
    md
}

fn render_feedback_section() -> String {
    feedback_section_md(&load_recovery_feedback())
}

/// 端口探测：不是"端口在监听"就算代理——必须完成一次真实 HTTP CONNECT
/// 握手才算可用。返回 Ok(()) 仅当代理回了 2xx；其余如实分类。
#[derive(Debug, Clone, PartialEq)]
enum ProxyProbeError {
    Refused,
    Timeout,
    NotHttpProxy,
    AuthRequired,
    Failed(String),
}

fn probe_http_connect_proxy(port: u16) -> Result<(), ProxyProbeError> {
    use std::io::{Read, Write};
    let addr: SocketAddr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return Err(ProxyProbeError::Refused),
    };
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|_| ProxyProbeError::Refused)?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));
    // CONNECT 到认证服务域名——与 Devin 实际会走路径一致
    let request = "CONNECT server.codeium.com:443 HTTP/1.1\r\nHost: server.codeium.com:443\r\n\r\n";
    stream
        .write_all(request.as_bytes())
        .map_err(|e| ProxyProbeError::Failed(format!("发送 CONNECT 失败: {e}")))?;
    let mut buf = [0u8; 512];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
            || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            return Err(ProxyProbeError::Timeout)
        }
        Err(e) => return Err(ProxyProbeError::Failed(format!("读取响应失败: {e}"))),
    };
    if n == 0 {
        return Err(ProxyProbeError::NotHttpProxy);
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());
    if !head.starts_with("HTTP/") {
        return Err(ProxyProbeError::NotHttpProxy);
    }
    match status {
        Some(code) if (200..300).contains(&code) => Ok(()),
        Some(407) => Err(ProxyProbeError::AuthRequired),
        Some(code) => Err(ProxyProbeError::Failed(format!("代理返回 HTTP {code}"))),
        None => Err(ProxyProbeError::NotHttpProxy),
    }
}

fn proxy_probe_error_message(port: u16, err: &ProxyProbeError) -> String {
    match err {
        ProxyProbeError::Refused => {
            format!("端口 {port} 没有监听（连接被拒），已中止（未修改任何文件）")
        }
        ProxyProbeError::Timeout => {
            format!("端口 {port} 接受连接但未在超时内回应 HTTP 代理握手，已中止")
        }
        ProxyProbeError::NotHttpProxy => {
            format!("端口 {port} 在监听但不是 HTTP 代理（CONNECT 握手未通过），已中止")
        }
        ProxyProbeError::AuthRequired => {
            format!("端口 {port} 是 HTTP 代理但要求认证（407），Devin 无法直接使用，已中止")
        }
        ProxyProbeError::Failed(reason) => {
            format!("端口 {port} 代理握手失败：{reason}，已中止")
        }
    }
}

/// 恢复操作：把 `http://127.0.0.1:<port>` 写入 Devin 的 User/settings.json
/// 顶层扁平键 `"http.proxy"`。门禁：与切号共用操作锁 + 在途切号阻断 +
/// 最近一次诊断存在代理相关发现（已确认或疑似）+ 端口通过真实 HTTP
/// CONNECT 握手。写前备份原文件；写入与并发修改冲突时中止；写后回读核对。
#[tauri::command]
pub async fn apply_client_proxy_fix(port: u16) -> Result<ProxyFixOutcome, String> {
    let _guard = crate::CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    tokio::task::spawn_blocking(move || apply_client_proxy_fix_inner(port))
        .await
        .map_err(|e| format!("修复任务执行失败: {e}"))?
}

fn apply_client_proxy_fix_inner(port: u16) -> Result<ProxyFixOutcome, String> {
    if port == 0 {
        return Err("端口无效".into());
    }
    let _file_guard = crate::modules::process::lock_client_operation()?;
    crate::modules::quota_monitor::global()
        .ensure_no_in_flight_switch()
        .map_err(|code| crate::modules::quota_monitor::confirm_error_message(&code))?;
    let last = load_last_diagnostics().ok_or("尚未运行诊断，无法确认代理异常")?;
    if !last.proxy.confirmed_proxy_issue && !last.proxy.ineffective_proxy_confirmed {
        return Err(
            "最近一次诊断未发现代理相关异常（已确认或疑似均否），已拒绝执行修复".into(),
        );
    }
    // 已有未撤销的修改时禁止再写：否则覆盖状态文件会丢掉上一次的还原凭据
    if load_proxy_fix_state().is_some() {
        return Err("存在尚未撤销的代理修改记录，请先「撤销本次修改」再写入新的代理设置".into());
    }
    // 端口监听 ≠ 可用代理：必须完成真实 CONNECT 握手
    probe_http_connect_proxy(port)
        .map_err(|e| proxy_probe_error_message(port, &e))?;
    let profile = client::get_default_windsurf_user_data_dir()?;
    let settings_path = devin_settings_path(&profile);
    let backup_dir = diagnostics_dir()?.join("backups");
    std::fs::create_dir_all(&backup_dir).map_err(|e| format!("创建备份目录失败: {e}"))?;
    let backup_path = backup_dir.join(format!("devin-user-settings-{}.json", timestamp_slug()));
    let state_path = proxy_fix_state_path()?;
    let outcome = apply_proxy_fix_to_settings(
        port,
        &settings_path,
        &backup_path,
        &state_path,
        &|path, expected, new_content| {
            crate::modules::atomic_write::replace_secret_string_if_matches(
                path,
                expected,
                Some(new_content),
            )
        },
    )?;
    Ok(outcome)
}

/// 核心写逻辑（与真实环境解耦以便单测）：
/// 备份原始字节 → **先落盘撤销记录**（含写入前的原值，保证修改成功后
/// 必有可恢复凭据；失败则中止不碰配置）→ JSONC 局部编辑顶层
/// `"http.proxy"`（注释/其他字段/格式逐字节保留；历史嵌套不删只提示）
/// → 条件原子写（期间被并发修改则中止并清理记录）→ 写后回读核对。
/// `write_if_unchanged(path, expected, new)` 仅当当前内容与 expected 一致
/// 时才写入；返回 Ok(false) 表示内容已变化、未写。
fn apply_proxy_fix_to_settings(
    port: u16,
    settings_path: &Path,
    backup_path: &Path,
    state_path: &Path,
    write_if_unchanged: &dyn Fn(&Path, Option<&str>, &str) -> Result<bool, String>,
) -> Result<ProxyFixOutcome, String> {
    let content = match std::fs::read_to_string(settings_path) {
        Ok(c) => Some(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("读取 settings.json 失败，已中止: {e}")),
    };
    let value: serde_json::Value = match content.as_deref() {
        None | Some("") => serde_json::json!({}),
        Some(c) if c.trim().is_empty() => serde_json::json!({}),
        Some(c) => match parse_settings_jsonc(c) {
            Some(v) => v,
            None => {
                return Err("Devin settings.json 不是合法 JSON/JSONC，已中止（未做任何修改）".into())
            }
        },
    };
    if !value.is_object() {
        return Err("Devin settings.json 顶层不是 JSON 对象，已中止（未做任何修改）".into());
    }
    // 历史误写检测（不自动删除，不猜测来源）
    let legacy_nested = value
        .get("http")
        .and_then(|h| h.get("proxy"))
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    // 备份原始字节（写失败/要还原时用它）
    if let Some(parent) = backup_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建备份目录失败: {e}"))?;
    }
    match &content {
        Some(c) => {
            std::fs::write(backup_path, c)
                .map_err(|e| format!("备份原 settings.json 失败，已中止: {e}"))?;
        }
        None => {
            std::fs::write(backup_path, "{}")
                .map_err(|e| format!("写占位备份失败，已中止: {e}"))?;
        }
    }

    let new_proxy = format!("http://127.0.0.1:{port}");
    let value_literal = serde_json::to_string(&new_proxy)
        .map_err(|e| format!("序列化代理值失败: {e}"))?;
    let base = content.as_deref().unwrap_or("{}");
    let new_content = if base.trim().is_empty() {
        format!("{{\n  \"http.proxy\": {value_literal}\n}}\n")
    } else {
        jsonc_set_top_level(base, "http.proxy", &value_literal)
            .map_err(|e| format!("局部编辑 settings.json 失败，已中止: {e}"))?
    };

    // 已存在撤销记录 → 说明有未还原的修改，拒绝再写：
    // 覆盖会丢掉上一次的原值凭据；也保证下方失败清理删的只可能是本次
    // 刚创建的记录。
    if state_path.exists() {
        return Err("已存在未撤销的代理修改记录，请先撤销后再写入（本次未做任何修改）".into());
    }

    // 先落盘撤销记录（写入前原值 + 文件原本是否存在），再动配置：
    // 修改一旦成功，可恢复凭据必然已在盘上。记录写不进去就直接中止，
    // 不留"改了却没法自动还原"的部分成功状态。
    let state = ProxyFixState {
        written_value: new_proxy.clone(),
        previous_value: value
            .get("http.proxy")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        settings_existed: content.is_some(),
        settings_path: settings_path.to_string_lossy().into_owned(),
        backup_path: backup_path.to_string_lossy().into_owned(),
        written_at_ms: now_ms(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let state_json = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("序列化代理修改状态失败: {e}"))?;
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建状态目录失败，已中止: {e}"))?;
    }
    crate::modules::atomic_write::write_string_atomic(state_path, &state_json)
        .map_err(|e| format!("撤销记录保存失败，已中止（未修改任何配置）: {e}"))?;

    // 条件写：仅当文件仍是刚才读到的内容才落盘，并发修改 → 中止并清理记录
    match write_if_unchanged(settings_path, content.as_deref(), &new_content) {
        Ok(true) => {}
        Ok(false) => {
            let _ = std::fs::remove_file(state_path);
            return Err("settings.json 在写入前被其他程序修改，已中止（未做任何修改），请重新诊断后重试".into());
        }
        Err(write_error) => {
            let _ = std::fs::remove_file(state_path);
            return Err(format!("写入 settings.json 失败（原文件未被改动）: {write_error}"));
        }
    }

    // 写后回读核对：不得在未核对前声称已生效
    let verified = match std::fs::read_to_string(settings_path)
        .ok()
        .and_then(|t| parse_settings_jsonc(&t))
        .and_then(|v| v.get("http.proxy").and_then(|p| p.as_str()).map(str::to_string))
    {
        Some(v) if v == new_proxy => true,
        _ => false,
    };
    if !verified {
        return Err(format!(
            "写入已提交但回读校验未通过（http.proxy 未呈现新值）。请检查文件状态；备份位于: {}",
            backup_path.display()
        ));
    }

    Ok(ProxyFixOutcome {
        settings_path: settings_path.to_string_lossy().into_owned(),
        new_proxy,
        backup_path: backup_path.to_string_lossy().into_owned(),
        legacy_nested_proxy_present: legacy_nested,
        write_verified: verified,
        state_path: state_path.to_string_lossy().into_owned(),
    })
}

/// 撤销恢复操作：仅当 settings.json 里 http.proxy 仍等于本工具上次写入
/// 的值时还原（删除该键），其余设置原样保留；值被用户改过时拒绝自动
/// 恢复并给出备份位置。
#[tauri::command]
pub async fn revert_client_proxy_fix() -> Result<ProxyFixOutcome, String> {
    let _guard = crate::CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    tokio::task::spawn_blocking(revert_client_proxy_fix_inner)
        .await
        .map_err(|e| format!("恢复任务执行失败: {e}"))?
}

/// 可测试的恢复核心：仅当 settings.json 里 http.proxy 仍等于
/// `expected_written_value` 时还原为写入前的原状（其余内容保留）：
/// - `previous_value` 有原值 → 写回原值；无原值 → 移除该键；
/// - `settings_existed=false`（文件由本工具创建）且移除后对象为空 →
///   删除整个文件，还原"文件本不存在"的状态。
/// 值被改动过时拒绝自动恢复并给出备份位置。
/// Ok(true)=已恢复；Ok(false)=键本就不存在，无需恢复。
fn revert_proxy_fix_to_settings(
    settings_path: &Path,
    expected_written_value: &str,
    previous_value: Option<&str>,
    settings_existed: bool,
    backup_display: &str,
    write_if_unchanged: &dyn Fn(&Path, Option<&str>, &str) -> Result<bool, String>,
) -> Result<bool, String> {
    let content = match std::fs::read_to_string(settings_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("读取 settings.json 失败，已中止: {e}")),
    };
    let value = parse_settings_jsonc(&content)
        .ok_or("settings.json 当前不是合法 JSON/JSONC，已中止")?;
    let current = value
        .get("http.proxy")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    match current.as_deref() {
        None => return Ok(false),
        Some(v) if v != expected_written_value => {
            return Err(format!(
                "http.proxy 当前值与本工具写入值不同（可能已被修改），拒绝自动恢复。\
                 写入前备份位于: {backup_display}（请核对后手动还原）"
            ));
        }
        _ => {}
    }

    // 目标：还原写入前状态。文件原本不存在且只剩本工具写入的键时，
    // 删除整个文件比留下空对象更忠实。
    let only_our_key = value
        .as_object()
        .map(|o| o.len() == 1 && o.contains_key("http.proxy"))
        .unwrap_or(false);
    if !settings_existed && only_our_key {
        // 删文件前再读一次确认内容未被并发改动
        let fresh = std::fs::read_to_string(settings_path)
            .map_err(|e| format!("删除前复核读取失败，已中止: {e}"))?;
        if fresh != content {
            return Err("settings.json 在恢复前被其他程序修改，已中止（未做任何修改）".into());
        }
        std::fs::remove_file(settings_path)
            .map_err(|e| format!("删除本工具创建的 settings.json 失败: {e}"))?;
        if settings_path.exists() {
            return Err("删除已提交但文件仍存在，请手动检查".into());
        }
        return Ok(true);
    }

    let new_content = match previous_value {
        Some(prev) => {
            let literal = serde_json::to_string(prev)
                .map_err(|e| format!("序列化原代理值失败: {e}"))?;
            jsonc_set_top_level(&content, "http.proxy", &literal)
                .map_err(|e| format!("恢复原代理值失败，已中止: {e}"))?
        }
        None => jsonc_remove_top_level(&content, "http.proxy")
            .map_err(|e| format!("移除 http.proxy 失败，已中止: {e}"))?,
    };
    match write_if_unchanged(settings_path, Some(&content), &new_content)? {
        true => {}
        false => {
            return Err("settings.json 在恢复前被其他程序修改，已中止（未做任何修改）".into());
        }
    }
    let ok = std::fs::read_to_string(settings_path)
        .ok()
        .and_then(|t| parse_settings_jsonc(&t))
        .map(|v| match previous_value {
            Some(prev) => v.get("http.proxy").and_then(|p| p.as_str()) == Some(prev),
            None => v.get("http.proxy").is_none(),
        })
        .unwrap_or(false);
    if !ok {
        return Err(format!(
            "恢复写入已提交但回读校验未通过。备份位于: {backup_display}"
        ));
    }
    Ok(true)
}

/// 从写入前备份求证原代理值：旧版撤销记录没有 previous_value 字段，
/// 不能把「原值未知」当成「原本没有代理」——备份能读就用备份说话，
/// 读不出/解析不了就拒绝自动恢复，让人工核对。
/// Ok(Some(v))=备份里确有原值；Ok(None)=备份证明原本没有该键。
fn recover_previous_from_backup(backup_path: &str) -> Result<Option<String>, String> {
    let text = std::fs::read_to_string(backup_path)
        .map_err(|e| format!("读取备份失败: {e}"))?;
    let value = parse_settings_jsonc(&text)
        .ok_or_else(|| "备份不是合法 JSON/JSONC".to_string())?;
    if !value.is_object() {
        return Err("备份顶层不是 JSON 对象".into());
    }
    Ok(value
        .get("http.proxy")
        .and_then(|v| v.as_str())
        .map(str::to_string))
}

/// 撤销主流程（可测试）：原值求证（含旧记录备份兜底）→ 核心还原 →
/// 成功后清理状态记录。
fn revert_with_state(
    state: &ProxyFixState,
    state_record_path: &Path,
    write_if_unchanged: &dyn Fn(&Path, Option<&str>, &str) -> Result<bool, String>,
) -> Result<ProxyFixOutcome, String> {
    let settings_path = PathBuf::from(&state.settings_path);
    // 原值：新记录直接带；旧记录从备份求证，求证不了就拒绝
    let previous: Option<String> = match &state.previous_value {
        Some(v) => Some(v.clone()),
        None => match recover_previous_from_backup(&state.backup_path) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!(
                    "撤销记录缺少原值且备份不可读，拒绝自动恢复（{e}）。\
                     请核对备份 {} 后手动还原",
                    state.backup_path
                ))
            }
        },
    };
    match revert_proxy_fix_to_settings(
        &settings_path,
        &state.written_value,
        previous.as_deref(),
        state.settings_existed,
        &state.backup_path,
        write_if_unchanged,
    ) {
        Ok(true) => {
            let _ = std::fs::remove_file(state_record_path);
            let restored = match &previous {
                // 返回值直接上前端展示：原值可能含 user:pass@/查询参数，脱敏显示；
                // 恢复动作本身仍用后端完整原值（上面的 previous）。
                Some(v) => format!("已恢复为 {}", mask_proxy_display(v)),
                None if state.settings_existed => "(已移除)".to_string(),
                None => "(本工具创建的 settings.json 已删除)".to_string(),
            };
            Ok(ProxyFixOutcome {
                settings_path: state.settings_path.clone(),
                new_proxy: restored,
                backup_path: state.backup_path.clone(),
                legacy_nested_proxy_present: false,
                write_verified: true,
                state_path: String::new(),
            })
        }
        Ok(false) => {
            let _ = std::fs::remove_file(state_record_path);
            Err("http.proxy 已不在配置中，无需恢复（记录已清除）".into())
        }
        Err(e) => Err(e),
    }
}

fn revert_client_proxy_fix_inner() -> Result<ProxyFixOutcome, String> {
    let _file_guard = crate::modules::process::lock_client_operation()?;
    crate::modules::quota_monitor::global()
        .ensure_no_in_flight_switch()
        .map_err(|code| crate::modules::quota_monitor::confirm_error_message(&code))?;
    let state = load_proxy_fix_state()
        .ok_or("没有本工具写入的代理修改记录，无法自动恢复")?;
    revert_with_state(&state, &proxy_fix_state_path()?, &|path, expected, new_content| {
        crate::modules::atomic_write::replace_secret_string_if_matches(
            path,
            expected,
            Some(new_content),
        )
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacClearGuidance {
    /// 保守方案：绝不写注册表，始终为 false。
    pub performed: bool,
    pub applicable: bool,
    pub steps: Vec<String>,
    pub note: String,
}

/// 恢复操作（保守降级）：不执行任何注册表写操作，只输出手动操作指引。
#[tauri::command]
pub async fn clear_stale_pac_config() -> Result<PacClearGuidance, String> {
    tokio::task::spawn_blocking(|| {
        let applicable = load_last_diagnostics()
            .map(|last| last.proxy.stale_pac_confirmed)
            .unwrap_or(false);
        PacClearGuidance {
            performed: false,
            applicable,
            steps: vec![
                "按 Win+R，运行 inetcpl.cpl 打开 Internet 属性".to_string(),
                "进入「连接」选项卡，点击「局域网(LAN)设置」".to_string(),
                "取消勾选「使用自动配置脚本」".to_string(),
                "确认静态代理设置（「为 LAN 使用代理服务器」）保持原样，不要改动".to_string(),
                "依次确定，完成。无需重启系统".to_string(),
            ],
            note: "为保护系统设置，本工具不直接修改注册表；请按上述步骤在系统设置中手动取消残留的 PAC 配置。".to_string(),
        }
    })
    .await
    .map_err(|e| format!("任务执行失败: {e}"))
}

/// 恢复操作：温和重启官方客户端（正常关闭 → 等待退出 → 按原路径启动）。
/// 不改登录态、不写任何客户端文件。前端必须在用户确认（含“已保存工作”）后调用。
/// close_windsurf 超时只报错不强杀，取消关闭时不会启动第二实例。
#[tauri::command]
pub async fn restart_devin_client() -> Result<String, String> {
    let _guard = crate::CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    tokio::task::spawn_blocking(|| -> Result<String, String> {
        let _file_guard = crate::modules::process::lock_client_operation()?;
        // 若官方客户端正在处理一次 devin:// 登录，重启会打断确认弹窗
        crate::modules::quota_monitor::global()
            .ensure_no_in_flight_switch()
            .map_err(|code| crate::modules::quota_monitor::confirm_error_message(&code))?;
        client::detect_and_save_windsurf_launch_path(false)
            .ok_or("未找到 Devin Desktop，请先安装或设置路径")?;
        client::ensure_windsurf_launch_path_configured()?;
        let profile = client::get_default_windsurf_user_data_dir()?;
        let profile_str = profile.to_string_lossy().into_owned();
        let was_running = client::profile_is_running(&profile);
        if was_running {
            client::close_windsurf(&[profile_str.clone()], 30)?;
        }
        client::start_windsurf_default_with_args_with_new_window(&[], true)?;
        Ok(if was_running {
            "客户端已正常关闭并重新启动，agent 子进程将重新认证。".to_string()
        } else {
            "客户端原本未在运行，已按原路径启动。".to_string()
        })
    })
    .await
    .map_err(|e| format!("重启任务执行失败: {e}"))?
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 脱敏 ----

    #[test]
    fn redact_windsurf_api_key() {
        let out = redact_text("key=windsurf_AbC123xYz method_id=windsurf-api-key");
        assert!(!out.contains("AbC123xYz"), "{out}");
        assert!(out.contains("windsurf_<redacted>"), "{out}");
        // 普通单词不受影响
        assert!(out.contains("method_id=windsurf-api-key"), "{out}");
    }

    #[test]
    fn redact_long_hex_and_base64() {
        let hex = "deadbeef".repeat(8); // 64 chars
        let out = redact_text(&format!("value={hex}"));
        assert!(!out.contains(&hex[..32]), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
        let b64 = "QUJDREVGRw==".repeat(4); // 48 chars
        let out = redact_text(&format!("payload {b64} done"));
        assert!(!out.contains("QUJDREVGRw=="), "{out}");
    }

    #[test]
    fn redact_query_secret_params() {
        let out = redact_text("https://127.0.0.1:20084/pac.js?secret=abcdef1234567890&token=xyz987");
        assert!(!out.contains("abcdef1234567890"), "{out}");
        assert!(!out.contains("xyz987"), "{out}");
        assert!(out.contains("secret=<redacted>"), "{out}");
        assert!(out.contains("token=<redacted>"), "{out}");
        assert!(out.contains("https://127.0.0.1:20084/pac.js"), "{out}");
    }

    #[test]
    fn redact_authorization_and_json_keys() {
        let out = redact_text("Authorization: Bearer sk-ws-01-abcdef1234567890123456789");
        assert!(!out.contains("abcdef1234567890"), "{out}");
        assert!(out.to_lowercase().contains("authorization: bearer <redacted>"), "{out}");
        let out = redact_text(r#"{"apiKey":"windsurf_secretvalue123","name":"x"}"#);
        assert!(!out.contains("secretvalue123"), "{out}");
        assert!(out.contains(r#""apiKey":"<redacted>""#), "{out}");
        assert!(out.contains(r#""name":"x""#), "{out}");
    }

    #[test]
    fn redact_email_masks_local_part() {
        let out = redact_text("contact alice.wonder@example.com for details");
        assert!(!out.contains("alice.wonder"), "{out}");
        assert!(out.contains("a***@example.com"), "{out}");
    }

    #[test]
    fn redact_auth1_and_session_tokens() {
        let out = redact_text("token devin-session-token$eyJabc.def.ghi end");
        assert!(!out.contains("eyJabc"), "{out}");
        let out = redact_text("x auth1_AAAAABBBBBCCCCC.DDDD key");
        assert!(!out.contains("AAAAABBBBB"), "{out}");
    }

    #[test]
    fn redact_keeps_benign_content() {
        let line = "2026-10-17T06:42:06.416191Z INFO chisel_agent::acp_server: ACP server ready; version=3000.10.67 host=E:\\Devin";
        let out = redact_text(line);
        assert_eq!(out, line);
    }

    // ---- 日志行解析 ----

    #[test]
    fn parse_authenticate_success_and_failure_variants() {
        let line = r#"2026-10-17T06:42:06Z INFO run_acp_server: chisel_agent::acp_server::agent_impl: ACP: authenticate #2 (agent_instance=0x1de9be94020, client=Some("windsurf"), had_credentials=true, method_id=windsurf-api-key, meta_keys=[])"#;
        let parsed = parse_authenticate_line(line).expect("auth line");
        assert!(parsed.had_credentials);
        assert_eq!(parsed.method_id.as_deref(), Some("windsurf-api-key"));

        let line = "ACP: authenticate #1 (had_credentials=false, method_id=windsurf-api-key)";
        let parsed = parse_authenticate_line(line).expect("auth line");
        assert!(!parsed.had_credentials);

        let line = "2026-10-17T06:31:23Z ERROR chisel_agent::team_settings: Team settings refresh failed: fetch timed out after 10000ms";
        assert!(parse_authenticate_line(line).is_none());
        assert!(line.contains("Team settings refresh failed"));
        assert!(line.contains("timed out"));
        assert_eq!(
            parse_log_timestamp(line).as_deref(),
            Some("2026-10-17T06:31:23Z")
        );
    }

    #[test]
    fn parse_zdr_remote_config_and_version_lines() {
        let zdr = "WARN chisel_agent::zdr: ZDR status refresh timed out on auth";
        assert!(zdr.contains("ZDR status refresh timed out"));
        let remote = "WARN windsurf_api_client::remote_config: remote config revalidation failed: operation timed out";
        assert!(remote.contains("remote config revalidation failed"));
        let version = "INFO chisel_server::acp: ACP server ready; version=3000.10.67";
        assert_eq!(parse_agent_version(version).as_deref(), Some("3000.10.67"));
        let unrelated = "DEBUG some_module: unrelated housekeeping message";
        assert!(parse_agent_version(unrelated).is_none());
        assert!(parse_authenticate_line(unrelated).is_none());
    }

    #[test]
    fn parse_log_file_pid() {
        assert_eq!(
            log_file_pid(Path::new("devin_20261017-143113_18508.log")),
            Some(18508)
        );
        assert_eq!(log_file_pid(Path::new("devin_20261017-143113_x.log")), None);
        assert_eq!(log_file_pid(Path::new("other.log")), None);
    }

    #[test]
    fn parse_log_timestamp_multibyte_safe() {
        // 多字节字符开头的日志行不得 panic
        assert_eq!(parse_log_timestamp("日本語のログ行ですが長い文字列"), None);
        assert_eq!(
            parse_log_timestamp("2026-10-17T06:31:23Z INFO ok"),
            Some("2026-10-17T06:31:23Z".to_string())
        );
    }

    // ---- DefaultConnectionSettings 解析（合成字节） ----

    // 合成字节布局与真实注册表一致：proxyServer + bypass + pacUrl
    fn build_default_connection_settings(
        flags: u32,
        proxy_server: Option<&str>,
        bypass: Option<&str>,
        pac_url: Option<&str>,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x46u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        for part in [proxy_server, bypass, pac_url] {
            let bytes = part.unwrap_or("").as_bytes().to_vec();
            data.extend_from_slice(&(bytes.len() as u32 + 1).to_le_bytes());
            data.extend_from_slice(&bytes);
            data.push(0);
        }
        data
    }

    #[test]
    fn parse_connection_settings_with_stale_pac_hides_secret() {
        // flags=0x04：PAC 生效中（PROXY_TYPE_AUTO_PROXY_URL）
        let bytes = build_default_connection_settings(
            0x04,
            None,
            Some("<local>"),
            Some("http://127.0.0.1:20084/proxy.pac?secret=topsecretvalue123456&token=abc"),
        );
        let info = parse_default_connection_settings(&bytes).expect("parse");
        assert!(info.pac_configured);
        assert!(info.pac_active);
        // PAC URL 在 bypass 之后的尾部，必须解析出 host:port
        assert_eq!(info.pac_target, Some(("127.0.0.1".to_string(), 20084)));
        assert!(info.pac_hidden_query);
        // secret 绝不进入解析结果
        let debug = format!("{info:?}");
        assert!(!debug.contains("topsecret"), "{debug}");
        assert!(!debug.contains("token=abc"), "{debug}");
        assert!(!debug.contains("proxy.pac"), "{debug}");
    }

    #[test]
    fn parse_connection_settings_manual_proxy_with_pac_residual_string() {
        // flags=0x03（手动代理开、PAC 关）+ blob 尾部残留 PAC 字符串：
        // 只算“配置了”，不算“生效中”——这是 reviewer 确认的误报场景
        let bytes = build_default_connection_settings(
            0x03,
            Some("127.0.0.1:7897"),
            Some("<local>"),
            Some("http://127.0.0.1:20084/proxy.pac?secret=residualsecretvalue"),
        );
        let info = parse_default_connection_settings(&bytes).expect("parse");
        assert!(info.pac_configured);
        assert!(!info.pac_active);
        assert_eq!(info.pac_target, Some(("127.0.0.1".to_string(), 20084)));
        // 残留场景不得产生 confirmed_issue / stale
        let registry = RegistryProxyInfo {
            pac_configured: info.pac_configured,
            pac_active: info.pac_active,
            pac_target: info.pac_target,
            pac_hidden_query: info.pac_hidden_query,
            ..Default::default()
        };
        let (item, issue, stale) = build_pac_item(&registry, Some(false));
        assert_eq!(item.status, CheckStatus::Ok, "{}", item.detail);
        assert!(!issue, "未启用的 PAC 残留不得判定为 confirmed_issue");
        assert!(!stale, "未启用的 PAC 残留不得置 stale_pac");
        let debug = format!("{item:?}");
        assert!(!debug.contains("residualsecret"), "{debug}");
    }

    #[test]
    fn pac_item_active_dead_port_is_confirmed_issue() {
        // flags=0x05（手动代理 + PAC 生效中）且 PAC 端口死：真故障
        let bytes = build_default_connection_settings(
            0x05,
            Some("127.0.0.1:7897"),
            Some("<local>"),
            Some("http://127.0.0.1:20084/proxy.pac"),
        );
        let info = parse_default_connection_settings(&bytes).expect("parse");
        assert!(info.pac_active);
        let registry = RegistryProxyInfo {
            pac_configured: info.pac_configured,
            pac_active: info.pac_active,
            pac_target: info.pac_target,
            pac_hidden_query: info.pac_hidden_query,
            ..Default::default()
        };
        let (item, issue, stale) = build_pac_item(&registry, Some(false));
        assert_eq!(item.status, CheckStatus::ConfirmedIssue, "{}", item.detail);
        assert!(issue);
        assert!(stale);
    }

    #[test]
    fn parse_connection_settings_no_pac() {
        // 静态代理 + bypass，无 PAC URL、无 PAC 标志位
        let bytes = build_default_connection_settings(0x01, Some("127.0.0.1:7897"), Some("<local>"), None);
        let info = parse_default_connection_settings(&bytes).expect("parse");
        assert!(!info.pac_configured);
        assert!(!info.pac_active);
        assert_eq!(info.pac_target, None);
    }

    #[test]
    fn parse_connection_settings_pac_active_but_url_empty() {
        // PAC 生效中（0x04）但 URL 为空串：不猜测目标
        let bytes = build_default_connection_settings(0x04, None, Some("<local>"), None);
        let info = parse_default_connection_settings(&bytes).expect("parse");
        assert!(info.pac_active);
        assert!(!info.pac_configured);
        assert_eq!(info.pac_target, None);
    }

    #[test]
    fn parse_connection_settings_truncated_pac_is_rejected() {
        let mut truncated = build_default_connection_settings(
            0x04,
            Some("127.0.0.1:7897"),
            Some("<local>"),
            Some("http://127.0.0.1:20084/proxy.pac?secret=truncatedsecretvalue"),
        );
        // 截掉 pacUrl 尾部字节：长度字段指向不存在的字节，必须判为无法解析而非半解析
        truncated.truncate(truncated.len() - 5);
        assert!(parse_default_connection_settings(&truncated).is_none());
    }

    #[test]
    fn parse_connection_settings_static_proxy_only() {
        let bytes = build_default_connection_settings(0x01, Some("127.0.0.1:7897"), None, None);
        let info = parse_default_connection_settings(&bytes).expect("parse");
        assert!(!info.pac_configured);
        assert!(!info.pac_active);
        assert_eq!(info.pac_target, None);
    }

    #[test]
    fn parse_connection_settings_rejects_garbage() {
        assert!(parse_default_connection_settings(&[]).is_none());
        assert!(parse_default_connection_settings(&[0u8; 8]).is_none());
        let mut bad = build_default_connection_settings(0x04, None, None, None);
        bad[0] = 0xFF; // 未知版本
        assert!(parse_default_connection_settings(&bad).is_none());
        let mut truncated = build_default_connection_settings(0x04, Some("127.0.0.1:7897"), None, None);
        truncated.truncate(14); // 长度字段指向不存在的字节
        assert!(parse_default_connection_settings(&truncated).is_none());
    }

    // ---- 网络判定逻辑 ----

    #[test]
    fn classify_probe_categories() {
        assert_eq!(classify_probe(false, &[], false, &[]), "dns_failed");
        assert_eq!(classify_probe(true, &[], false, &[]), "tcp_failed");
        assert_eq!(classify_probe(true, &[100], true, &[]), "tls_failed");
        assert_eq!(classify_probe(true, &[100, 5200, 200], true, &[150]), "high_latency");
        assert_eq!(classify_probe(true, &[300, 900, 4400], true, &[400, 1000, 4600]), "unstable");
        assert_eq!(classify_probe(true, &[100, 140, 120], true, &[110, 150]), "ok");
        // TLS 未尝试（非 Windows）时不受 TLS 影响
        assert_eq!(classify_probe(true, &[100], false, &[]), "ok");
        // 全部成功且 max < 3000ms 才允许 ok
        assert_eq!(classify_probe(true, &[2500, 2800, 2600], true, &[2400, 2900, 2500]), "ok");
        // 单次 TLS 握手 max ≥ 5000ms（线上认证超时同款特征）→ tail_latency
        assert_eq!(classify_probe(true, &[300, 400, 350], true, &[280, 330, 12215]), "tail_latency");
        // max ≥ 3000 且 max−min ≥ 3000（波动）→ tail_latency
        assert_eq!(classify_probe(true, &[300, 400, 350], true, &[1500, 4800, 2000]), "tail_latency");
        // 3000 ≤ max < 5000 且无大幅波动：也不允许无条件 ok
        assert_eq!(classify_probe(true, &[300, 400, 350], true, &[2000, 4500, 2100]), "tail_latency");
        // TLS 快但 TCP 整体尾巴偏高 → tail_latency
        assert_eq!(classify_probe(true, &[2800, 3100, 2900], true, &[200, 250, 210]), "tail_latency");
    }

    #[test]
    fn extract_host_port_variants() {
        assert_eq!(
            extract_host_port("127.0.0.1:7897"),
            Some(("127.0.0.1".to_string(), 7897))
        );
        assert_eq!(
            extract_host_port("http://127.0.0.1:7897"),
            Some(("127.0.0.1".to_string(), 7897))
        );
        assert_eq!(
            extract_host_port("http=127.0.0.1:7897;https=127.0.0.1:7897"),
            Some(("127.0.0.1".to_string(), 7897))
        );
        assert_eq!(
            extract_host_port("http://user:pass@proxy.example.com:8080"),
            Some(("proxy.example.com".to_string(), 8080))
        );
        assert_eq!(extract_host_port(""), None);
        assert_eq!(extract_host_port("no-port-here"), None);
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("192.168.1.1"));
        assert!(!is_loopback_host("proxy.example.com"));
    }

    // ---- apply_client_proxy_fix 写逻辑（临时目录，不触真实环境） ----

    #[test]
    fn ineffective_item_is_unknown_with_uncertainty_wording() {
        let item = build_ineffective_item(&[7897]);
        assert_eq!(item.id, "proxy.ineffective");
        assert_eq!(item.status, CheckStatus::Unknown, "不得升级为 confirmed_issue");
        assert_eq!(item.title, "可能存在代理问题，待对照验证");
        assert!(item.detail.contains("不构成已确认的故障"), "{}", item.detail);
        assert!(item.detail.contains("TUN"), "{}", item.detail);
        assert!(item.detail.contains("对照验证"), "{}", item.detail);
        assert!(!item.detail.contains("必须重启"));
    }

    fn temp_case_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "devin-diag-test-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).expect("创建临时测试目录");
        dir
    }

    fn atomic_write_fn(path: &Path, content: &str) -> Result<(), String> {
        crate::modules::atomic_write::write_string_atomic(path, content)
    }

    /// 与 replace_secret_string_if_matches 同语义的测试写入口。
    fn cond_write_fn(path: &Path, expected: Option<&str>, content: &str) -> Result<bool, String> {
        let current = std::fs::read_to_string(path).ok();
        if current.as_deref() != expected {
            return Ok(false);
        }
        atomic_write_fn(path, content)?;
        Ok(true)
    }

    #[test]
    fn proxy_fix_creates_backup_and_preserves_other_fields() {
        let dir = temp_case_dir("preserve");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        // VS Code 扁平键形态
        let original = r#"{"http.proxy":"http://127.0.0.1:1","http.proxyStrictSSL":false,"editor":{"fontSize":14},"tokens":["a","b"]}"#;
        atomic_write_fn(&settings, original).unwrap();

        let outcome =
            apply_proxy_fix_to_settings(7897, &settings, &backup, &state, &cond_write_fn).unwrap();
        assert_eq!(outcome.new_proxy, "http://127.0.0.1:7897");
        assert!(outcome.write_verified);
        assert!(!outcome.legacy_nested_proxy_present);

        let new_content = std::fs::read_to_string(&settings).unwrap();
        let value: serde_json::Value = serde_json::from_str(&new_content).unwrap();
        assert_eq!(value["http.proxy"], "http://127.0.0.1:7897");
        // 其余字段内容不丢
        assert_eq!(value["http.proxyStrictSSL"], false);
        assert_eq!(value["editor"]["fontSize"], 14);
        assert_eq!(value["tokens"], serde_json::json!(["a", "b"]));
        // 局部编辑：除被替换的值外，原文逐字节保留
        assert!(new_content.contains("\"editor\":{\"fontSize\":14}"), "{new_content}");

        // 备份等于原文件内容
        let backup_content = std::fs::read_to_string(&backup).unwrap();
        assert_eq!(backup_content, original);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_fix_writes_flat_key_and_keeps_nested_miswrite() {
        let dir = temp_case_dir("keep-nested");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        // 旧版误写的嵌套形式（可能还混有其他 http.* 键）：
        // 不自动删除、不猜测来源，仅提示
        let original = r#"{"http":{"proxy":"http://127.0.0.1:1","proxySupport":"override"},"editor.fontSize":14}"#;
        atomic_write_fn(&settings, original).unwrap();

        let outcome =
            apply_proxy_fix_to_settings(7899, &settings, &backup, &state, &cond_write_fn).unwrap();
        assert!(outcome.legacy_nested_proxy_present);

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(value["http.proxy"], "http://127.0.0.1:7899");
        // 嵌套字段原样保留（含壳内其他键）
        assert_eq!(value["http"]["proxy"], "http://127.0.0.1:1");
        assert_eq!(value["http"]["proxySupport"], "override");
        assert_eq!(value["editor.fontSize"], 14);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_fix_preserves_comments_and_other_keys() {
        let dir = temp_case_dir("jsonc");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        let original = "{\n  // 用户代理设置\n  \"http.proxy\": \"http://127.0.0.1:1\",\n  /* 块注释 */\n  \"editor.fontSize\": 14, // 行尾注释\n  \"tokens\": [\"a\", \"b\",],\n}\n";
        atomic_write_fn(&settings, original).unwrap();

        let outcome =
            apply_proxy_fix_to_settings(7800, &settings, &backup, &state, &cond_write_fn).unwrap();
        assert!(outcome.write_verified);

        // 注释 / 尾逗号 / 其他键原样保留，仅 http.proxy 值被替换
        let new_content = std::fs::read_to_string(&settings).unwrap();
        assert!(new_content.contains("// 用户代理设置"), "{new_content}");
        assert!(new_content.contains("/* 块注释 */"), "{new_content}");
        assert!(new_content.contains("// 行尾注释"), "{new_content}");
        assert!(new_content.contains("[\"a\", \"b\",]"), "{new_content}");
        let value = parse_settings_jsonc(&new_content).expect("JSONC 仍可解析");
        assert_eq!(value["http.proxy"], "http://127.0.0.1:7800");
        assert_eq!(value["editor.fontSize"], 14);
        assert_eq!(value["tokens"], serde_json::json!(["a", "b"]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_devin_proxy_settings_reads_flat_key_and_jsonc() {
        let dir = temp_case_dir("read-flat");
        let settings = dir.join("settings.json");
        let content = "{\n  // 注释\n  \"http.proxy\": \"http://127.0.0.1:7897\", // 尾逗号下一行\n  \"devin.acp.agentEnv\": {\"HTTPS_PROXY\": \"http://user:pass@127.0.0.1:7897\"},\n}\n";
        atomic_write_fn(&settings, content).unwrap();

        let parsed = read_devin_proxy_settings(&settings);
        assert!(!parsed.parse_error, "JSONC 应能解析");
        assert_eq!(parsed.http_proxy.as_deref(), Some("http://127.0.0.1:7897"));
        // agentEnv 只列键名/主机端口，不回传凭据
        assert_eq!(parsed.agent_env_keys, vec!["HTTPS_PROXY=127.0.0.1:7897".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_devin_proxy_settings_nested_fallback() {
        let dir = temp_case_dir("read-nested");
        let settings = dir.join("settings.json");
        // 旧版误写的嵌套形式：读取侧兼容
        atomic_write_fn(
            &settings,
            r#"{"http":{"proxy":"http://127.0.0.1:9"}}"#,
        )
        .unwrap();

        let parsed = read_devin_proxy_settings(&settings);
        assert!(!parsed.parse_error);
        assert_eq!(parsed.http_proxy.as_deref(), Some("http://127.0.0.1:9"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsonc_preprocess_protects_strings() {
        let cleaned = strip_jsonc(
            r#"{"url": "http://example.com/a//b", "s": "/*not comment*/", "list": [1,], /* real */ "x": 1}"#,
        );
        let value: serde_json::Value = serde_json::from_str(&cleaned).expect("预处理结果应可解析");
        assert_eq!(value["url"], "http://example.com/a//b");
        assert_eq!(value["s"], "/*not comment*/");
        assert_eq!(value["list"], serde_json::json!([1]));
        assert_eq!(value["x"], 1);
    }

    #[test]
    fn proxy_fix_creates_settings_file_when_missing() {
        let dir = temp_case_dir("create");
        let settings = dir.join("User").join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");

        let outcome =
            apply_proxy_fix_to_settings(7890, &settings, &backup, &state, &cond_write_fn).unwrap();
        assert_eq!(outcome.new_proxy, "http://127.0.0.1:7890");
        assert!(outcome.write_verified);

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(value["http.proxy"], "http://127.0.0.1:7890");
        assert_eq!(value.as_object().unwrap().len(), 1, "只应新增 http.proxy");
        // 占位备份
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "{}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_fix_write_failure_leaves_original_untouched() {
        let dir = temp_case_dir("rollback");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        let original = r#"{"http.proxy":"http://127.0.0.1:1","editor.fontSize":14}"#;
        atomic_write_fn(&settings, original).unwrap();

        // 条件写返回 Err：原子写全有或全无，原文件未被改动
        let writer = |_path: &Path, _expected: Option<&str>, _c: &str| -> Result<bool, String> {
            Err("模拟写入失败".into())
        };

        let err = apply_proxy_fix_to_settings(7897, &settings, &backup, &state, &writer)
            .expect_err("写入失败必须返回 Err");
        assert!(err.contains("写入 settings.json 失败"), "{err}");
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), original);
        assert!(backup.is_file(), "备份仍应已创建");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_fix_aborts_when_file_changed_concurrently() {
        let dir = temp_case_dir("concurrent");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        let original = r#"{"http.proxy":"http://127.0.0.1:1"}"#;
        atomic_write_fn(&settings, original).unwrap();

        // 条件写检测到内容变化 → Ok(false) → 必须中止且不得声称已写入
        let writer = |_path: &Path, _expected: Option<&str>, _c: &str| -> Result<bool, String> {
            Ok(false)
        };

        let err = apply_proxy_fix_to_settings(7897, &settings, &backup, &state, &writer)
            .expect_err("并发修改必须中止");
        assert!(err.contains("被其他程序修改"), "{err}");
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), original);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_fix_aborts_when_post_write_verify_fails() {
        let dir = temp_case_dir("verify-fail");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        atomic_write_fn(&settings, r#"{"a":1}"#).unwrap();

        // 写入口声称成功但实际写入了别的内容 → 回读校验必须抓出来
        let writer = |path: &Path, _e: Option<&str>, _c: &str| -> Result<bool, String> {
            atomic_write_fn(path, r#"{"http.proxy":"http://127.0.0.1:9999"}"#)?;
            Ok(true)
        };

        let err = apply_proxy_fix_to_settings(7897, &settings, &backup, &state, &writer)
            .expect_err("回读不一致必须报错");
        assert!(err.contains("回读校验未通过"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_fix_aborts_on_invalid_json_without_touching_files() {
        let dir = temp_case_dir("invalid-json");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        atomic_write_fn(&settings, "{not valid json").unwrap();

        let err = apply_proxy_fix_to_settings(7897, &settings, &backup, &state, &cond_write_fn)
            .expect_err("非法 JSON 必须中止");
        assert!(err.contains("不是合法 JSON"), "{err}");
        assert!(!backup.exists(), "中止时不得创建备份");
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{not valid json");

        // 未闭合的块注释：预处理后仍非法，也必须中止
        atomic_write_fn(&settings, "{\"a\": 1, /* 未闭合").unwrap();
        let err = apply_proxy_fix_to_settings(7897, &settings, &backup, &state, &cond_write_fn)
            .expect_err("非法 JSONC 必须中止");
        assert!(err.contains("不是合法 JSON"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- JSONC 局部编辑 ----

    #[test]
    fn jsonc_set_replaces_existing_value_only() {
        let text = r#"{"http.proxy": "old", "a": 1, "url": "http://x//y"}"#;
        let out = jsonc_set_top_level(text, "http.proxy", "\"new\"").unwrap();
        assert_eq!(out, r#"{"http.proxy": "new", "a": 1, "url": "http://x//y"}"#);
    }

    #[test]
    fn jsonc_set_inserts_before_first_member_with_indent() {
        let text = "{\n    \"editor.fontSize\": 14,\n    \"a\": 1\n}";
        let out = jsonc_set_top_level(text, "http.proxy", "\"v\"").unwrap();
        assert_eq!(
            out,
            "{\n    \"http.proxy\": \"v\",\n    \"editor.fontSize\": 14,\n    \"a\": 1\n}"
        );
    }

    #[test]
    fn jsonc_set_into_empty_and_compact_objects() {
        assert_eq!(
            jsonc_set_top_level("{}", "http.proxy", "\"v\"").unwrap(),
            "{ \"http.proxy\": \"v\" }"
        );
        let out = jsonc_set_top_level("{\"a\":1}", "http.proxy", "\"v\"").unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["http.proxy"], "v");
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn jsonc_remove_members_at_edges() {
        // 首成员
        let out = jsonc_remove_top_level("{\"http.proxy\":\"v\",\"a\":1}", "http.proxy").unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&out).unwrap()["a"], 1);
        assert!(!out.contains("http.proxy"));
        // 末成员（带走前逗号）
        let out = jsonc_remove_top_level("{\"a\":1,\"http.proxy\":\"v\"}", "http.proxy").unwrap();
        assert_eq!(out, "{\"a\":1}");
        // 中间成员
        let out = jsonc_remove_top_level("{\"a\":1,\"http.proxy\":\"v\",\"b\":2}", "http.proxy").unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], 2);
        // 唯一成员
        let out = jsonc_remove_top_level("{\"http.proxy\":\"v\"}", "http.proxy").unwrap();
        assert!(!out.contains("http.proxy"));
        // 不存在的键 → 原样返回
        let out = jsonc_remove_top_level("{\"a\":1}", "http.proxy").unwrap();
        assert_eq!(out, "{\"a\":1}");
    }

    #[test]
    fn jsonc_members_skip_comments_and_strings() {
        // 注释里的 "http.proxy" 和字符串里的引号不得误判为成员
        let text = "{\n  // \"http.proxy\": \"fake\"\n  \"a\": \"{\\\"http.proxy\\\":1}\",\n  \"http.proxy\": \"v\"\n}";
        let members = jsonc_top_level_members(text).unwrap();
        let keys: Vec<&str> = members.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, vec!["a", "http.proxy"]);
    }

    // ---- HTTP CONNECT 代理握手 ----

    fn fake_proxy_once(response: &'static str) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        port
    }

    #[test]
    fn proxy_probe_accepts_2xx_connect_response() {
        let port = fake_proxy_once("HTTP/1.1 200 Connection established\r\n\r\n");
        assert!(probe_http_connect_proxy(port).is_ok());
    }

    #[test]
    fn proxy_probe_flags_auth_required_on_407() {
        let port = fake_proxy_once("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        assert_eq!(probe_http_connect_proxy(port), Err(ProxyProbeError::AuthRequired));
    }

    #[test]
    fn proxy_probe_rejects_non_proxy_port() {
        let port = fake_proxy_once("not-an-http-response");
        assert_eq!(probe_http_connect_proxy(port), Err(ProxyProbeError::NotHttpProxy));
    }

    #[test]
    fn proxy_probe_refused_when_nothing_listens() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(probe_http_connect_proxy(port), Err(ProxyProbeError::Refused));
    }

    #[test]
    fn proxy_probe_silent_port_is_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((_s, _)) = listener.accept() {
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        });
        assert_eq!(probe_http_connect_proxy(port), Err(ProxyProbeError::Timeout));
    }

    // ---- 恢复本次代理修改 ----

    #[test]
    fn revert_restores_when_value_matches() {
        let dir = temp_case_dir("revert-ok");
        let settings = dir.join("settings.json");
        atomic_write_fn(&settings, "{\n  \"http.proxy\": \"http://127.0.0.1:7897\",\n  \"a\": 1\n}").unwrap();
        let reverted = revert_proxy_fix_to_settings(
            &settings, "http://127.0.0.1:7897", None, true, "B", &cond_write_fn).unwrap();
        assert!(reverted);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert!(v.get("http.proxy").is_none());
        assert_eq!(v["a"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revert_refuses_when_value_changed_by_user() {
        let dir = temp_case_dir("revert-conflict");
        let settings = dir.join("settings.json");
        atomic_write_fn(&settings, "{\"http.proxy\":\"http://127.0.0.1:9999\"}").unwrap();
        let err = revert_proxy_fix_to_settings(
            &settings, "http://127.0.0.1:7897", None, true, "B", &cond_write_fn).unwrap_err();
        assert!(err.contains("拒绝自动恢复"), "{err}");
        assert!(err.contains('B'), "{err}");
        // 文件未被改动
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{\"http.proxy\":\"http://127.0.0.1:9999\"}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revert_noop_when_key_absent() {
        let dir = temp_case_dir("revert-absent");
        let settings = dir.join("settings.json");
        atomic_write_fn(&settings, "{\"a\":1}").unwrap();
        let reverted = revert_proxy_fix_to_settings(
            &settings, "x", None, true, "B", &cond_write_fn).unwrap();
        assert!(!reverted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revert_restores_previous_proxy_value_not_deletes() {
        // 原配置 http.proxy=7890，修复写成 7897：撤销必须恢复 7890，
        // 不能变成"没有代理"。这是审查指出的核心场景。
        let dir = temp_case_dir("revert-restore");
        let settings = dir.join("settings.json");
        atomic_write_fn(&settings, "{\n  \"http.proxy\": \"http://127.0.0.1:7897\",\n  \"a\": 1\n}").unwrap();
        let reverted = revert_proxy_fix_to_settings(
            &settings, "http://127.0.0.1:7897", Some("http://127.0.0.1:7890"), true, "B", &cond_write_fn,
        ).unwrap();
        assert!(reverted);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["http.proxy"], "http://127.0.0.1:7890", "必须恢复原端口");
        assert_eq!(v["a"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revert_deletes_settings_file_when_tool_created_it() {
        // 文件原本不存在（本工具创建）：恢复后应回到"没有该文件"的状态
        let dir = temp_case_dir("revert-del-file");
        let settings = dir.join("settings.json");
        atomic_write_fn(&settings, "{\n  \"http.proxy\": \"http://127.0.0.1:7897\"\n}\n").unwrap();
        let reverted = revert_proxy_fix_to_settings(
            &settings, "http://127.0.0.1:7897", None, false, "B", &cond_write_fn,
        ).unwrap();
        assert!(reverted);
        assert!(!settings.exists(), "本工具创建的文件应被删除还原");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revert_removes_key_keeps_file_when_user_added_keys() {
        // 文件原本不存在但用户后来加了其他设置：只移除我们的键，保留文件
        let dir = temp_case_dir("revert-keep-file");
        let settings = dir.join("settings.json");
        atomic_write_fn(&settings, "{\n  \"http.proxy\": \"http://127.0.0.1:7897\",\n  \"editor.fontSize\": 15\n}\n").unwrap();
        let reverted = revert_proxy_fix_to_settings(
            &settings, "http://127.0.0.1:7897", None, false, "B", &cond_write_fn,
        ).unwrap();
        assert!(reverted);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert!(v.get("http.proxy").is_none());
        assert_eq!(v["editor.fontSize"], 15, "用户后加的设置必须保留");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_persists_state_so_revert_restores_original() {
        // 端到端：apply 在改配置前落盘撤销记录 → revert 凭记录恢复原端口
        let dir = temp_case_dir("roundtrip");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        atomic_write_fn(&settings, "{\"http.proxy\":\"http://127.0.0.1:7890\",\"a\":1}").unwrap();

        let outcome = apply_proxy_fix_to_settings(7897, &settings, &backup, &state, &cond_write_fn).unwrap();
        assert_eq!(outcome.new_proxy, "http://127.0.0.1:7897");
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(saved["writtenValue"], "http://127.0.0.1:7897");
        assert_eq!(saved["previousValue"], "http://127.0.0.1:7890");
        assert_eq!(saved["settingsExisted"], true);

        // 模拟用户又加了别的设置后执行撤销：原端口恢复、新设置保留
        atomic_write_fn(&settings, "{\"http.proxy\":\"http://127.0.0.1:7897\",\"a\":1,\"new.key\":true}").unwrap();
        let reverted = revert_proxy_fix_to_settings(
            &settings,
            saved["writtenValue"].as_str().unwrap(),
            saved["previousValue"].as_str(),
            saved["settingsExisted"].as_bool().unwrap(),
            "B",
            &cond_write_fn,
        ).unwrap();
        assert!(reverted);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["http.proxy"], "http://127.0.0.1:7890");
        assert_eq!(v["new.key"], true, "撤销期间用户新增的设置必须保留");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_aborts_when_state_record_unwritable() {
        // 撤销记录写不进去 → 直接中止，不制造"改了没法还原"的部分成功
        let dir = temp_case_dir("state-fail");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let blocker = dir.join("blocker");
        atomic_write_fn(&settings, "{\"a\":1}").unwrap();
        atomic_write_fn(&blocker, "file").unwrap();
        let state = blocker.join("child").join("state.json");
        let err = apply_proxy_fix_to_settings(7897, &settings, &backup, &state, &cond_write_fn)
            .expect_err("状态记录失败必须中止");
        assert!(err.contains("记录") || err.contains("中止"), "{err}");
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{\"a\":1}", "配置不得被改动");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_refuses_when_unreverted_record_exists() {
        // 已有未撤销记录时禁止再写：否则覆盖会丢掉上一次的还原凭据；
        // 失败清理也只允许删本次创建的记录（前置拒绝保证这一点）。
        let dir = temp_case_dir("reapply-blocked");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        atomic_write_fn(&settings, "{\"http.proxy\":\"http://127.0.0.1:7897\",\"a\":1}").unwrap();
        // 上一次修改留下的记录（写 7897，原值 7890）
        atomic_write_fn(&state, "{\"writtenValue\":\"http://127.0.0.1:7897\",\"previousValue\":\"http://127.0.0.1:7890\",\"settingsExisted\":true}").unwrap();

        let err = apply_proxy_fix_to_settings(7898, &settings, &backup, &state, &cond_write_fn)
            .expect_err("存在未撤销记录必须拒绝");
        assert!(err.contains("先撤销") || err.contains("未撤销"), "{err}");
        // 配置与旧记录都原样保留
        assert_eq!(std::fs::read_to_string(&settings).unwrap(),
            "{\"http.proxy\":\"http://127.0.0.1:7897\",\"a\":1}");
        assert!(std::fs::read_to_string(&state).unwrap().contains("7890"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_record_recovers_previous_value_from_backup() {
        // 旧版撤销记录没有 previousValue 字段：必须从当时备份求证原值
        let dir = temp_case_dir("legacy-restore");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state_path = dir.join("proxy-fix-state.json");
        atomic_write_fn(&settings, "{\"http.proxy\":\"http://127.0.0.1:7897\",\"a\":1}").unwrap();
        // 备份证明写入前是 7890
        atomic_write_fn(&backup, "{\"http.proxy\":\"http://127.0.0.1:7890\",\"a\":1}").unwrap();
        let legacy: ProxyFixState = serde_json::from_str(&format!(
            "{{\"writtenValue\":\"http://127.0.0.1:7897\",\"settingsPath\":\"{}\",\"backupPath\":\"{}\",\"writtenAtMs\":1,\"appVersion\":\"0.0.0\"}}",
            settings.to_string_lossy().replace('\\', "\\\\"),
            backup.to_string_lossy().replace('\\', "\\\\")
        )).unwrap();
        assert!(legacy.previous_value.is_none() && legacy.settings_existed);

        let outcome = revert_with_state(&legacy, &state_path, &cond_write_fn).unwrap();
        assert!(outcome.new_proxy.contains("7890"), "{}", outcome.new_proxy);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["http.proxy"], "http://127.0.0.1:7890", "必须从备份恢复原值");
        assert!(!state_path.exists(), "恢复成功后记录应清除");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_record_unreadable_backup_refuses() {
        // 旧记录无原值 + 备份不可读 → 拒绝自动恢复，不做"当作没有"的猜测
        let dir = temp_case_dir("legacy-nobackup");
        let settings = dir.join("settings.json");
        let state_path = dir.join("proxy-fix-state.json");
        atomic_write_fn(&settings, "{\"http.proxy\":\"http://127.0.0.1:7897\"}").unwrap();
        let legacy: ProxyFixState = serde_json::from_str(&format!(
            "{{\"writtenValue\":\"http://127.0.0.1:7897\",\"settingsPath\":\"{}\",\"backupPath\":\"{}\",\"writtenAtMs\":1,\"appVersion\":\"0.0.0\"}}",
            settings.to_string_lossy().replace('\\', "\\\\"),
            dir.join("missing-backup.json").to_string_lossy().replace('\\', "\\\\")
        )).unwrap();

        let err = revert_with_state(&legacy, &state_path, &cond_write_fn).unwrap_err();
        assert!(err.contains("拒绝自动恢复"), "{err}");
        assert_eq!(std::fs::read_to_string(&settings).unwrap(),
            "{\"http.proxy\":\"http://127.0.0.1:7897\"}", "拒绝时不得改动配置");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_record_empty_backup_proves_no_previous() {
        // 旧记录无原值但备份可读且确无该键 → 移除键是忠实还原
        let dir = temp_case_dir("legacy-noprev");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state_path = dir.join("proxy-fix-state.json");
        atomic_write_fn(&settings, "{\"http.proxy\":\"http://127.0.0.1:7897\",\"a\":1}").unwrap();
        atomic_write_fn(&backup, "{\"a\":1}").unwrap();
        let legacy: ProxyFixState = serde_json::from_str(&format!(
            "{{\"writtenValue\":\"http://127.0.0.1:7897\",\"settingsPath\":\"{}\",\"backupPath\":\"{}\",\"writtenAtMs\":1,\"appVersion\":\"0.0.0\"}}",
            settings.to_string_lossy().replace('\\', "\\\\"),
            backup.to_string_lossy().replace('\\', "\\\\")
        )).unwrap();

        let outcome = revert_with_state(&legacy, &state_path, &cond_write_fn).unwrap();
        assert_eq!(outcome.new_proxy, "(已移除)");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert!(v.get("http.proxy").is_none() && v["a"] == 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_info_masks_credentials_in_previous_value() {
        // 原代理值可能带 user:pass@ 或查询参数：给前端的必须脱敏
        let state = ProxyFixState {
            written_value: "http://127.0.0.1:7897".into(),
            previous_value: Some("http://user:secretpass@proxy.local:8888?key=abc".into()),
            settings_existed: true,
            settings_path: "C:\\s\\settings.json".into(),
            backup_path: "C:\\s\\backup.json".into(),
            written_at_ms: 1,
            app_version: "0.0.0".into(),
        };
        let info = state_info(&state);
        let prev = info.previous_value.unwrap();
        assert!(!prev.contains("secretpass"), "密码泄漏: {prev}");
        assert!(!prev.contains("key=abc"), "查询参数泄漏: {prev}");
        assert!(prev.contains("***"), "{prev}");
        // 恢复用的完整值仍留在 state，不受展示脱敏影响
        assert!(state.previous_value.unwrap().contains("secretpass"));
    }

    #[test]
    fn revert_outcome_masks_credentials_but_restores_full_value() {
        // 原代理值带 user:pass@：配置必须恢复完整原值，
        // 但返回给前端的 new_proxy 不得含密码。
        let dir = temp_case_dir("revert-masked");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state_path = dir.join("proxy-fix-state.json");
        let secret = "http://alice:s3cret-pass@proxy.local:8888";
        atomic_write_fn(&settings, "{\"http.proxy\":\"http://127.0.0.1:7897\",\"a\":1}").unwrap();
        atomic_write_fn(&backup, &format!("{{\"http.proxy\":\"{secret}\",\"a\":1}}")).unwrap();
        let legacy: ProxyFixState = serde_json::from_str(&format!(
            "{{\"writtenValue\":\"http://127.0.0.1:7897\",\"settingsPath\":\"{}\",\"backupPath\":\"{}\",\"writtenAtMs\":1,\"appVersion\":\"0.0.0\"}}",
            settings.to_string_lossy().replace('\\', "\\\\"),
            backup.to_string_lossy().replace('\\', "\\\\")
        )).unwrap();

        let outcome = revert_with_state(&legacy, &state_path, &cond_write_fn).unwrap();
        // 序列化返回体不得含密码；展示值带脱敏标记
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(!json.contains("s3cret-pass"), "返回体泄漏密码: {json}");
        assert!(outcome.new_proxy.contains("***"), "{}", outcome.new_proxy);
        // 配置文件里恢复的是完整原值
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["http.proxy"], secret, "配置必须恢复完整原值");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_cleans_state_record_when_settings_write_fails() {
        // 配置写入失败 → 撤销记录同步清理，不留假记录
        let dir = temp_case_dir("state-clean");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        atomic_write_fn(&settings, "{\"a\":1}").unwrap();
        let err = apply_proxy_fix_to_settings(
            7897, &settings, &backup, &state,
            &|_p, _e, _c| -> Result<bool, String> { Err("disk full".into()) },
        ).expect_err("写入失败");
        assert!(err.contains("写入"), "{err}");
        assert!(!state.exists(), "写入失败不得留下撤销记录");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn feedback_append_and_report_section() {
        let dir = temp_case_dir("feedback");
        let path = dir.join("recovery-feedback.json");
        append_recovery_feedback(&path, "confirmed").unwrap();
        append_recovery_feedback(&path, "unresolved").unwrap();
        let list: Vec<RecoveryFeedback> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(list.len(), 2);
        let md = feedback_section_md(&list);
        assert!(md.contains("已显示且消息正常") && md.contains("仍未恢复"), "{md}");
        assert!(feedback_section_md(&[]).contains("尚无"), "无记录须如实说明");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- 失败分类 ----

    #[test]
    fn classify_failure_line_categories() {
        assert_eq!(classify_failure_line("Team settings refresh failed: request timed out"), "network_timeout");
        assert_eq!(classify_failure_line("request failed 401"), "auth_failed");
        assert_eq!(classify_failure_line("status 403 Forbidden"), "auth_failed");
        assert_eq!(classify_failure_line("open file: EACCES permission denied"), "permission");
        assert_eq!(classify_failure_line("remote config revalidation failed"), "config");
        assert_eq!(classify_failure_line("something weird happened"), "unknown");
    }

    #[test]
    fn proxy_fix_aborts_when_backup_path_unwritable() {
        let dir = temp_case_dir("backup-fail");
        let settings = dir.join("settings.json");
        let blocker = dir.join("blocker");
        let original = r#"{"a":1}"#;
        atomic_write_fn(&settings, original).unwrap();
        atomic_write_fn(&blocker, "file").unwrap();
        // 备份路径的父目录落在一个已存在的文件上 → 建目录/写备份必失败
        let backup = blocker.join("child").join("backup.json");
        let state = dir.join("proxy-fix-state.json");
        let err = apply_proxy_fix_to_settings(7897, &settings, &backup, &state, &cond_write_fn).unwrap_err();
        assert!(err.contains("备份") || err.contains("中止"), "{err}");
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), original, "备份失败不得改动原文件");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn minimal_diagnostics_result() -> DiagnosticsResult {
        DiagnosticsResult {
            generated_at_ms: 1_760_000_000_000,
            app_version: "0.0.0-test".into(),
            items: vec![DiagnosticItem::new(
                "t.secret",
                "test",
                "含敏感证据的检查项",
                CheckStatus::Unknown,
                "detail".into(),
            )
            .with_evidence([
                "Authorization: Bearer abcdef1234567890abcdef".to_string(),
                "email=user@example.com".to_string(),
            ])],
            client: ClientDiagnostics {
                exe_path: Some("C:\\Devin\\Devin.exe".into()),
                exe_exists: true,
                product_version: Some("1.0.0".into()),
                product_commit: None,
                file_version: None,
                data_dir: Some("C:\\Users\\tester\\AppData\\Roaming\\Devin".into()),
                data_dir_exists: true,
                user_settings_exists: true,
                cli_log_dir_exists: true,
                ide_processes_running: 1,
                agent_processes_running: 0,
                acp_reload_available: true,
                acp_reconnect_available: false,
            },
            proxy: ProxySection {
                system_proxy_enabled: false,
                system_proxy_server: None,
                system_proxy_listening: None,
                pac_configured: false,
                pac_active: false,
                pac_target: None,
                pac_listening: None,
                env_proxies: vec![],
                devin_settings_proxy: Some("http://127.0.0.1:7897?secret=QUERYSECRET123".into()),
                devin_agent_env_keys: vec![],
                confirmed_proxy_issue: false,
                stale_pac_confirmed: false,
                ineffective_proxy_confirmed: false,
                listening_local_ports: vec![],
            },
            network: vec![],
            logs: LogDiagnostics {
                log_dir: "C:\\logs".into(),
                total_log_files: 0,
                logs_examined: 0,
                agent_starts: 0,
                authenticate_attempts: 0,
                authenticate_with_credentials: 0,
                team_settings_failures: 0,
                timeout_failures: 0,
                zdr_timeouts: 0,
                remote_config_failures: 0,
                last_failure_at: None,
                agent_versions: vec![],
                running_agent_pids: vec![],
                running_agents_authenticated: None,
                newest_log_has_auth_failure: false,
                failure_categories: vec![],
            },
            summary: SummarySection {
                category: "测试".into(),
                confidence: "低".into(),
                overview: "token=SECRETTOKEN000000000000000".into(),
                recommended_fixes: vec![],
            },
        }
    }

    #[test]
    fn report_output_is_redacted_end_to_end() {
        let md = render_markdown_report(&minimal_diagnostics_result());
        assert!(!md.contains("abcdef1234567890abcdef"), "Bearer 泄漏:\n{md}");
        assert!(!md.contains("user@example.com"), "邮箱泄漏:\n{md}");
        assert!(!md.contains("QUERYSECRET123"), "查询参数泄漏:\n{md}");
        assert!(!md.contains("SECRETTOKEN000000000000000"), "概述 token 泄漏:\n{md}");
        assert!(!md.contains("tester"), "用户目录泄漏:\n{md}");
        assert!(md.contains("客户端环境") && md.contains("检查项明细"), "报告结构缺失:\n{md}");
    }

    // ---- Live 真实环境验证（只读，显式运行） ----
    // cargo test live_ -- --ignored --nocapture

    #[test]
    #[ignore = "真实环境 live 诊断冒烟（只读），显式运行: cargo test live_ -- --ignored --nocapture"]
    fn live_full_diagnostics_smoke() {
        let result = run_full_diagnostics().expect("run_full_diagnostics 应在真实环境成功");
        let json = serde_json::to_string_pretty(&result).expect("序列化诊断结果");
        println!("===== DiagnosticsResult JSON BEGIN =====\n{json}\n===== DiagnosticsResult JSON END =====");

        // round-trip：items 的所有文本必须已处于脱敏稳态
        for item in &result.items {
            assert_eq!(redact_text(&item.title), item.title, "title 未脱敏: {}", item.title);
            assert_eq!(redact_text(&item.detail), item.detail, "detail 未脱敏: {}", item.detail);
            for ev in &item.evidence {
                assert_eq!(redact_text(ev), *ev, "evidence 未脱敏: {ev}");
            }
        }
        // 全量 JSON 再校验一遍（覆盖 items 之外的结构性字段）
        assert_eq!(redact_text(&json), json, "JSON 中存在未脱敏字段");
    }

    #[test]
    #[ignore = "真实环境报告脱敏审计（只读），显式运行: cargo test live_ -- --ignored --nocapture"]
    fn live_report_redaction_audit() {
        let result = run_full_diagnostics().expect("run_full_diagnostics 应在真实环境成功");
        let md = render_markdown_report(&result);
        let dir = temp_case_dir("report-audit");
        let path = dir.join("diagnostics-report-test.md");
        std::fs::write(&path, &md).unwrap();
        println!("===== 审计报告路径: {} =====", path.display());
        println!("===== 报告全文 BEGIN =====\n{md}\n===== 报告全文 END =====");

        let find = |pattern: &str, haystack: &str| -> Option<String> {
            let re = regex::Regex::new(pattern).unwrap();
            re.find(haystack)
                .map(|m| format!("{pattern} -> 命中 `{}`", m.as_str()))
        };
        let leaks = [
            find(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", &md),
            find(r"windsurf_[A-Za-z0-9]{6,}", &md),
            find(r"(?i)devin-session-token", &md),
            find(r"(?i)\b(secret|api[_-]?key|access[_-]?token|refresh[_-]?token|password)\s*[=:]", &md),
            find(r"\b[0-9a-fA-F]{32,}\b", &md),
            find(r"\b[A-Za-z0-9+/_=-]{32,}\b", &md),
            find(r"(?i)users[/\\]34023\b", &md),
            find(r"\b34023\b", &md),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        assert!(leaks.is_empty(), "报告存在未脱敏内容:\n{}", leaks.join("\n"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
