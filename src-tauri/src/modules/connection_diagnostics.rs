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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxySection {
    pub system_proxy_enabled: bool,
    pub system_proxy_server: Option<String>,
    pub system_proxy_listening: Option<bool>,
    pub pac_detected: bool,
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
    pac_detected: bool,
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
                info.pac_detected = parsed.pac_detected;
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
    pub pac_detected: bool,
    pub pac_target: Option<(String, u16)>,
    pub pac_hidden_query: bool,
}

/// 解析 `HKCU\...\Internet Settings\Connections\DefaultConnectionSettings`
/// 注册表字节。只提取“是否配置了 PAC + PAC 目标主机:端口”，
/// PAC URL 的 path/query/secret 绝不进入返回值。
///
/// 字节布局（版本 0x3C/0x46）：version(4) counter(4) options(4)
/// proxyServer(str+null) bypass(str+null) pacUrl(str+null) ...
/// 注意 PAC URL 在 bypass 之后；旧实现漏掉 bypass，把 bypass 误当 PAC。
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
    let pac_flag = flags & 0x02 != 0;
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
    let mut skip_string = |offset: &mut usize| -> Option<()> {
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
        pac_detected: pac_flag,
        pac_target: None,
        pac_hidden_query: false,
    };
    if !pac_text.is_empty() {
        info.pac_detected = true;
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

#[derive(Debug, Clone, Default)]
struct DevinProxySettings {
    http_proxy: Option<String>,
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
    let value: serde_json::Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(_) => {
            result.parse_error = true;
            return result;
        }
    };
    result.http_proxy = value
        .get("http")
        .and_then(|http| http.get("proxy"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
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

    // PAC 残留项
    items.push(if registry.pac_detected {
        match (&registry.pac_target, pac_listening) {
            (Some((host, port)), Some(false)) => {
                confirmed_issue = true;
                stale_pac = true;
                let item = DiagnosticItem::new(
                    "proxy.pac_stale",
                    "proxy",
                    "PAC 自动配置脚本",
                    CheckStatus::ConfirmedIssue,
                    format!("DefaultConnectionSettings 中残留 PAC 配置，指向 {host}:{port}（无监听），该软件可能已退出"),
                );
                let mut evidence = vec![format!("pac_target={host}:{port}, listening=false")];
                if registry.pac_hidden_query {
                    evidence.push("PAC URL 含查询参数（已隐藏）".to_string());
                }
                item.with_evidence(evidence)
            }
            (Some((host, port)), Some(true)) => {
                let item = DiagnosticItem::new(
                    "proxy.pac",
                    "proxy",
                    "PAC 自动配置脚本",
                    CheckStatus::Ok,
                    format!("PAC 配置指向 {host}:{port}，端口在监听"),
                );
                let mut evidence = vec![format!("pac_target={host}:{port}, listening=true")];
                if registry.pac_hidden_query {
                    evidence.push("PAC URL 含查询参数（已隐藏）".to_string());
                }
                item.with_evidence(evidence)
            }
            (Some((host, port)), None) => {
                let mut item = DiagnosticItem::new(
                    "proxy.pac",
                    "proxy",
                    "PAC 自动配置脚本",
                    CheckStatus::Unknown,
                    format!("检测到 PAC 配置指向 {host}:{port}（非本机地址，无法探测）"),
                );
                if registry.pac_hidden_query {
                    item = item.with_evidence(["PAC URL 含查询参数（已隐藏）".to_string()]);
                }
                item
            }
            (None, _) => DiagnosticItem::new(
                "proxy.pac",
                "proxy",
                "PAC 自动配置脚本",
                CheckStatus::Unknown,
                "检测到 PAC 配置但无法解析目标地址".to_string(),
            ),
        }
    } else {
        DiagnosticItem::new(
            "proxy.pac",
            "proxy",
            "PAC 自动配置脚本",
            CheckStatus::Ok,
            "DefaultConnectionSettings 中没有 PAC 配置".to_string(),
        )
    });

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
        (Some((host, port)), _) => DiagnosticItem::new(
            "proxy.devin_settings",
            "proxy",
            "Devin 代理设置",
            CheckStatus::Ok,
            format!("Devin settings.json 的 http.proxy 为 {host}:{port}"),
        )
        .with_evidence([format!("http.proxy={host}:{port}")]),
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

    // 无效代理判定：Devin 未配 http.proxy + codeium 系网络差 + 本机有可用代理端口
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
        items.push(DiagnosticItem::new(
            "proxy.ineffective",
            "proxy",
            "代理未接入 Devin",
            CheckStatus::ConfirmedIssue,
            format!(
                "Devin 未配置 http.proxy，且到 codeium 服务的网络不稳定；本机检测到在监听的代理端口 {}",
                listening_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }

    let section = ProxySection {
        system_proxy_enabled: registry.proxy_enable.unwrap_or(false),
        system_proxy_server: system_endpoint
            .as_ref()
            .map(|(host, port)| format!("{host}:{port}")),
        system_proxy_listening: system_listening,
        pac_detected: registry.pac_detected,
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
            }
            if is_team_settings_failure && line.contains("timed out") {
                timeout_failures += 1;
            }
            if line.contains("ZDR status refresh timed out") {
                zdr_timeouts += 1;
            }
            if line.contains("remote config revalidation failed") {
                remote_config_failures += 1;
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
                "PID {} 对应的最新日志中出现 team settings 认证失败；该进程认证失败后可能长驻，重启客户端可重新拉起",
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
            "诊断发现已确认的代理配置异常（死端口 / 残留 PAC / 代理未接入 Devin），这是模型列表为空的最常见原因之一。".to_string(),
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
            "日志中存在 team settings 认证失败记录；若问题仍在持续，重启客户端让 agent 重新认证通常可恢复。".to_string(),
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
            label: "清除残留的 PAC 配置（手动步骤，提供指引）".into(),
            requires_restart: false,
            affects_login: false,
            manual: true,
        });
    }
    if proxy.confirmed_proxy_issue {
        fixes.push(RecommendedFix {
            id: "apply_client_proxy_fix".into(),
            label: "把可用的本机代理端口写入 Devin 的 http.proxy".into(),
            requires_restart: false,
            affects_login: false,
            manual: false,
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
    let summary = build_summary(&proxy_section, &network, &log_diag);

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
        "- PAC: detected={} target={:?} listening={:?}\n",
        result.proxy.pac_detected, result.proxy.pac_target, result.proxy.pac_listening
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
    for probe in &result.network {
        md.push_str(&format!(
            "- {}: dns_ok={} classification={} resolved={:?} tcp={:?} tls={:?}\n",
            probe.host, probe.dns_ok, probe.classification, probe.resolved_ip, probe.tcp, probe.tls
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

#[tauri::command]
pub async fn export_diagnostics_report() -> Result<String, String> {
    tokio::task::spawn_blocking(|| -> Result<String, String> {
        let result = load_last_diagnostics()
            .ok_or("尚无诊断结果，请先运行诊断")?;
        let dir = diagnostics_dir()?;
        let path = dir.join(format!("diagnostics-report-{}.md", timestamp_slug()));
        let markdown = render_markdown_report(&result);
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
}

/// 恢复操作：把 `http://127.0.0.1:<port>` 写入 Devin 的 User/settings.json 的
/// `http.proxy` 字段。仅当最近一次诊断确认了代理异常、且端口当前确实在监听
/// 时才允许执行；写前备份原文件到本应用数据目录，写失败自动回退。
#[tauri::command]
pub async fn apply_client_proxy_fix(port: u16) -> Result<ProxyFixOutcome, String> {
    tokio::task::spawn_blocking(move || apply_client_proxy_fix_inner(port))
        .await
        .map_err(|e| format!("修复任务执行失败: {e}"))?
}

fn apply_client_proxy_fix_inner(port: u16) -> Result<ProxyFixOutcome, String> {
    if port == 0 {
        return Err("端口无效".into());
    }
    if !is_local_port_listening(port) {
        return Err(format!("端口 {port} 当前没有监听，已中止（未修改任何文件）"));
    }
    let last = load_last_diagnostics().ok_or("尚未运行诊断，无法确认代理异常")?;
    if !last.proxy.confirmed_proxy_issue {
        return Err("最近一次诊断未确认代理异常，已拒绝执行修复".into());
    }
    let profile = client::get_default_windsurf_user_data_dir()?;
    let settings_path = devin_settings_path(&profile);
    let backup_dir = diagnostics_dir()?.join("backups");
    std::fs::create_dir_all(&backup_dir).map_err(|e| format!("创建备份目录失败: {e}"))?;
    let backup_path = backup_dir.join(format!("devin-user-settings-{}.json", timestamp_slug()));
    apply_proxy_fix_to_settings(
        port,
        &settings_path,
        &backup_path,
        &|path, content| crate::modules::atomic_write::write_string_atomic(path, content),
    )
}

/// 核心写逻辑（与真实环境解耦以便单测）：备份原文件 → 仅修改 `http.proxy`
/// 字段（其余内容原样保留）→ 原子写入 → 写失败自动回退。
/// `write_file` 是写入口，测试可注入失败场景。
fn apply_proxy_fix_to_settings(
    port: u16,
    settings_path: &Path,
    backup_path: &Path,
    write_file: &dyn Fn(&Path, &str) -> Result<(), String>,
) -> Result<ProxyFixOutcome, String> {
    let settings_existed = settings_path.is_file();
    let content = std::fs::read_to_string(settings_path).unwrap_or_default();
    let mut value: serde_json::Value = if content.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&content)
            .map_err(|_| "Devin settings.json 不是合法 JSON，已中止（未做任何修改）")?
    };
    if !value.is_object() {
        return Err("Devin settings.json 顶层不是 JSON 对象，已中止（未做任何修改）".into());
    }

    // 备份原文件（写失败时据此回退）
    if let Some(parent) = backup_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建备份目录失败: {e}"))?;
    }
    if settings_existed {
        std::fs::copy(settings_path, backup_path)
            .map_err(|e| format!("备份原 settings.json 失败，已中止: {e}"))?;
    } else {
        // 文件不存在：写一个空对象占位备份，恢复时可删除 http.proxy
        write_file(backup_path, "{}")?;
    }

    let new_proxy = format!("http://127.0.0.1:{port}");
    let write_result = {
        let obj = value.as_object_mut().expect("checked object above");
        let http = obj
            .entry("http".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if !http.is_object() {
            *http = serde_json::json!({});
        }
        http.as_object_mut()
            .expect("checked object above")
            .insert("proxy".to_string(), serde_json::Value::String(new_proxy.clone()));
        serde_json::to_string_pretty(&value)
            .map_err(|e| format!("序列化 settings.json 失败: {e}"))
            .and_then(|serialized| write_file(settings_path, &serialized))
    };

    if let Err(write_error) = write_result {
        // 回退：尽力恢复原文件内容；原本不存在的文件则删除，避免留下空文件
        if settings_existed {
            let _ = write_file(settings_path, &content);
        } else {
            let _ = std::fs::remove_file(settings_path);
        }
        return Err(format!("写入 settings.json 失败，已恢复原内容: {write_error}"));
    }

    Ok(ProxyFixOutcome {
        settings_path: settings_path.to_string_lossy().into_owned(),
        new_proxy,
        backup_path: backup_path.to_string_lossy().into_owned(),
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
#[tauri::command]
pub async fn restart_devin_client() -> Result<String, String> {
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
        let bytes = build_default_connection_settings(
            0x02,
            None,
            Some("<local>"),
            Some("http://127.0.0.1:20084/proxy.pac?secret=topsecretvalue123456&token=abc"),
        );
        let info = parse_default_connection_settings(&bytes).expect("parse");
        assert!(info.pac_detected);
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
    fn parse_connection_settings_no_pac() {
        // 静态代理 + bypass，无 PAC URL、无 PAC 标志位
        let bytes = build_default_connection_settings(0x01, Some("127.0.0.1:7897"), Some("<local>"), None);
        let info = parse_default_connection_settings(&bytes).expect("parse");
        assert!(!info.pac_detected);
        assert_eq!(info.pac_target, None);
    }

    #[test]
    fn parse_connection_settings_pac_flag_set_but_url_empty() {
        // 标志位有 PAC 但 URL 为空串：不猜测目标
        let bytes = build_default_connection_settings(0x02, None, Some("<local>"), None);
        let info = parse_default_connection_settings(&bytes).expect("parse");
        assert_eq!(info.pac_target, None);
    }

    #[test]
    fn parse_connection_settings_truncated_pac_is_rejected() {
        let mut truncated = build_default_connection_settings(
            0x02,
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
        assert!(!info.pac_detected);
        assert_eq!(info.pac_target, None);
    }

    #[test]
    fn parse_connection_settings_rejects_garbage() {
        assert!(parse_default_connection_settings(&[]).is_none());
        assert!(parse_default_connection_settings(&[0u8; 8]).is_none());
        let mut bad = build_default_connection_settings(0x02, None, None, None);
        bad[0] = 0xFF; // 未知版本
        assert!(parse_default_connection_settings(&bad).is_none());
        let mut truncated = build_default_connection_settings(0x02, Some("127.0.0.1:7897"), None, None);
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

    #[test]
    fn proxy_fix_creates_backup_and_preserves_other_fields() {
        let dir = temp_case_dir("preserve");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let original = r#"{"http":{"proxy":"http://127.0.0.1:1","proxyStrictSSL":false},"editor":{"fontSize":14},"tokens":["a","b"]}"#;
        atomic_write_fn(&settings, original).unwrap();

        let outcome =
            apply_proxy_fix_to_settings(7897, &settings, &backup, &atomic_write_fn).unwrap();
        assert_eq!(outcome.new_proxy, "http://127.0.0.1:7897");

        let new_content = std::fs::read_to_string(&settings).unwrap();
        let value: serde_json::Value = serde_json::from_str(&new_content).unwrap();
        assert_eq!(value["http"]["proxy"], "http://127.0.0.1:7897");
        // 其余字段内容不丢
        assert_eq!(value["http"]["proxyStrictSSL"], false);
        assert_eq!(value["editor"]["fontSize"], 14);
        assert_eq!(value["tokens"], serde_json::json!(["a", "b"]));

        // 备份等于原文件内容
        let backup_content = std::fs::read_to_string(&backup).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&backup_content).unwrap(),
            serde_json::from_str::<serde_json::Value>(original).unwrap()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_fix_creates_settings_file_when_missing() {
        let dir = temp_case_dir("create");
        let settings = dir.join("User").join("settings.json");
        let backup = dir.join("backups").join("backup.json");

        let outcome =
            apply_proxy_fix_to_settings(7890, &settings, &backup, &atomic_write_fn).unwrap();
        assert_eq!(outcome.new_proxy, "http://127.0.0.1:7890");

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(value["http"]["proxy"], "http://127.0.0.1:7890");
        assert_eq!(value.as_object().unwrap().len(), 1, "只应新增 http.proxy");
        // 占位备份
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "{}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_fix_rolls_back_original_content_on_write_failure() {
        let dir = temp_case_dir("rollback");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        let original = r#"{"http":{"proxy":"http://127.0.0.1:1"},"editor":{"fontSize":14}}"#;
        atomic_write_fn(&settings, original).unwrap();

        // 首次写 settings 时模拟失败，回退时写入必须成功
        let attempts = std::cell::Cell::new(0u32);
        let writer = |path: &Path, content: &str| -> Result<(), String> {
            if path == settings.as_path() {
                let n = attempts.get() + 1;
                attempts.set(n);
                if n == 1 {
                    return Err("模拟首次写入失败".into());
                }
            }
            atomic_write_fn(path, content)
        };

        let err = apply_proxy_fix_to_settings(7897, &settings, &backup, &writer)
            .expect_err("写入失败必须返回 Err");
        assert!(err.contains("已恢复原内容"), "{err}");
        // 原文件内容未被破坏，备份也已创建
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), original);
        assert!(backup.is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_fix_aborts_on_invalid_json_without_touching_files() {
        let dir = temp_case_dir("invalid-json");
        let settings = dir.join("settings.json");
        let backup = dir.join("backups").join("backup.json");
        atomic_write_fn(&settings, "{not valid json").unwrap();

        let err = apply_proxy_fix_to_settings(7897, &settings, &backup, &atomic_write_fn)
            .expect_err("非法 JSON 必须中止");
        assert!(err.contains("不是合法 JSON"), "{err}");
        assert!(!backup.exists(), "中止时不得创建备份");
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{not valid json");

        let _ = std::fs::remove_dir_all(&dir);
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
