#[cfg(target_os = "windows")]
use serde::Serialize;

#[cfg(target_os = "windows")]
pub const WINDOWS_OPERATION_ERROR_PREFIX: &str = "WINDOWS_OPERATION_ERROR:";

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WindowsOperationErrorPayload<'a> {
    code: &'a str,
    operation: &'a str,
    summary: &'a str,
    original_reason: &'a str,
    target: Option<&'a str>,
    pids: &'a [u32],
    retryable: bool,
    can_elevate: bool,
    manual_action_available: bool,
    attempted_recoveries: &'a [&'a str],
}

#[cfg(any(target_os = "windows", test))]
pub fn is_access_denied_message(message: &str) -> bool {
    let normalized = message.trim().to_ascii_lowercase();
    normalized.contains("os error 5")
        || normalized.contains("permissiondenied")
        || normalized.contains("permission denied")
        || normalized.contains("access is denied")
        || normalized.contains("access denied")
        || message.contains("拒绝访问")
}

pub fn format_error(
    operation: &str,
    summary: &str,
    original_reason: &str,
    target: Option<&str>,
    pids: &[u32],
    retryable: bool,
    can_elevate: bool,
    manual_action_available: bool,
) -> String {
    #[cfg(target_os = "windows")]
    {
        let code = if is_access_denied_message(original_reason) {
            "access_denied"
        } else {
            "operation_failed"
        };
        let payload = WindowsOperationErrorPayload {
            code,
            operation,
            summary,
            original_reason,
            target,
            pids,
            retryable,
            can_elevate,
            manual_action_available,
            attempted_recoveries: match operation {
                "stop_process" => &["graceful_stop", "taskkill"],
                "write_file" | "replace_file" => &["atomic_write"],
                _ => &[],
            },
        };
        return serde_json::to_string(&payload)
            .map(|json| format!("{}{}", WINDOWS_OPERATION_ERROR_PREFIX, json))
            .unwrap_or_else(|_| format!("{}: {}", summary, original_reason));
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (
            operation,
            target,
            pids,
            retryable,
            can_elevate,
            manual_action_available,
        );
        format!("{}: {}", summary, original_reason)
    }
}

pub fn format_permission_io_error(
    operation: &str,
    summary: &str,
    target: &str,
    error: &std::io::Error,
) -> Option<String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (operation, summary, target, error);
        return None;
    }

    #[cfg(target_os = "windows")]
    {
        if error.kind() != std::io::ErrorKind::PermissionDenied && error.raw_os_error() != Some(5) {
            return None;
        }
        Some(format_error(
            operation,
            summary,
            &error.to_string(),
            Some(target),
            &[],
            true,
            false,
            false,
        ))
    }
}
