// Read-only local quota shape probe. Never print credentials, identity, or full raw snapshots.
use serde_json::Value;
fn walk(value: &Value, path: &str) {
    if let Some(map) = value.as_object() {
        for (key, value) in map {
            let next = format!("{path}.{key}");
            let lower = key.to_lowercase();
            if (lower.contains("credit") || lower.contains("quota") || lower.contains("reset"))
                && value.is_number()
            {
                println!("{next}={value}");
            } else if lower == "billingstrategy" || lower == "billing_strategy" {
                if matches!(value.as_str(), Some("quota" | "credits")) {
                    println!("{next}={value}");
                }
            }
            if value.is_object() {
                walk(value, &next);
            }
        }
    }
}
fn main() {
    let accounts = devin_switcher_lib::modules::windsurf_account::list_accounts_checked()
        .expect("local account read failed");
    println!("local_accounts={}", accounts.len());
    for (index, account) in accounts.iter().enumerate() {
        println!("account_index={index}");
        for (name, value) in [
            ("plan_status", account.windsurf_plan_status.as_ref()),
            ("user_status", account.windsurf_user_status.as_ref()),
            ("snapshots", account.copilot_quota_snapshots.as_ref()),
        ] {
            if let Some(value) = value {
                walk(value, name);
            }
        }
        let binary = account
            .windsurf_auth_status_raw
            .as_ref()
            .and_then(|v| v.get("userStatusProtoBinaryBase64"))
            .and_then(Value::as_str)
            .is_some();
        println!("has_binary_quota_snapshot={binary}");
    }
}
