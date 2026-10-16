//! Authentication destinations are trusted by exact HTTPS origin, never by imported JSON.
use serde_json::Value;
pub fn validate_base(raw: &str) -> Result<(), String> {
    let u = url::Url::parse(raw.trim())
        .map_err(|_| "认证服务器地址无效，请重新通过官方登录导入账号")?;
    let path_ok = match u.host_str() {
        Some("server.codeium.com" | "server.self-serve.windsurf.com" | "register.windsurf.com") => {
            u.path() == "/" || u.path().is_empty()
        }
        Some("windsurf.com") => u.path().trim_end_matches('/') == "/_backend",
        _ => false,
    };
    if u.scheme() != "https"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.port().is_some_and(|p| p != 443)
        || u.query().is_some()
        || u.fragment().is_some()
        || !path_ok
    {
        return Err("拒绝非官方认证服务器地址，请使用官方登录或可信的原始导出文件".into());
    }
    Ok(())
}
pub fn validate_json(value: &Value) -> Result<(), String> {
    fn walk(v: &Value, depth: usize) -> Result<(), String> {
        if depth > 32 {
            return Err("账号数据嵌套过深".into());
        }
        match v {
            Value::Object(o) => {
                for (k, v) in o {
                    if matches!(
                        k.as_str(),
                        "windsurf_api_server_url" | "apiServerUrl" | "api_server_url"
                    ) && !v.is_null()
                    {
                        let s = v.as_str().ok_or("认证服务器地址格式无效")?;
                        if !s.trim().is_empty() {
                            validate_base(s)?;
                        }
                    }
                    walk(v, depth + 1)?;
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, depth + 1)?;
                }
            }
            _ => {}
        };
        Ok(())
    }
    walk(value, 0)
}
pub fn validate_account(a: &crate::models::windsurf::WindsurfAccount) -> Result<(), String> {
    validate_json(
        &serde_json::json!({"windsurf_api_server_url":a.windsurf_api_server_url,"auth":a.windsurf_auth_status_raw}),
    )
}
