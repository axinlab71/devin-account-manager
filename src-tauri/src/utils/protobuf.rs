use base64::{engine::general_purpose, Engine as _};

/// Protobuf Varint 编码
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    while value >= 0x80 {
        buf.push((value & 0x7F | 0x80) as u8);
        value >>= 7;
    }
    buf.push(value as u8);
    buf
}

/// 编码长度分隔字段 (wire_type = 2)
pub fn encode_len_delim_field(field_num: u32, data: &[u8]) -> Vec<u8> {
    let tag = (field_num << 3) | 2;
    let mut f = encode_varint(tag as u64);
    f.extend(encode_varint(data.len() as u64));
    f.extend_from_slice(data);
    f
}

/// 编码字符串字段 (wire_type = 2)
pub fn encode_string_field(field_num: u32, value: &str) -> Vec<u8> {
    encode_len_delim_field(field_num, value.as_bytes())
}

/// 编码 Varint 字段 (wire_type = 0)
pub fn encode_varint_field(field_num: u32, value: u64) -> Vec<u8> {
    let tag = (field_num << 3) | 0;
    let mut field = encode_varint(tag as u64);
    field.extend(encode_varint(value));
    field
}

/// 读取 Protobuf Varint
pub fn read_varint(data: &[u8], offset: usize) -> Result<(u64, usize), String> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut pos = offset;

    loop {
        if pos >= data.len() {
            return Err("数据不完整".to_string());
        }
        let byte = data[pos];
        result |= ((byte & 0x7F) as u64) << shift;
        pos += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    Ok((result, pos))
}

/// 跳过 Protobuf 字段
pub fn skip_field(data: &[u8], offset: usize, wire_type: u8) -> Result<usize, String> {
    match wire_type {
        0 => {
            // Varint
            let (_, new_offset) = read_varint(data, offset)?;
            Ok(new_offset)
        }
        1 => {
            // 64-bit
            Ok(offset + 8)
        }
        2 => {
            // Length-delimited
            let (length, content_offset) = read_varint(data, offset)?;
            Ok(content_offset + length as usize)
        }
        5 => {
            // 32-bit
            Ok(offset + 4)
        }
        _ => Err(format!("未知 wire_type: {}", wire_type)),
    }
}

/// 创建 OAuthTokenInfo 消息
pub fn create_oauth_info(access_token: &str, refresh_token: &str, expiry: i64) -> Vec<u8> {
    create_oauth_info_with_metadata(access_token, refresh_token, expiry, None, None, None)
}

/// 创建包含官方客户端登录态元数据的 OAuthTokenInfo 消息
pub fn create_oauth_info_with_metadata(
    access_token: &str,
    refresh_token: &str,
    expiry: i64,
    is_gcp_tos: Option<bool>,
    id_token: Option<&str>,
    _email: Option<&str>,
) -> Vec<u8> {
    let is_gcp_tos = is_gcp_tos.unwrap_or(false);

    // Field 1: access_token (string, wire_type = 2)
    let field1 = encode_string_field(1, access_token);

    // Field 2: token_type (string, fixed value "Bearer", wire_type = 2)
    let field2 = encode_string_field(2, "Bearer");

    // Field 3: refresh_token (string, wire_type = 2)
    let field3 = encode_string_field(3, refresh_token);

    // Field 4: expiry (嵌套的 Timestamp 消息, wire_type = 2)
    let timestamp_tag = (1 << 3) | 0;
    let mut timestamp_msg = encode_varint(timestamp_tag);
    timestamp_msg.extend(encode_varint(expiry as u64));
    timestamp_msg.extend(encode_varint_field(2, 0));

    let field4 = encode_len_delim_field(4, &timestamp_msg);

    let mut oauth_info = Vec::new();
    oauth_info.extend(field1);
    oauth_info.extend(field2);
    oauth_info.extend(field3);
    oauth_info.extend(field4);
    if let Some(id_token) = id_token.map(str::trim).filter(|value| !value.is_empty()) {
        oauth_info.extend(encode_string_field(5, id_token));
    }
    if is_gcp_tos {
        oauth_info.extend(encode_varint_field(6, 1));
    }
    oauth_info
}

/// 创建 unified-state Topic.data entry。
pub fn create_unified_topic_entry(sentinel_key: &str, payload: &[u8]) -> Vec<u8> {
    let row = encode_string_field(1, &general_purpose::STANDARD.encode(payload));
    let entry = [
        encode_string_field(1, sentinel_key),
        encode_len_delim_field(2, &row),
    ]
    .concat();
    encode_len_delim_field(1, &entry)
}

/// 创建 unified-state stringValue payload。
pub fn create_string_value_payload(value: &str) -> Vec<u8> {
    encode_string_field(3, value)
}

/// 创建最小可用的 UserStatus payload。
pub fn create_minimal_user_status_payload(email: &str) -> Vec<u8> {
    [encode_string_field(3, email), encode_string_field(7, email)].concat()
}

/// 从 Topic.data 中移除指定 map entry，保留同 topic 下其他 sentinel row。
pub fn remove_unified_topic_entry(data: &[u8], target_key: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let start_offset = offset;
        let (tag, new_offset) = read_varint(data, offset)?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;
        let next_offset = skip_field(data, new_offset, wire_type)?;

        let should_remove = if field_num == 1 && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset)?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return Err("Topic.data entry 数据不完整".to_string());
            }
            let entry = &data[content_offset..content_offset + length];
            unified_topic_entry_key(entry) == Some(target_key)
        } else {
            false
        };

        if !should_remove {
            result.extend_from_slice(&data[start_offset..next_offset]);
        }
        offset = next_offset;
    }

    Ok(result)
}

fn unified_topic_entry_key(data: &[u8]) -> Option<&str> {
    let mut offset = 0;
    while offset < data.len() {
        let (tag, new_offset) = read_varint(data, offset).ok()?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if field_num == 1 && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset).ok()?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return None;
            }
            return std::str::from_utf8(&data[content_offset..content_offset + length]).ok();
        }

        offset = skip_field(data, new_offset, wire_type).ok()?;
    }

    None
}

/// 从 antigravityUnifiedStateSync.oauthToken 中提取 refresh_token。
/// 结构: Topic.data[oauthTokenInfoSentinelKey].Row.value = base64(OAuthTokenInfo)，再取 Field 3。
pub fn extract_refresh_token_from_unified_oauth_token(data: &[u8]) -> Option<String> {
    let mut offset = 0;
    while offset < data.len() {
        let (tag, new_offset) = read_varint(data, offset).ok()?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if field_num == 1 && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset).ok()?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return None;
            }
            let entry = &data[content_offset..content_offset + length];
            if let Some(refresh_token) = extract_refresh_token_from_unified_entry(entry) {
                return Some(refresh_token);
            }
        }

        offset = skip_field(data, new_offset, wire_type).ok()?;
    }

    None
}

fn extract_refresh_token_from_unified_entry(data: &[u8]) -> Option<String> {
    let mut offset = 0;
    let mut sentinel_matched = false;
    let mut row_data: Option<Vec<u8>> = None;

    while offset < data.len() {
        let (tag, new_offset) = read_varint(data, offset).ok()?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset).ok()?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return None;
            }
            let value = &data[content_offset..content_offset + length];
            if field_num == 1 {
                sentinel_matched = std::str::from_utf8(value).ok()? == "oauthTokenInfoSentinelKey";
            } else if field_num == 2 {
                row_data = Some(value.to_vec());
            }
        }

        offset = skip_field(data, new_offset, wire_type).ok()?;
    }

    if !sentinel_matched {
        return None;
    }

    let row_data = row_data?;
    let oauth_info_b64 = extract_string_field(&row_data, 1)?;
    let oauth_info = general_purpose::STANDARD.decode(oauth_info_b64).ok()?;
    extract_string_field(&oauth_info, 3)
}

/// GetUserStatus/UserStatus proto 中配额相关字段的只读摘要。
/// 字段映射与前端 parseWindsurfProtoSummary 一致：
/// 顶层 f3=name, f7=email, f13=planStatus；
/// planStatus f8=promptAvail, f6=promptUsed, f4=flexAvail, f7=flexUsed,
/// f14=日剩余%, f15=周剩余%, f17/f18=重置秒, f1=planInfo；
/// planInfo f2=planName, f12=monthlyPromptCredits, f14=monthlyFlexCredits。
#[derive(Debug, Clone, Default)]
pub struct UserStatusQuotaSummary {
    pub name: Option<String>,
    pub email: Option<String>,
    pub plan_name: Option<String>,
    pub daily_remaining_percent: Option<f64>,
    pub weekly_remaining_percent: Option<f64>,
    pub daily_reset_at_secs: Option<i64>,
    pub weekly_reset_at_secs: Option<i64>,
    /// "available" 字段语义有争议（前端视为月度总额，上游注释视为剩余），
    /// 调用方按 UnverifiedMapping 处理，不得直接当剩余。
    pub prompt_credits_available: Option<f64>,
    pub prompt_credits_used: Option<f64>,
    pub prompt_credits_monthly: Option<f64>,
    pub flex_credits_available: Option<f64>,
    pub flex_credits_used: Option<f64>,
    pub flex_credits_monthly: Option<f64>,
}

fn read_len_delim<'a>(data: &'a [u8], offset: usize) -> Option<(&'a [u8], usize)> {
    let (length, start) = read_varint(data, offset).ok()?;
    let end = start.checked_add(length as usize)?;
    if end > data.len() {
        return None;
    }
    Some((&data[start..end], end))
}

fn read_field_varint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    read_varint(data, offset).ok()
}

/// 与前端 normalizeProtoCreditsValue 相同：>=1000 或 100 的整数倍按 ×100 还原。
fn normalize_credits(value: u64) -> f64 {
    let v = value as f64;
    if v >= 1000.0 || (v >= 100.0 && v % 100.0 == 0.0) {
        v / 100.0
    } else {
        v
    }
}

/// 解码 base64 UserStatus proto；任何一步失败返回 None（调用方视为无数据，
/// 永不把解析失败当成"额度为 0"）。
pub fn parse_user_status_quota(b64: &str) -> Option<UserStatusQuotaSummary> {
    let bytes = general_purpose::STANDARD.decode(b64.trim()).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let mut out = UserStatusQuotaSummary::default();
    let mut plan_status: Option<Vec<u8>> = None;
    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, next) = read_varint(&bytes, offset).ok()?;
        let field = tag >> 3;
        let wire = (tag & 7) as u8;
        if wire == 2 {
            let (value, end) = read_len_delim(&bytes, next)?;
            match field {
                3 => out.name = String::from_utf8(value.to_vec()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
                7 => out.email = String::from_utf8(value.to_vec()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
                13 => plan_status = Some(value.to_vec()),
                _ => {}
            }
            offset = end;
        } else {
            offset = skip_field(&bytes, next, wire).ok()?;
        }
    }

    let plan_status = plan_status?;
    let mut plan_info: Option<Vec<u8>> = None;
    let mut offset = 0;
    while offset < plan_status.len() {
        let (tag, next) = read_varint(&plan_status, offset).ok()?;
        let field = tag >> 3;
        let wire = (tag & 7) as u8;
        match (field, wire) {
            (8, 0) => {
                let (v, e) = read_field_varint(&plan_status, next)?;
                out.prompt_credits_available = Some(normalize_credits(v));
                offset = e;
            }
            (6, 0) => {
                let (v, e) = read_field_varint(&plan_status, next)?;
                out.prompt_credits_used = Some(normalize_credits(v));
                offset = e;
            }
            (4, 0) => {
                let (v, e) = read_field_varint(&plan_status, next)?;
                out.flex_credits_available = Some(normalize_credits(v));
                offset = e;
            }
            (7, 0) => {
                let (v, e) = read_field_varint(&plan_status, next)?;
                out.flex_credits_used = Some(normalize_credits(v));
                offset = e;
            }
            (1, 2) => {
                let (v, e) = read_len_delim(&plan_status, next)?;
                plan_info = Some(v.to_vec());
                offset = e;
            }
            (14, 0) => {
                let (v, e) = read_field_varint(&plan_status, next)?;
                out.daily_remaining_percent = Some((v as f64).clamp(0.0, 100.0));
                offset = e;
            }
            (15, 0) => {
                let (v, e) = read_field_varint(&plan_status, next)?;
                out.weekly_remaining_percent = Some((v as f64).clamp(0.0, 100.0));
                offset = e;
            }
            (17, 0) => {
                let (v, e) = read_field_varint(&plan_status, next)?;
                out.daily_reset_at_secs = Some(v as i64);
                offset = e;
            }
            (18, 0) => {
                let (v, e) = read_field_varint(&plan_status, next)?;
                out.weekly_reset_at_secs = Some(v as i64);
                offset = e;
            }
            _ => {
                offset = skip_field(&plan_status, next, wire).ok()?;
            }
        }
    }

    if let Some(info) = plan_info {
        let mut offset = 0;
        while offset < info.len() {
            let (tag, next) = read_varint(&info, offset).ok()?;
            let field = tag >> 3;
            let wire = (tag & 7) as u8;
            match (field, wire) {
                (2, 2) => {
                    let (v, e) = read_len_delim(&info, next)?;
                    out.plan_name = String::from_utf8(v.to_vec())
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    offset = e;
                }
                (12, 0) => {
                    let (v, e) = read_field_varint(&info, next)?;
                    out.prompt_credits_monthly = Some(normalize_credits(v));
                    offset = e;
                }
                (14, 0) => {
                    let (v, e) = read_field_varint(&info, next)?;
                    out.flex_credits_monthly = Some(normalize_credits(v));
                    offset = e;
                }
                _ => {
                    offset = skip_field(&info, next, wire).ok()?;
                }
            }
        }
    }

    Some(out)
}

/// 从 protobuf 消息中提取指定字段的字符串
fn extract_string_field(data: &[u8], target_field: u32) -> Option<String> {
    let mut offset = 0;
    while offset < data.len() {
        let (tag, new_offset) = read_varint(data, offset).ok()?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if field_num == target_field && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset).ok()?;
            let length = length as usize;
            if content_offset + length > data.len() {
                return None;
            }
            let value = &data[content_offset..content_offset + length];
            return String::from_utf8(value.to_vec()).ok();
        }

        offset = skip_field(data, new_offset, wire_type).ok()?;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_oauth_info_with_metadata_gmail_gcp_tos() {
        let payload = create_oauth_info_with_metadata(
            "fake_access_token",
            "fake_refresh_token",
            1700000000,
            Some(true),
            Some("fake_id_token"),
            Some("test-gcp-tos-user@gmail.com"),
        );

        let has_field_6 = payload.windows(2).any(|w| w == [0x30, 0x01]);
        assert!(
            has_field_6,
            "Protobuf must encode field 6 when is_gcp_tos is Some(true)"
        );
    }

    #[test]
    fn test_create_oauth_info_with_metadata_gmail_personal() {
        let payload = create_oauth_info_with_metadata(
            "fake_access_token",
            "fake_refresh_token",
            1700000000,
            None,
            Some("fake_id_token"),
            Some("test-personal-user@gmail.com"),
        );

        let has_field_6 = payload.windows(2).any(|w| w == [0x30, 0x01]);
        assert!(
            !has_field_6,
            "Protobuf must NOT encode field 6 when is_gcp_tos is None"
        );
    }
}
