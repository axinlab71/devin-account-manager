/** Windsurf 账号数据（后端原样返回的结构） */
export interface WindsurfAccount {
  id: string;
  github_login: string;
  github_id: number;
  github_name?: string | null;
  github_email?: string | null;
  tags?: string[] | null;

  // 注意：这里包含敏感信息。前端不应打印/上报。
  github_access_token: string;
  github_token_type?: string | null;
  github_scope?: string | null;
  copilot_token: string;

  copilot_plan?: string | null;
  copilot_chat_enabled?: boolean | null;
  copilot_expires_at?: number | null;
  copilot_refresh_in?: number | null;
  copilot_quota_snapshots?: unknown;
  copilot_quota_reset_date?: string | null;
  copilot_limited_user_quotas?: unknown;
  copilot_limited_user_reset_date?: number | null;
  windsurf_api_key?: string | null;
  windsurf_api_server_url?: string | null;
  windsurf_auth_token?: string | null;
  windsurf_user_status?: unknown;
  windsurf_plan_status?: unknown;
  windsurf_auth_status_raw?: unknown;
  quota_query_last_error?: string | null;
  quota_query_last_error_at?: number | null;

  created_at: number;
  last_used: number;

  // ---- 兼容旧 UI（从 Codex 页面复制而来） ----
  // 这些字段不会由后端直接返回，需要在前端做映射/派生。
  email?: string;
  plan_type?: string;

}

