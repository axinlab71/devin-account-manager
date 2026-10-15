/**
 * 跨平台通用数据解析工具函数（从 windsurf.ts / kiro.ts 中提取的重复逻辑）。
 *
 * 这些工具被 Windsurf、Kiro 等多个平台的 quota/account 解析代码共同使用。
 */

/* ------------------------------------------------------------------ */
/*  Type guards                                                       */
/* ------------------------------------------------------------------ */

/** 判断 value 是否为非空 plain object */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/* ------------------------------------------------------------------ */
/*  Deep path access                                                  */
/* ------------------------------------------------------------------ */

/**
 * 安全地沿嵌套路径取值。
 * 支持对象和数组索引（Kiro 需要数组索引支持）。
 */
export function getPathValue(root: unknown, path: string[]): unknown {
  let current = root;
  for (const key of path) {
    if (Array.isArray(current)) {
      const index = Number(key);
      if (!Number.isInteger(index) || index < 0 || index >= current.length) return null;
      current = current[index];
      continue;
    }
    if (!isRecord(current)) return null;
    current = current[key];
  }
  return current;
}

/* ------------------------------------------------------------------ */
/*  Scalar extractors                                                 */
/* ------------------------------------------------------------------ */

/** 提取有效数字（支持 string 解析） */
export function toNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    if (!value.trim()) return null;
    const n = Number(value.trim());
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

/** 提取非空字符串 */
export function toStringValue(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed || null;
}

/* ------------------------------------------------------------------ */
/*  Multi-path first-match extractors                                 */
/* ------------------------------------------------------------------ */

/** 从多条路径中取第一个有效数字 */
export function firstNumber(root: unknown, paths: string[][]): number | null {
  for (const path of paths) {
    const value = toNumber(getPathValue(root, path));
    if (value != null) return value;
  }
  return null;
}

/** 从多条路径中取第一个有效字符串 */
export function firstString(root: unknown, paths: string[][]): string | null {
  for (const path of paths) {
    const value = toStringValue(getPathValue(root, path));
    if (value) return value;
  }
  return null;
}

/** 从多条路径中取第一个可解析的 record */
export function firstRecord(values: unknown[]): Record<string, unknown> | null {
  for (const value of values) {
    if (isRecord(value)) return value;
  }
  return null;
}

/* ------------------------------------------------------------------ */
/*  Timestamp normalization                                           */
/* ------------------------------------------------------------------ */

/**
 * 将多种格式的时间值统一为秒级 Unix 时间戳。
 * - 毫秒级自动 /1000
 * - 字符串自动尝试 Number / Date.parse
 * - 嵌套 { seconds, unixSeconds, ... } 自动递归提取
 */
export function normalizeTimestamp(value: unknown): number | null {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const asNumber = Number(trimmed);
    if (Number.isFinite(asNumber)) {
      if (asNumber <= 0) return null;
      if (asNumber > 1e12) return Math.floor(asNumber / 1000);
      return Math.floor(asNumber);
    }
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed) && parsed > 0) return Math.floor(parsed / 1000);
    return null;
  }

  const n = toNumber(value);
  if (n != null) {
    if (n <= 0) return null;
    if (n > 1e12) return Math.floor(n / 1000);
    return Math.floor(n);
  }

  // Windsurf 风格的嵌套结构 { seconds, unixSeconds, ... }
  if (isRecord(value)) {
    const candidates = ['seconds', 'unixSeconds', 'unix', 'timestamp', 'value'];
    for (const key of candidates) {
      const ts = normalizeTimestamp(value[key]);
      if (ts != null) return ts;
    }
  }

  return null;
}

/** 从多条路径中取第一个有效时间戳 */
export function firstTimestamp(root: unknown, paths: string[][]): number | null {
  for (const path of paths) {
    const ts = normalizeTimestamp(getPathValue(root, path));
    if (ts != null) return ts;
  }
  return null;
}

/* ------------------------------------------------------------------ */
/*  Math helpers                                                      */
/* ------------------------------------------------------------------ */

/** 将百分比值限制在 [0, 100] 并四舍五入 */
export function clampPercent(value: number | null): number | null {
  if (value == null || !Number.isFinite(value)) return null;
  if (value < 0) return 0;
  if (value > 100) return 100;
  return Math.round(value);
}

/** 安全计算 total - used（最小为 0） */
export function safeLeft(total: number | null, used: number | null): number | null {
  if (total == null) return null;
  if (used == null) return total;
  return Math.max(0, total - used);
}

/** 对一组可能为 null 的数字求和（全部为 null 时返回 null） */
export function sumDefined(values: Array<number | null | undefined>): number | null {
  let sum = 0;
  let found = false;
  for (const v of values) {
    if (v != null) {
      sum += v;
      found = true;
    }
  }
  return found ? sum : null;
}
