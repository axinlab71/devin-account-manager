//! Encrypted, integrity-checked full SQLite snapshot. No plaintext backup is written to disk.
use crate::modules::{account, atomic_write, secure_account_storage};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{backup::Backup, Connection, DatabaseName};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    profile: String,
    created: i64,
    key_fingerprint: Option<String>,
    database: String,
    digest: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub available: bool,
    pub pending: bool,
    pub created_at: Option<i64>,
    pub legacy_count: usize,
}
fn folder() -> Result<PathBuf, String> {
    Ok(account::get_data_dir()?.join("client-backups"))
}
fn path() -> Result<PathBuf, String> {
    Ok(folder()?.join("last-switch.encrypted.json"))
}
fn journal() -> Result<PathBuf, String> {
    Ok(folder()?.join("switch-state.json"))
}
fn profile_id(p: &Path) -> Result<String, String> {
    p.canonicalize()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|_| "客户端目录不存在".into())
}
fn key_fingerprint(p: &Path) -> Option<String> {
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(p.join("Local State")).ok()?).ok()?;
    v.pointer("/os_crypt/encrypted_key")
        .and_then(|v| v.as_str())
        .map(|v| format!("{:x}", Sha256::digest(v.as_bytes())))
}
fn copy_database(source: &Connection, dest: &mut Connection) -> Result<(), String> {
    let backup = Backup::new(source, dest).map_err(|_| "无法准备数据库快照")?;
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(15) {
            return Err("数据库被占用或复制超时，已停止操作，恢复点仍保留".into());
        }
        match backup.step(128).map_err(|_| "数据库复制失败")? {
            rusqlite::backup::StepResult::Done => return Ok(()),
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}
fn checked(conn: &Connection) -> Result<(), String> {
    let result: String = conn
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|_| "数据库完整性检查失败")?;
    if result != "ok" {
        return Err("数据库损坏，已中止操作".into());
    }
    Ok(())
}
fn decode(snapshot: &Snapshot) -> Result<Connection, String> {
    if snapshot.version != 1 {
        return Err("备份版本不受支持".into());
    }
    let bytes = STANDARD
        .decode(&snapshot.database)
        .map_err(|_| "备份内容无效")?;
    if bytes.len() > 256 * 1024 * 1024
        || bytes.len() < 100
        || !bytes.starts_with(b"SQLite format 3\0")
        || format!("{:x}", Sha256::digest(&bytes)) != snapshot.digest
    {
        return Err("备份完整性校验失败".into());
    }
    let mut memory = Connection::open_in_memory().map_err(|_| "无法准备恢复")?;
    // OwnedData must use SQLite's allocator. SQLite owns this checked allocation after deserialize.
    let ptr = std::ptr::NonNull::new(
        unsafe { rusqlite::ffi::sqlite3_malloc64((bytes.len() + 20) as u64) }.cast::<u8>(),
    )
    .ok_or("恢复内存不足")?;
    unsafe {
        std::ptr::write_bytes(ptr.as_ptr(), 0, bytes.len() + 20);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.as_ptr(), bytes.len());
    }
    let owned = unsafe { rusqlite::serialize::OwnedData::from_raw_nonnull(ptr, bytes.len()) };
    memory
        .deserialize(DatabaseName::Main, owned, true)
        .map_err(|_| "无法读取备份数据库")?;
    checked(&memory)?;
    Ok(memory)
}
fn load(profile: &Path) -> Result<Snapshot, String> {
    if std::fs::metadata(path()?)
        .map_err(|_| "没有可恢复的切换备份")?
        .len()
        > 400 * 1024 * 1024
    {
        return Err("恢复点文件过大，已中止恢复".into());
    }
    let content = std::fs::read_to_string(path()?).map_err(|_| "没有可恢复的切换备份")?;
    let s: Snapshot = secure_account_storage::deserialize_encrypted_snapshot(&content)
        .map_err(|_| "备份解密失败，请使用原 Windows 用户和本机账号数据目录")?;
    if s.profile != profile_id(profile)? || s.key_fingerprint != key_fingerprint(profile) {
        return Err("备份不属于当前客户端目录，或客户端加密密钥已变化，已中止恢复".into());
    }
    let _ = decode(&s)?;
    Ok(s)
}
fn write(s: &Snapshot) -> Result<(), String> {
    std::fs::create_dir_all(folder()?).map_err(|_| "无法创建备份目录")?;
    let encrypted = secure_account_storage::serialize_account_file("client-backup", s)?;
    atomic_write::write_secret_string_atomic(&path()?, &encrypted)
}
fn phase(value: &str) -> Result<(), String> {
    atomic_write::write_secret_string_atomic(&journal()?, value)
}
pub fn create(profile: &Path) -> Result<PathBuf, String> {
    let db = profile.join("User/globalStorage/state.vscdb");
    let source = Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| "无法读取客户端数据库")?;
    let pages: u64 = source
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .map_err(|_| "无法读取数据库大小")?;
    let page_size: u64 = source
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .map_err(|_| "无法读取数据库页大小")?;
    if pages.saturating_mul(page_size) > 256 * 1024 * 1024 {
        return Err("客户端数据库超过 256 MB，已中止备份".into());
    }
    checked(&source)?;
    let mut memory = Connection::open_in_memory().map_err(|_| "无法准备备份")?;
    copy_database(&source, &mut memory)?;
    // A memory snapshot avoids WAL sidecar dependencies and plaintext temporary files.
    memory
        .execute_batch("PRAGMA journal_mode=DELETE;")
        .map_err(|_| "无法准备备份快照")?;
    let data = memory
        .serialize(DatabaseName::Main)
        .map_err(|_| "无法序列化数据库快照")?;
    if data.len() > 256 * 1024 * 1024 {
        return Err("数据库超过 256 MB，已中止切换，请先检查客户端数据".into());
    }
    let mut serialized = data.to_vec();
    // SQLite documents that deserialized snapshots must use rollback mode.
    // Backup has already copied all committed WAL pages into this memory image.
    // https://www.sqlite.org/c3ref/deserialize.html
    serialized[18] = 1;
    serialized[19] = 1;
    let s = Snapshot {
        version: 1,
        profile: profile_id(profile)?,
        created: chrono::Utc::now().timestamp(),
        key_fingerprint: key_fingerprint(profile),
        database: STANDARD.encode(&serialized),
        digest: format!("{:x}", Sha256::digest(&serialized)),
    };
    let _ = decode(&s)?;
    write(&s)?;
    let _ = load(profile)?;
    phase("pending")?;
    path()
}
pub fn preflight(profile: &Path) -> Result<(), String> {
    load(profile).map(|_| ())
}
pub fn restore(profile: &Path) -> Result<(), String> {
    let s = load(profile)?;
    restore_snapshot(profile, &s)?;
    phase("restored")
}
fn restore_snapshot(profile: &Path, s: &Snapshot) -> Result<(), String> {
    let source = decode(s)?;
    let mut dest = Connection::open(profile.join("User/globalStorage/state.vscdb"))
        .map_err(|_| "无法打开恢复目标")?;
    dest.busy_timeout(Duration::from_secs(5))
        .map_err(|_| "无法设置恢复超时")?;
    copy_database(&source, &mut dest)?;
    checked(&dest)
}
pub fn completed() -> Result<(), String> {
    phase("completed")
}
pub fn status() -> Result<Status, String> {
    let meta = std::fs::metadata(path()?).ok();
    let created = meta
        .as_ref()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    let pending = std::fs::read_to_string(journal()?).is_ok_and(|s| s == "pending");
    let legacy_count = std::fs::read_dir(folder()?)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|e| is_legacy(&e.file_name().to_string_lossy()))
        .count();
    Ok(Status {
        available: meta.is_some_and(|m| m.is_file()),
        pending,
        created_at: created,
        legacy_count,
    })
}
fn is_legacy(name: &str) -> bool {
    name.strip_prefix("state-")
        .and_then(|s| s.strip_suffix(".vscdb"))
        .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
}
pub fn cleanup_legacy(profile: &Path) -> Result<usize, String> {
    preflight(profile)?;
    let dir = folder()?.canonicalize().map_err(|_| "无法读取备份目录")?;
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).map_err(|_| "无法读取备份目录")? {
        let entry = entry.map_err(|_| "读取备份文件失败")?;
        if !is_legacy(&entry.file_name().to_string_lossy())
            || !entry.file_type().map(|t| t.is_file()).unwrap_or(false)
        {
            continue;
        }
        if entry
            .path()
            .canonicalize()
            .ok()
            .as_deref()
            .and_then(Path::parent)
            != Some(dir.as_path())
        {
            continue;
        }
        std::fs::remove_file(entry.path()).map_err(|_| "部分旧版备份未能清理，请检查目录权限")?;
        count += 1;
    }
    Ok(count)
}
/// Explicitly records whether restoring the prior running state is safe.
#[derive(Debug)]
pub struct Failure {
    pub message: String,
    pub safe_to_restart: bool,
}
#[cfg(test)]
pub fn guarded_operation(
    profile: &Path,
    operation: impl FnOnce() -> Result<(), String>,
) -> Result<PathBuf, String> {
    guarded_with_close(profile, operation, || Ok(())).map_err(|e| e.message)
}
pub fn guarded_with_close(
    profile: &Path,
    operation: impl FnOnce() -> Result<(), String>,
    before_restore: impl FnOnce() -> Result<(), String>,
) -> Result<PathBuf, Failure> {
    let backup = create(profile).map_err(|message| Failure {
        message,
        safe_to_restart: true,
    })?;
    match operation() {
        Ok(()) => {
            completed().map_err(|message| Failure {
                message: format!("客户端已启动，但恢复记录更新失败：{message}"),
                safe_to_restart: false,
            })?;
            Ok(backup)
        }
        Err(original) => {
            if let Err(close) = before_restore() {
                return Err(Failure{message:format!("操作失败，客户端仍在运行，未覆盖数据库：{close}。加密恢复点已保留，请手动关闭后在设置中恢复。"),safe_to_restart:false});
            }
            match restore(profile){
    Ok(())=>Err(Failure{message:format!("操作失败，已恢复切换前数据库。原因：{original}"),safe_to_restart:true}),
    Err(recovery)=>Err(Failure{message:format!("操作失败且自动恢复未完成：{recovery}。请在设置中恢复；加密备份仍保留。原错误：{original}"),safe_to_restart:false})
   }
        }
    }
}
