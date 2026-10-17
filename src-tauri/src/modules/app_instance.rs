//! One manager process per data directory. This never locks the IDE profile.
use std::{fs::{File, OpenOptions}, path::Path};

fn acquire_at(path: &Path) -> Result<Option<File>, String> {
    let file = OpenOptions::new().read(true).write(true).create(true)
        .truncate(false).open(path).map_err(|_| "无法创建管理器实例锁")?;
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(Some(file)),
        Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => Ok(None),
        Err(_) => Err("无法锁定管理器实例，请检查本地目录权限".into()),
    }
}

pub fn acquire() -> Result<Option<File>, String> {
    acquire_at(&super::account::get_data_dir()?.join("manager-instance.lock"))
}

pub fn show_existing() {
    #[cfg(target_os = "windows")]
    unsafe {
        use windows::{core::w, Win32::UI::WindowsAndMessaging::{
            FindWindowW, ShowWindow, SetForegroundWindow, SW_RESTORE,
        }};
        if let Ok(window) = FindWindowW(None, w!("Devin Account Manager")) {
            let _ = ShowWindow(window, SW_RESTORE);
            let _ = SetForegroundWindow(window);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_one_owner_and_lock_released_on_exit() {
        let path = std::env::temp_dir().join(format!("manager-lock-{}.lock", uuid::Uuid::new_v4()));
        let first = super::acquire_at(&path).unwrap().unwrap();
        assert!(super::acquire_at(&path).unwrap().is_none());
        drop(first);
        let next = super::acquire_at(&path).unwrap().unwrap();
        drop(next);
        std::fs::remove_file(path).unwrap();
    }
}
