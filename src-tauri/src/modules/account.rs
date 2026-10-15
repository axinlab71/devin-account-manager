use std::path::PathBuf;

// Keep the upstream storage format in a separate application directory.
pub fn get_data_dir() -> Result<PathBuf, String> {
    #[cfg(test)]
    if let Some(path) = std::env::var_os("COCKPIT_TOOLS_TEST_DATA_DIR") {
        let path = PathBuf::from(path);
        std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        return Ok(path);
    }
    let path = dirs::data_local_dir()
        .ok_or("无法定位本地数据目录")?
        .join("DevinSwitcher");
    std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
    Ok(path)
}
