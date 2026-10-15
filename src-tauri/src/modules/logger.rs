// Upstream error messages can contain remote response bodies. Do not persist
// authentication diagnostics or credentials in production logs.
pub fn log_info(_message: &str) {}
pub fn log_warn(_message: &str) {}
pub fn log_error(_message: &str) {}
