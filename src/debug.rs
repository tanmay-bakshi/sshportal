use std::env;

pub(crate) fn debug_enabled() -> bool {
    env::var_os("SSHPORTAL_DEBUG").is_some()
}

pub(crate) fn debug_log(message: impl AsRef<str>) {
    if debug_enabled() {
        eprintln!("[sshportal-debug] {}", message.as_ref());
    }
}
