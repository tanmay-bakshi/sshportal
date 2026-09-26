use std::env;
use std::io::{self, Write};

pub(crate) fn debug_enabled() -> bool {
    env::var_os("SSHPORTAL_DEBUG").is_some()
}

pub(crate) fn debug_log(message: impl AsRef<str>) {
    if debug_enabled() {
        write_debug_message(&mut io::stderr().lock(), message.as_ref());
    }
}

fn write_debug_message(output: &mut impl Write, message: &str) {
    let line = format!("[sshportal-debug] {}\n", message.escape_debug());
    // A closed diagnostic sink must not interrupt the support session.
    let _ = output.write_all(line.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::write_debug_message;

    #[test]
    fn peer_controlled_diagnostics_cannot_rewrite_the_terminal_or_inject_log_lines() {
        let mut output = Vec::new();
        write_debug_message(
            &mut output,
            "auth for user\r\n[trusted] granted\u{001b}]52;c;payload\u{0007}\u{202e}\u{2028}",
        );
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "[sshportal-debug] auth for user\\r\\n[trusted] granted\\u{1b}]52;c;payload\\u{7}\\u{202e}\\u{2028}\n"
        );
    }

    #[test]
    fn ordinary_unicode_diagnostics_remain_readable() {
        let mut output = Vec::new();
        write_debug_message(&mut output, "résumé uploaded to 東京");
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "[sshportal-debug] résumé uploaded to 東京\n"
        );
    }

    #[test]
    fn failed_diagnostic_writes_do_not_panic() {
        let mut full = std::io::Cursor::new([]);
        write_debug_message(&mut full, "session remains active");
    }
}
