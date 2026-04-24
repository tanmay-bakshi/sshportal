use std::env;

use anyhow::Result;
use russh::client;
use russh::keys::{PublicKey, ssh_key};

#[derive(Default)]
pub(super) struct NoopClientHandler;

impl client::Handler for NoopClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn debug_enabled() -> bool {
    env::var_os("SSHPORTAL_DEBUG").is_some()
}

pub(super) fn debug_log(message: impl AsRef<str>) {
    if debug_enabled() {
        eprintln!("[sshportal-debug] {}", message.as_ref());
    }
}

pub(super) fn debug_public_key(label: &str, public_key: &PublicKey) {
    if !debug_enabled() {
        return;
    }
    let rendered_key = public_key
        .to_openssh()
        .unwrap_or_else(|_| "<failed to render public key>".to_string());
    eprintln!("[sshportal-debug] {label}: {rendered_key}");
}

pub(super) fn same_public_key(left: &PublicKey, right: &PublicKey) -> bool {
    left.algorithm() == right.algorithm() && left.key_data() == right.key_data()
}

pub(super) const SSH_EXTENDED_DATA_STDERR: u32 = 1;
pub(super) const SESSION_INPUT_CHANNEL_CAPACITY: usize = 32;
pub(super) const SESSION_OUTPUT_CHANNEL_CAPACITY: usize = 32;
