use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

/// Owns process signal registration and a cancellation token for all session epochs.
pub struct Shutdown {
    pub token: CancellationToken,
    _task: AbortOnDropHandle<()>,
}

impl Shutdown {
    pub fn new() -> Result<Self> {
        let token = CancellationToken::new();
        let notified = token.clone();
        #[cfg(unix)]
        let signals = {
            use tokio::signal::unix::{SignalKind, signal};
            let mut interrupt =
                signal(SignalKind::interrupt()).context("failed to listen for SIGINT")?;
            let mut terminate =
                signal(SignalKind::terminate()).context("failed to listen for SIGTERM")?;
            let mut hangup = signal(SignalKind::hangup()).context("failed to listen for SIGHUP")?;
            async move {
                tokio::select! {
                    _ = interrupt.recv() => {}
                    _ = terminate.recv() => {}
                    _ = hangup.recv() => {}
                }
            }
        };
        #[cfg(windows)]
        let signals = {
            let mut interrupt =
                tokio::signal::windows::ctrl_c().context("failed to listen for Ctrl-C")?;
            let mut terminate =
                tokio::signal::windows::ctrl_break().context("failed to listen for Ctrl-Break")?;
            async move {
                tokio::select! {
                    _ = interrupt.recv() => {}
                    _ = terminate.recv() => {}
                }
            }
        };
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            signals.await;
            notified.cancel();
        }));
        Ok(Self { token, _task: task })
    }
}
