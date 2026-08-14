use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio_tungstenite::WebSocketStream;
use tokio_util::task::AbortOnDropHandle;

use crate::network::run_operator_network_proxy_with_listener;
use crate::socks::SocksAuthentication;

const COMPANION_BUNDLE_NAME: &str = "SSHPortal.app";
const COMPANION_EXECUTABLE: &str = "Contents/MacOS/SSHPortal";
const COMPANION_SYSTEM_EXTENSION: &str =
    "Contents/Library/SystemExtensions/SSHPortalAppProxy.systemextension";
const COMPANION_START_TIMEOUT: Duration = Duration::from_secs(180);
const COMPANION_STOP_TIMEOUT: Duration = Duration::from_secs(15);
const SOCKS_USERNAME: &str = "sshportal";

#[derive(Clone, Debug)]
pub struct MacosPerAppVpn {
    application_bundle: PathBuf,
    application_name: String,
    companion_bundle: PathBuf,
    companion_executable: PathBuf,
}

impl MacosPerAppVpn {
    pub fn resolve(application_bundle: &Path, companion_bundle: Option<&Path>) -> Result<Self> {
        let application_bundle = canonical_app_bundle(application_bundle, "VPN application")?;
        let application_name = application_bundle
            .file_stem()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .context("VPN application bundle has no valid display name")?
            .to_string();
        let companion_bundle = resolve_companion_bundle(companion_bundle)?;
        let companion_executable = companion_bundle.join(COMPANION_EXECUTABLE);
        if !companion_executable.is_file() {
            bail!(
                "macOS companion executable is missing at {}; rebuild or reinstall {COMPANION_BUNDLE_NAME}",
                companion_executable.display()
            );
        }
        let system_extension = companion_bundle.join(COMPANION_SYSTEM_EXTENSION);
        if !system_extension.is_dir() {
            bail!(
                "macOS app proxy system extension is missing at {}; rebuild or reinstall {COMPANION_BUNDLE_NAME}",
                system_extension.display()
            );
        }

        Ok(Self {
            application_bundle,
            application_name,
            companion_bundle,
            companion_executable,
        })
    }

    pub fn application_name(&self) -> &str {
        &self.application_name
    }

    pub fn application_bundle(&self) -> &Path {
        &self.application_bundle
    }

    pub fn companion_bundle(&self) -> &Path {
        &self.companion_bundle
    }

    pub async fn run<S>(&self, websocket: WebSocketStream<S>) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("failed to bind the per-app VPN's private SOCKS5 listener")?;
        let socks_address = listener
            .local_addr()
            .context("failed to read the per-app VPN's private SOCKS5 address")?;
        let password = random_session_secret();
        let authentication = SocksAuthentication::UsernamePassword {
            username: SOCKS_USERNAME.to_string(),
            password: password.clone(),
        };
        let mut shutdown_signals = ShutdownSignals::new()?;
        let mut companion = CompanionProcess::spawn(&self.companion_executable).await?;
        let start_command = CompanionCommand::Start {
            application_path: self.application_bundle.display().to_string(),
            socks_host: socks_address.ip().to_string(),
            socks_port: socks_address.port(),
            username: SOCKS_USERNAME.to_string(),
            password,
        };
        if let Err(error) = companion.send(&start_command).await {
            return match companion.stop().await {
                Ok(()) => Err(error),
                Err(stop_error) => Err(error.context(format!(
                    "macOS per-app VPN cleanup also failed: {stop_error:#}"
                ))),
            };
        }

        let mut proxy_task = Some(AbortOnDropHandle::new(tokio::spawn(
            run_operator_network_proxy_with_listener(websocket, listener, authentication),
        )));
        match wait_for_companion_start(&mut companion, &mut proxy_task, &mut shutdown_signals).await
        {
            Ok(CompanionStart::Active) => {}
            Ok(CompanionStart::ShutdownRequested) => {
                let proxy_result = stop_proxy_task(&mut proxy_task).await;
                return combine_results(
                    proxy_result,
                    companion.stop().await,
                    "macOS per-app VPN companion cleanup also failed",
                );
            }
            Err(error) => {
                let proxy_result = stop_proxy_task(&mut proxy_task).await;
                return combine_results(
                    combine_results(
                        Err(error),
                        proxy_result,
                        "per-app VPN network proxy cleanup also failed",
                    ),
                    companion.stop().await,
                    "macOS per-app VPN companion cleanup also failed",
                );
            }
        }

        println!(
            "per-app VPN active for {} ({})",
            self.application_name,
            self.application_bundle.display()
        );
        println!("only new connections from this application are routed through the client");
        println!("press Ctrl-C to disconnect and remove the per-app VPN configuration");

        let session_result = tokio::select! {
            proxy_result = proxy_task.as_mut().expect("per-app VPN proxy task is present") => {
                proxy_task.take();
                proxy_result
                    .context("per-app VPN network proxy task failed to join")
                    .and_then(|result| result)
            }
            event_result = companion.next_event() => {
                match event_result {
                    Ok(Some(CompanionEvent::Error { message })) => {
                        Err(anyhow!("macOS per-app VPN companion failed: {message}"))
                    }
                    Ok(Some(event)) => {
                        Err(anyhow!("macOS per-app VPN companion stopped unexpectedly: {event:?}"))
                    }
                    Ok(None) => Err(anyhow!("macOS per-app VPN companion exited unexpectedly")),
                    Err(error) => Err(error),
                }
            }
            _ = shutdown_signals.recv() => Ok(()),
        };

        let proxy_result = stop_proxy_task(&mut proxy_task).await;
        combine_results(
            combine_results(
                session_result,
                proxy_result,
                "per-app VPN network proxy cleanup also failed",
            ),
            companion.stop().await,
            "macOS per-app VPN companion cleanup also failed",
        )
    }
}

fn canonical_app_bundle(path: &Path, description: &str) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to find {description} at {}", path.display()))?;
    if !canonical.is_dir()
        || canonical
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("app")
    {
        bail!(
            "{description} must be a macOS .app bundle: {}",
            path.display()
        );
    }
    Ok(canonical)
}

fn resolve_companion_bundle(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return canonical_app_bundle(path, "macOS companion");
    }

    let current_executable =
        std::env::current_exe().context("failed to locate sshportal-server")?;
    let sibling = current_executable
        .parent()
        .context("sshportal-server has no parent directory")?
        .join(COMPANION_BUNDLE_NAME);
    let candidates = [sibling, PathBuf::from("/Applications/SSHPortal.app")];
    for candidate in candidates {
        if candidate.is_dir() {
            return canonical_app_bundle(&candidate, "macOS companion");
        }
    }

    bail!(
        "{COMPANION_BUNDLE_NAME} was not found beside sshportal-server or in /Applications; build and install the native companion, or pass --vpn-companion"
    )
}

fn random_session_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::fill(&mut bytes);
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;

        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[derive(Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum CompanionCommand {
    Start {
        application_path: String,
        socks_host: String,
        socks_port: u16,
        username: String,
        password: String,
    },
    Stop,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum CompanionEvent {
    Installing,
    ApprovalRequired,
    Configuring {
        application: String,
        signing_identifier: String,
    },
    Active,
    Stopped,
    Error {
        message: String,
    },
}

struct CompanionProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    saw_stopped: bool,
}

impl CompanionProcess {
    async fn spawn(executable: &Path) -> Result<Self> {
        let mut child = Command::new(executable)
            .arg("--stdio-control")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| {
                format!(
                    "failed to start the macOS per-app VPN companion at {}",
                    executable.display()
                )
            })?;
        let stdin = child
            .stdin
            .take()
            .context("macOS per-app VPN companion has no command pipe")?;
        let stdout = child
            .stdout
            .take()
            .context("macOS per-app VPN companion has no event pipe")?;
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout).lines(),
            saw_stopped: false,
        })
    }

    async fn send(&mut self, command: &CompanionCommand) -> Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .context("macOS per-app VPN companion command pipe is closed")?;
        let mut encoded = serde_json::to_vec(command)
            .context("failed to encode macOS per-app VPN companion command")?;
        encoded.push(b'\n');
        stdin
            .write_all(&encoded)
            .await
            .context("failed to send command to macOS per-app VPN companion")?;
        stdin
            .flush()
            .await
            .context("failed to flush macOS per-app VPN companion command")
    }

    async fn next_event(&mut self) -> Result<Option<CompanionEvent>> {
        let Some(line) = self
            .stdout
            .next_line()
            .await
            .context("failed to read macOS per-app VPN companion event")?
        else {
            return Ok(None);
        };
        let event: CompanionEvent = serde_json::from_str(&line).with_context(|| {
            format!("macOS per-app VPN companion emitted invalid event: {line}")
        })?;
        if matches!(event, CompanionEvent::Stopped) {
            self.saw_stopped = true;
        }
        Ok(Some(event))
    }

    async fn stop(&mut self) -> Result<()> {
        let request_result = if self.child.try_wait()?.is_none() && self.stdin.is_some() {
            self.send(&CompanionCommand::Stop).await
        } else {
            Ok(())
        };
        self.stdin.take();
        let stop_result = tokio::time::timeout(COMPANION_STOP_TIMEOUT, async {
            let mut stopped = self.saw_stopped;
            let mut event_error = None;
            while !stopped {
                match self.next_event().await? {
                    Some(CompanionEvent::Stopped) => {
                        stopped = true;
                    }
                    None => break,
                    Some(CompanionEvent::Error { message }) => {
                        event_error = Some(message);
                    }
                    Some(_) => {}
                }
            }
            let status = match self.child.try_wait()? {
                Some(status) => status,
                None => self
                    .child
                    .wait()
                    .await
                    .context("failed to wait for macOS per-app VPN companion")?,
            };
            Ok((status, stopped, event_error))
        })
        .await;
        match stop_result {
            Ok(Ok((status, true, None))) if status.success() => Ok(()),
            Ok(Ok((status, _, event_error))) => {
                if let Some(message) = event_error {
                    bail!("macOS per-app VPN companion cleanup failed: {message}");
                }
                if !status.success() {
                    bail!("macOS per-app VPN companion exited with {status}");
                }
                if let Err(error) = request_result {
                    return Err(error).context("failed to request macOS per-app VPN cleanup");
                }
                bail!("macOS per-app VPN companion exited without confirming cleanup");
            }
            Ok(Err(error)) => {
                self.kill_and_wait().await?;
                Err(error)
            }
            Err(_) => {
                self.kill_and_wait().await?;
                bail!("macOS per-app VPN companion did not stop within 15 seconds");
            }
        }
    }

    async fn kill_and_wait(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child
                .kill()
                .await
                .context("macOS per-app VPN companion did not stop and could not be killed")?;
        }
        self.child
            .wait()
            .await
            .context("failed to reap the macOS per-app VPN companion")?;
        Ok(())
    }
}

async fn wait_for_companion_start(
    companion: &mut CompanionProcess,
    proxy_task: &mut Option<AbortOnDropHandle<Result<()>>>,
    shutdown_signals: &mut ShutdownSignals,
) -> Result<CompanionStart> {
    let startup = async {
        loop {
            match companion.next_event().await? {
                Some(CompanionEvent::Installing) => {
                    println!("installing the SSHPortal network extension");
                }
                Some(CompanionEvent::ApprovalRequired) => {
                    println!(
                        "approve the SSHPortal system extension in System Settings to continue"
                    );
                }
                Some(CompanionEvent::Configuring {
                    application,
                    signing_identifier,
                }) => {
                    println!("configuring per-app VPN for {application} ({signing_identifier})");
                }
                Some(CompanionEvent::Active) => return Ok(CompanionStart::Active),
                Some(CompanionEvent::Error { message }) => {
                    bail!("macOS per-app VPN companion failed: {message}");
                }
                Some(CompanionEvent::Stopped) | None => {
                    bail!("macOS per-app VPN companion stopped during startup");
                }
            }
        }
    };
    tokio::select! {
        startup_result = tokio::time::timeout(COMPANION_START_TIMEOUT, startup) => {
            startup_result.context("timed out waiting for the macOS per-app VPN to activate")?
        }
        proxy_result = proxy_task.as_mut().expect("per-app VPN proxy task is present") => {
            proxy_task.take();
            match proxy_result.context("per-app VPN network proxy task failed during startup")? {
                Ok(()) => bail!("per-app VPN network proxy stopped during startup"),
                Err(error) => Err(error).context("per-app VPN network proxy failed during startup"),
            }
        }
        _ = shutdown_signals.recv() => Ok(CompanionStart::ShutdownRequested),
    }
}

async fn stop_proxy_task(task: &mut Option<AbortOnDropHandle<Result<()>>>) -> Result<()> {
    let Some(task) = task.take() else {
        return Ok(());
    };
    task.abort();
    match task.await {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(error).context("per-app VPN network proxy task failed to join"),
    }
}

fn combine_results(primary: Result<()>, secondary: Result<()>, context: &str) -> Result<()> {
    match (primary, secondary) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error).context(context.to_string()),
        (Err(primary), Err(secondary)) => Err(primary).context(format!("{context}: {secondary:#}")),
    }
}

enum CompanionStart {
    Active,
    ShutdownRequested,
}

struct ShutdownSignals {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
}

impl ShutdownSignals {
    fn new() -> Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())
                .context("failed to register the per-app VPN SIGINT handler")?,
            terminate: signal(SignalKind::terminate())
                .context("failed to register the per-app VPN SIGTERM handler")?,
            hangup: signal(SignalKind::hangup())
                .context("failed to register the per-app VPN SIGHUP handler")?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
            _ = self.hangup.recv() => {}
        }
    }
}
