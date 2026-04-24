use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child as StdChild, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use portable_pty::{ChildKiller, MasterPty, PtyPair, PtySize, native_pty_system};
use russh::keys::{PrivateKey, PublicKey, ssh_key};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, mpsc as tokio_mpsc};

use crate::platform::ShellLaunch;

use super::common::{
    SESSION_INPUT_CHANNEL_CAPACITY, SESSION_OUTPUT_CHANNEL_CAPACITY, SSH_EXTENDED_DATA_STDERR,
    debug_log, debug_public_key, same_public_key,
};
use super::forwarding::bridge_ssh_channel_with_tcp_stream;

pub async fn run_remote_shell_server<S>(
    io: S,
    allowed_username: String,
    allowed_public_key: PublicKey,
    working_directory: PathBuf,
    shell: ShellLaunch,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host_key = PrivateKey::random(
        &mut russh::keys::ssh_key::rand_core::OsRng,
        ssh_key::Algorithm::Ed25519,
    )
    .context("failed to generate SSH host key")?;
    debug_log("starting SSH server session");
    let config = server::Config {
        auth_rejection_time: Duration::from_secs(2),
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 12,
        nodelay: true,
        keys: vec![host_key],
        ..Default::default()
    };
    let config = Arc::new(config);

    let shell_states: Arc<AsyncMutex<HashMap<ChannelId, SessionChannelState>>> =
        Arc::new(AsyncMutex::new(HashMap::new()));
    let handler = RemoteShellHandler {
        allowed_username,
        allowed_public_key,
        working_directory,
        shell,
        shell_states: Arc::clone(&shell_states),
    };

    let running_session = server::run_stream(config, io, handler)
        .await
        .context("failed to start SSH server transport")?;
    debug_log("SSH server transport established");
    running_session.await.context("SSH server session failed")
}

struct PendingSessionChannel {
    env_vars: Vec<(String, String)>,
}

enum SessionChannelState {
    Pending(PendingSessionChannel),
    PtyAllocated {
        pair: PtyPair,
        term: String,
        env_vars: Vec<(String, String)>,
    },
    RunningPty {
        master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
        input_sender: Option<tokio_mpsc::Sender<Vec<u8>>>,
        killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
    },
    RunningExec {
        child: Arc<Mutex<StdChild>>,
        input_sender: Option<tokio_mpsc::Sender<Vec<u8>>>,
    },
}

struct RemoteShellHandler {
    allowed_username: String,
    allowed_public_key: PublicKey,
    working_directory: PathBuf,
    shell: ShellLaunch,
    shell_states: Arc<AsyncMutex<HashMap<ChannelId, SessionChannelState>>>,
}

impl RemoteShellHandler {
    fn shell_size(cols: u32, rows: u32, pix_width: u32, pix_height: u32) -> PtySize {
        PtySize {
            rows: rows.max(1) as u16,
            cols: cols.max(1) as u16,
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
        }
    }

    fn exit_status_code(status: ExitStatus) -> u32 {
        match status.code() {
            Some(code) => u32::try_from(code).unwrap_or(1),
            None => 1,
        }
    }

    fn read_process_output<R>(mut reader: R, sender: tokio_mpsc::Sender<Vec<u8>>)
    where
        R: Read + Send + 'static,
    {
        std::mem::drop(tokio::task::spawn_blocking(move || {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes_read) => {
                        if sender.blocking_send(buffer[..bytes_read].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    async fn start_pty_session(
        &self,
        channel: ChannelId,
        handle: server::Handle,
        pair: PtyPair,
        term: String,
        env_vars: Vec<(String, String)>,
        command_text: Option<String>,
    ) -> Result<()> {
        let mut command = match command_text {
            Some(command_text) => self.shell.build_exec_pty_command(&command_text),
            None => self.shell.build_command(),
        };
        command.cwd(&self.working_directory);
        command.env("TERM", &term);
        for (name, value) in &env_vars {
            command.env(name, value);
        }
        let mut child = pair
            .slave
            .spawn_command(command)
            .context("failed to spawn PTY process")?;

        let killer = Arc::new(Mutex::new(child.clone_killer()));
        let mut reader = pair
            .master
            .try_clone_reader()
            .context("failed to clone PTY reader")?;
        let mut writer = pair
            .master
            .take_writer()
            .context("failed to take PTY writer")?;
        let master = Arc::new(Mutex::new(pair.master));

        let (input_sender, mut input_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_INPUT_CHANNEL_CAPACITY);
        std::mem::drop(tokio::task::spawn_blocking(move || {
            while let Some(data) = input_receiver.blocking_recv() {
                if writer.write_all(&data).is_err() {
                    break;
                }
                if writer.flush().is_err() {
                    break;
                }
            }
        }));

        let (output_sender, mut output_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_OUTPUT_CHANNEL_CAPACITY);
        tokio::task::spawn_blocking(move || {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes_read) => {
                        if output_sender
                            .blocking_send(buffer[..bytes_read].to_vec())
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let output_handle = handle.clone();
        tokio::spawn(async move {
            while let Some(bytes) = output_receiver.recv().await {
                if output_handle.data(channel, bytes).await.is_err() {
                    break;
                }
            }
        });

        {
            let mut guard = self.shell_states.lock().await;
            guard.insert(
                channel,
                SessionChannelState::RunningPty {
                    master,
                    input_sender: Some(input_sender),
                    killer,
                },
            );
        }

        let exit_handle = handle.clone();
        let shell_states = Arc::clone(&self.shell_states);
        tokio::spawn(async move {
            let wait_result = tokio::task::spawn_blocking(move || child.wait()).await;
            let exit_code: u32 = match wait_result {
                Ok(Ok(status)) => status.exit_code(),
                _ => 1,
            };
            debug_log(format!("PTY process exited with status {exit_code}"));
            let _ = exit_handle.exit_status_request(channel, exit_code).await;
            let _ = exit_handle.eof(channel).await;
            let _ = exit_handle.close(channel).await;
            let mut guard = shell_states.lock().await;
            guard.remove(&channel);
        });
        Ok(())
    }

    async fn start_exec_session(
        &self,
        channel: ChannelId,
        handle: server::Handle,
        env_vars: Vec<(String, String)>,
        command_text: String,
    ) -> Result<()> {
        let mut command = self.shell.build_exec_command(&command_text);
        command.current_dir(&self.working_directory);
        for (name, value) in &env_vars {
            command.env(name, value);
        }
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command.spawn().context("failed to spawn exec process")?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("failed to take exec stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("failed to take exec stderr"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to take exec stdin"))?;

        let child = Arc::new(Mutex::new(child));

        let (input_sender, mut input_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_INPUT_CHANNEL_CAPACITY);
        std::mem::drop(tokio::task::spawn_blocking(move || {
            while let Some(data) = input_receiver.blocking_recv() {
                if stdin.write_all(&data).is_err() {
                    break;
                }
                if stdin.flush().is_err() {
                    break;
                }
            }
        }));

        let (stdout_sender, mut stdout_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_OUTPUT_CHANNEL_CAPACITY);
        let (stderr_sender, mut stderr_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_OUTPUT_CHANNEL_CAPACITY);
        Self::read_process_output(stdout, stdout_sender);
        Self::read_process_output(stderr, stderr_sender);

        let stdout_handle = handle.clone();
        tokio::spawn(async move {
            while let Some(bytes) = stdout_receiver.recv().await {
                if stdout_handle.data(channel, bytes).await.is_err() {
                    break;
                }
            }
        });

        let stderr_handle = handle.clone();
        tokio::spawn(async move {
            while let Some(bytes) = stderr_receiver.recv().await {
                if stderr_handle
                    .extended_data(channel, SSH_EXTENDED_DATA_STDERR, bytes)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let wait_child = Arc::clone(&child);
        {
            let mut guard = self.shell_states.lock().await;
            guard.insert(
                channel,
                SessionChannelState::RunningExec {
                    child,
                    input_sender: Some(input_sender),
                },
            );
        }

        let exit_handle = handle.clone();
        let shell_states = Arc::clone(&self.shell_states);
        tokio::spawn(async move {
            let exit_code = tokio::task::spawn_blocking(move || -> u32 {
                loop {
                    let maybe_status = {
                        let mut child_guard = match wait_child.lock() {
                            Ok(child_guard) => child_guard,
                            Err(_) => return 1,
                        };
                        match child_guard.try_wait() {
                            Ok(status) => status,
                            Err(error) => {
                                debug_log(format!("failed to poll exec process status: {error:#}"));
                                return 1;
                            }
                        }
                    };
                    if let Some(status) = maybe_status {
                        return Self::exit_status_code(status);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            })
            .await
            .unwrap_or(1);
            debug_log(format!("exec process exited with status {exit_code}"));
            let _ = exit_handle.exit_status_request(channel, exit_code).await;
            let _ = exit_handle.eof(channel).await;
            let _ = exit_handle.close(channel).await;
            let mut guard = shell_states.lock().await;
            guard.remove(&channel);
        });
        Ok(())
    }
}

impl server::Handler for RemoteShellHandler {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        username: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        debug_log(format!("auth publickey offered for {username}"));
        debug_public_key("offered auth key", public_key);
        debug_public_key("allowed auth key", &self.allowed_public_key);
        if username == self.allowed_username
            && same_public_key(public_key, &self.allowed_public_key)
        {
            return Ok(Auth::Accept);
        }
        Ok(Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        username: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        debug_log(format!("auth publickey verify for {username}"));
        if username == self.allowed_username
            && same_public_key(public_key, &self.allowed_public_key)
        {
            return Ok(Auth::Accept);
        }
        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug_log(format!(
            "channel_open_session received for {:?}",
            channel.id()
        ));
        let mut guard = self.shell_states.lock().await;
        guard.insert(
            channel.id(),
            SessionChannelState::Pending(PendingSessionChannel {
                env_vars: Vec::new(),
            }),
        );
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let port = match u16::try_from(port_to_connect) {
            Ok(port) => port,
            Err(_) => {
                debug_log(format!(
                    "rejecting direct-tcpip request with invalid port {port_to_connect}"
                ));
                return Ok(false);
            }
        };
        let outbound = match TcpStream::connect((host_to_connect, port)).await {
            Ok(stream) => stream,
            Err(error) => {
                debug_log(format!(
                    "failed to connect direct-tcpip target {host_to_connect}:{port} from \
                     {originator_address}:{originator_port}: {error}"
                ));
                return Ok(false);
            }
        };
        debug_log(format!(
            "accepted direct-tcpip request {host_to_connect}:{port} from \
             {originator_address}:{originator_port}"
        ));
        tokio::spawn(async move {
            if let Err(error) = bridge_ssh_channel_with_tcp_stream(channel, outbound).await {
                debug_log(format!("direct-tcpip bridge failed: {error:#}"));
            }
        });
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug_log(format!(
            "pty_request term={term} cols={col_width} rows={row_height} pix_width={pix_width} pix_height={pix_height}"
        ));
        let pty_system = native_pty_system();
        let size = Self::shell_size(col_width, row_height, pix_width, pix_height);
        let pair = match pty_system.openpty(size) {
            Ok(pair) => pair,
            Err(error) => {
                debug_log(format!("failed to allocate PTY for {channel:?}: {error:#}"));
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        let mut guard = self.shell_states.lock().await;
        let Some(SessionChannelState::Pending(pending_state)) = guard.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        guard.insert(
            channel,
            SessionChannelState::PtyAllocated {
                pair,
                term: term.to_string(),
                env_vars: pending_state.env_vars,
            },
        );
        session.channel_success(channel)?;
        debug_log("pty_request accepted");
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut guard = self.shell_states.lock().await;
        let success = match guard.get_mut(&channel) {
            Some(SessionChannelState::Pending(pending_state)) => {
                pending_state
                    .env_vars
                    .push((variable_name.to_string(), variable_value.to_string()));
                true
            }
            Some(SessionChannelState::PtyAllocated { env_vars, .. }) => {
                env_vars.push((variable_name.to_string(), variable_value.to_string()));
                true
            }
            _ => false,
        };
        if success {
            session.channel_success(channel)?;
            return Ok(());
        }
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug_log("shell_request received");
        let pending_state = {
            let mut guard = self.shell_states.lock().await;
            guard.remove(&channel)
        };
        let Some(SessionChannelState::PtyAllocated {
            pair,
            term,
            env_vars,
        }) = pending_state
        else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if let Err(error) = self
            .start_pty_session(channel, session.handle(), pair, term, env_vars, None)
            .await
        {
            debug_log(format!("failed to spawn shell for {channel:?}: {error:#}"));
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        debug_log("shell_request accepted");
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command_text = String::from_utf8_lossy(data).into_owned();
        debug_log(format!(
            "exec_request received for {channel:?}: {command_text}"
        ));
        let pending_state = {
            let mut guard = self.shell_states.lock().await;
            guard.remove(&channel)
        };
        let start_result = match pending_state {
            Some(SessionChannelState::Pending(pending_state)) => {
                self.start_exec_session(
                    channel,
                    session.handle(),
                    pending_state.env_vars,
                    command_text,
                )
                .await
            }
            Some(SessionChannelState::PtyAllocated {
                pair,
                term,
                env_vars,
            }) => {
                self.start_pty_session(
                    channel,
                    session.handle(),
                    pair,
                    term,
                    env_vars,
                    Some(command_text),
                )
                .await
            }
            _ => Err(anyhow!("channel was not ready for exec request")),
        };
        if let Err(error) = start_result {
            debug_log(format!(
                "failed to start exec request for {channel:?}: {error:#}"
            ));
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let input_sender = {
            let guard = self.shell_states.lock().await;
            match guard.get(&channel) {
                Some(SessionChannelState::RunningPty {
                    input_sender: Some(input_sender),
                    ..
                })
                | Some(SessionChannelState::RunningExec {
                    input_sender: Some(input_sender),
                    ..
                }) => input_sender.clone(),
                _ => return Ok(()),
            }
        };
        if data.is_empty() {
            return Ok(());
        }
        debug_log(format!(
            "forwarding {} bytes into session input",
            data.len()
        ));
        input_sender
            .send(data.to_vec())
            .await
            .map_err(|_| anyhow!("failed to send data to session input writer"))?;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut guard = self.shell_states.lock().await;
        match guard.get_mut(&channel) {
            Some(SessionChannelState::RunningPty { input_sender, .. })
            | Some(SessionChannelState::RunningExec { input_sender, .. }) => {
                debug_log("received SSH channel EOF");
                let _ = input_sender.take();
            }
            _ => {}
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let removed_state = {
            let mut guard = self.shell_states.lock().await;
            guard.remove(&channel)
        };
        match removed_state {
            Some(SessionChannelState::RunningPty { killer, .. }) => {
                debug_log("received SSH channel close");
                if let Ok(mut killer_guard) = killer.lock() {
                    let _ = killer_guard.kill();
                }
            }
            Some(SessionChannelState::RunningExec { child, .. }) => {
                debug_log("received SSH channel close");
                if let Ok(mut child_guard) = child.lock() {
                    let _ = child_guard.kill();
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let size = Self::shell_size(col_width, row_height, pix_width, pix_height);
        let guard = self.shell_states.lock().await;
        match guard.get(&channel) {
            Some(SessionChannelState::PtyAllocated { pair, .. }) => {
                pair.master
                    .resize(size)
                    .context("failed to resize pending PTY")?;
            }
            Some(SessionChannelState::RunningPty { master, .. }) => {
                let master_guard = master
                    .lock()
                    .map_err(|_| anyhow!("failed to lock PTY master"))?;
                master_guard
                    .resize(size)
                    .context("failed to resize running PTY")?;
            }
            _ => {}
        }
        Ok(())
    }
}
