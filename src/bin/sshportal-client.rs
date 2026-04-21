#![forbid(unsafe_code)]

use std::env;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use hostname::get;

use sshportal::{
    AuthorizedKeySupport, ClientDecision, ClientHello, ClientMetadata, ControlPacket,
    PROTOCOL_VERSION, Platform, ServerOffer, ShellLaunch, authorized_key_support,
    connect_async_with_env_proxy, install_default_rustls_crypto_provider, normalize_websocket_url,
    parse_public_key, recv_packet, run_remote_shell_server, send_packet, validate_protocol_version,
    websocket_to_io,
};

#[derive(Parser, Debug)]
#[command(
    name = "sshportal-client",
    about = "Connect back to an sshportal server and request local user approval.",
    long_about = "Connect to an sshportal rendezvous endpoint, complete the handshake, and serve the approved shell session back to the operator over the upgraded transport.",
    after_help = "Examples:\n  sshportal-client --server http://server-host:8080?token=<join-token>\n  sshportal-client --server https://support.example.com?token=<join-token> --approve-session"
)]
struct ClientCli {
    /// Server URL to connect to.
    ///
    /// Accepts http://, https://, ws://, or wss:// URLs. If the URL has no
    /// explicit path, the client automatically targets /connect.
    #[arg(long)]
    server: String,
    /// Skip the prompt that approves the live support session.
    #[arg(long)]
    approve_session: bool,
    /// Skip the prompt that approves persistent operator key installation.
    #[arg(long)]
    approve_key_install: bool,
}

struct LocalClientEnvironment {
    metadata: ClientMetadata,
    shell: ShellLaunch,
}

struct KeyInstallOutcome {
    installed: bool,
    note: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = ClientCli::parse();
    install_default_rustls_crypto_provider();
    let client_environment = gather_client_environment()?;
    let server_url = normalize_websocket_url(&cli.server)?;
    println!("connecting to {server_url}");

    let (mut websocket, _response) = connect_async_with_env_proxy(&server_url)
        .await
        .context("failed to connect to sshportal server")?;
    let hello = ClientHello {
        protocol_version: PROTOCOL_VERSION,
        metadata: client_environment.metadata.clone(),
    };
    send_packet(&mut websocket, &ControlPacket::ClientHello(hello)).await?;

    let offer = match recv_packet(&mut websocket).await? {
        ControlPacket::ServerOffer(offer) => offer,
        unexpected => bail!("expected server_offer packet, received {unexpected:?}"),
    };
    validate_protocol_version(offer.protocol_version)?;

    let public_key = parse_public_key(&offer.ssh_public_key)?;
    let session_allowed = if cli.approve_session {
        true
    } else {
        prompt_yes_no(
            &format!(
                "Allow {} to open SSH support sessions into this environment while this connection remains open?",
                offer.operator_name
            ),
            false,
        )?
    };
    if !session_allowed {
        let decision = ClientDecision {
            session_allowed: false,
            key_installed: false,
            note: Some("local user declined the support session".to_string()),
        };
        send_packet(&mut websocket, &ControlPacket::ClientDecision(decision)).await?;
        bail!("support session was declined locally");
    }

    let key_install = maybe_install_operator_key(&cli, &offer)?;
    let decision = ClientDecision {
        session_allowed: true,
        key_installed: key_install.installed,
        note: key_install.note,
    };
    send_packet(&mut websocket, &ControlPacket::ClientDecision(decision)).await?;

    let transport = websocket_to_io(websocket);
    run_remote_shell_server(
        transport,
        client_environment.metadata.username,
        public_key,
        PathBuf::from(client_environment.metadata.working_directory),
        client_environment.shell,
    )
    .await
}

fn gather_client_environment() -> Result<LocalClientEnvironment> {
    let hostname = get()
        .context("failed to determine hostname")?
        .to_string_lossy()
        .to_string();
    let username = env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| whoami::username());
    let working_directory = env::current_dir()
        .context("failed to determine current working directory")?
        .display()
        .to_string();
    let platform = Platform::current()?;
    let shell = ShellLaunch::detect_for_current_platform()?;
    Ok(LocalClientEnvironment {
        metadata: ClientMetadata {
            hostname,
            username,
            working_directory,
            preferred_shell: shell.label().to_string(),
            platform,
        },
        shell,
    })
}

fn maybe_install_operator_key(cli: &ClientCli, offer: &ServerOffer) -> Result<KeyInstallOutcome> {
    if !offer.persist_key_requested {
        return Ok(KeyInstallOutcome {
            installed: false,
            note: None,
        });
    }

    let target = match authorized_key_support()? {
        AuthorizedKeySupport::Supported(target) => target,
        AuthorizedKeySupport::Unsupported { reason } => {
            return Ok(KeyInstallOutcome {
                installed: false,
                note: Some(reason),
            });
        }
    };

    let install_key = if cli.approve_key_install {
        true
    } else {
        prompt_yes_no(
            &format!(
                "Persist {}'s SSH key into {} for future access?",
                offer.operator_name,
                target.prompt_path()
            ),
            false,
        )?
    };
    if !install_key {
        return Ok(KeyInstallOutcome {
            installed: false,
            note: None,
        });
    }

    let installed = target
        .install(&offer.ssh_public_key)
        .with_context(|| format!("failed to add the operator key to {}", target.prompt_path()))?;
    Ok(KeyInstallOutcome {
        installed,
        note: None,
    })
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let stdin_is_terminal = io::stdin().is_terminal();
    let stdout_is_terminal = io::stdout().is_terminal();
    if !stdin_is_terminal || !stdout_is_terminal {
        bail!("{prompt} Refusing to assume consent without --approve flags.");
    }

    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    let mut stdout = io::stdout();
    write!(stdout, "{prompt} {suffix} ").context("failed to write prompt")?;
    stdout.flush().context("failed to flush prompt")?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| anyhow!("failed to read prompt response: {error}"))?;
    let normalized = answer.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(default);
    }
    match normalized.as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => bail!("unrecognized response `{normalized}`"),
    }
}
