use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{self, PrivateKey, PublicKey, ssh_key};

#[derive(Clone)]
pub struct OperatorKeyMaterial {
    private_key: Arc<PrivateKey>,
    public_key_openssh: String,
    persistent: bool,
}

impl OperatorKeyMaterial {
    pub fn from_private_key(private_key: PrivateKey, persistent: bool) -> Result<Self> {
        let public_key_openssh = private_key
            .public_key()
            .to_openssh()
            .context("failed to encode public key")?;
        Ok(Self {
            private_key: Arc::new(private_key),
            public_key_openssh,
            persistent,
        })
    }

    pub fn private_key(&self) -> &Arc<PrivateKey> {
        &self.private_key
    }

    pub fn public_key_openssh(&self) -> &str {
        &self.public_key_openssh
    }

    pub fn persistent(&self) -> bool {
        self.persistent
    }
}

pub fn load_operator_key(
    private_key_path: Option<&Path>,
    persistent: bool,
) -> Result<OperatorKeyMaterial> {
    if persistent && private_key_path.is_none() {
        bail!("--persist-operator-key requires --operator-key");
    }

    let private_key: PrivateKey = if let Some(path) = private_key_path {
        keys::load_secret_key(path, None)
            .with_context(|| format!("failed to load private key from {}", path.display()))?
    } else {
        PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
            .context("failed to generate an ephemeral SSH key")?
    };
    OperatorKeyMaterial::from_private_key(private_key, persistent)
}

pub fn parse_public_key(public_key_openssh: &str) -> Result<PublicKey> {
    PublicKey::from_openssh(public_key_openssh.trim()).context("failed to parse public key")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedKeyTarget {
    authorized_keys_path: PathBuf,
    prompt_path: String,
}

impl AuthorizedKeyTarget {
    pub fn prompt_path(&self) -> &str {
        &self.prompt_path
    }

    pub fn install(&self, public_key_openssh: &str) -> Result<bool> {
        install_authorized_key_at_path(&self.authorized_keys_path, public_key_openssh)
    }

    #[cfg(not(windows))]
    fn from_home(home_directory: &Path) -> Self {
        Self {
            authorized_keys_path: home_directory.join(".ssh").join("authorized_keys"),
            prompt_path: "~/.ssh/authorized_keys".to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedKeySupport {
    Supported(AuthorizedKeyTarget),
    Unsupported { reason: String },
}

pub fn authorized_key_support() -> Result<AuthorizedKeySupport> {
    #[cfg(windows)]
    {
        Ok(AuthorizedKeySupport::Unsupported {
            reason: "persistent operator key installation is not supported on Windows clients"
                .to_string(),
        })
    }

    #[cfg(not(windows))]
    {
        let home_directory = home_directory()?;
        Ok(AuthorizedKeySupport::Supported(
            AuthorizedKeyTarget::from_home(&home_directory),
        ))
    }
}

fn install_authorized_key_at_path(
    authorized_keys_path: &Path,
    public_key_openssh: &str,
) -> Result<bool> {
    let ssh_directory = authorized_keys_path
        .parent()
        .ok_or_else(|| anyhow!("authorized_keys path had no parent directory"))?;

    fs::create_dir_all(ssh_directory)
        .with_context(|| format!("failed to create {}", ssh_directory.display()))?;
    set_directory_permissions(ssh_directory)?;

    let normalized_key: String = public_key_openssh.trim().to_string();
    let mut existing_contents: String = String::new();
    if authorized_keys_path.exists() {
        let mut file = OpenOptions::new()
            .read(true)
            .open(authorized_keys_path)
            .with_context(|| format!("failed to open {}", authorized_keys_path.display()))?;
        file.read_to_string(&mut existing_contents)
            .with_context(|| format!("failed to read {}", authorized_keys_path.display()))?;
    }

    let already_present: bool = existing_contents
        .lines()
        .any(|line| line.trim() == normalized_key);
    if already_present {
        set_file_permissions(authorized_keys_path)?;
        return Ok(false);
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(authorized_keys_path)
        .with_context(|| format!("failed to open {}", authorized_keys_path.display()))?;
    if !existing_contents.is_empty() && !existing_contents.ends_with('\n') {
        file.write_all(b"\n").with_context(|| {
            format!(
                "failed to append newline to {}",
                authorized_keys_path.display()
            )
        })?;
    }
    file.write_all(normalized_key.as_bytes())
        .with_context(|| format!("failed to append key to {}", authorized_keys_path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finalize {}", authorized_keys_path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush {}", authorized_keys_path.display()))?;
    set_file_permissions(authorized_keys_path)?;
    Ok(true)
}

#[cfg(not(windows))]
fn home_directory() -> Result<PathBuf> {
    if let Some(home_directory) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home_directory));
    }

    if let Some(home_directory) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(home_directory));
    }

    Err(anyhow!("HOME and USERPROFILE are not set"))
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::AuthorizedKeyTarget;

    fn authorized_key_target_for_test(home_directory: &std::path::Path) -> AuthorizedKeyTarget {
        AuthorizedKeyTarget {
            authorized_keys_path: home_directory.join(".ssh").join("authorized_keys"),
            prompt_path: "~/.ssh/authorized_keys".to_string(),
        }
    }

    #[test]
    fn authorized_key_installation_is_idempotent() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN4hvJxW3y2gM5N1mW2S4Gv0y1D7g2cP1wI6Xo4YgNqS";
        let target = authorized_key_target_for_test(temp_dir.path());

        let first_install = target.install(key).unwrap();
        let second_install = target.install(key).unwrap();

        assert!(first_install);
        assert!(!second_install);

        let authorized_keys =
            fs::read_to_string(temp_dir.path().join(".ssh/authorized_keys")).unwrap();
        assert_eq!(authorized_keys.lines().count(), 1);
        assert_eq!(authorized_keys.trim(), key);
    }
}
