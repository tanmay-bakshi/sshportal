use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
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
        PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
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

    /// Installs the public key identity without copying its untrusted comment.
    pub fn install(&self, public_key: &PublicKey) -> Result<bool> {
        install_authorized_key_at_path(&self.authorized_keys_path, public_key)
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
    public_key: &PublicKey,
) -> Result<bool> {
    let normalized_key = PublicKey::from(public_key.key_data().clone())
        .to_openssh()
        .context("failed to encode the authorized public key")?;
    let ssh_directory = authorized_keys_path
        .parent()
        .ok_or_else(|| anyhow!("authorized_keys path had no parent directory"))?;

    fs::create_dir_all(ssh_directory)
        .with_context(|| format!("failed to create {}", ssh_directory.display()))?;
    set_directory_permissions(ssh_directory)?;

    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(authorized_keys_path)
        .with_context(|| format!("failed to open {}", authorized_keys_path.display()))?;
    // The same locked handle covers inspection and append, including competing processes.
    file.lock()
        .with_context(|| format!("failed to lock {}", authorized_keys_path.display()))?;
    set_file_permissions(&file)?;
    let mut existing_contents = String::new();
    file.read_to_string(&mut existing_contents)
        .with_context(|| format!("failed to read {}", authorized_keys_path.display()))?;

    let already_present: bool = existing_contents
        .lines()
        .filter_map(|line| PublicKey::from_openssh(line.trim()).ok())
        .any(|existing_key| existing_key.key_data() == public_key.key_data());
    if already_present {
        return Ok(false);
    }

    let separator = if !existing_contents.is_empty() && !existing_contents.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    let entry = format!("{separator}{normalized_key}\n");
    file.write_all(entry.as_bytes())
        .with_context(|| format!("failed to append key to {}", authorized_keys_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", authorized_keys_path.display()))?;
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
fn set_file_permissions(file: &File) -> Result<()> {
    let permissions = fs::Permissions::from_mode(0o600);
    file.set_permissions(permissions)
        .context("failed to set authorized_keys permissions")?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Barrier};

    use tempfile::TempDir;

    use super::{AuthorizedKeyTarget, parse_public_key};

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

        let public_key = parse_public_key(key).unwrap();
        let first_install = target.install(&public_key).unwrap();
        let second_install = target.install(&public_key).unwrap();

        assert!(first_install);
        assert!(!second_install);

        let authorized_keys =
            fs::read_to_string(temp_dir.path().join(".ssh/authorized_keys")).unwrap();
        assert_eq!(authorized_keys.lines().count(), 1);
        assert_eq!(authorized_keys.trim(), key);
    }

    #[test]
    fn authorized_key_installation_stores_only_the_parsed_key_identity() {
        let temp_dir = TempDir::new().unwrap();
        let approved_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
        let additional_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN4hvJxW3y2gM5N1mW2S4Gv0y1D7g2cP1wI6Xo4YgNqS";
        let offered_key = format!("{approved_key} support key\n{additional_key}");
        let parsed_key = parse_public_key(&offered_key).unwrap();
        assert_eq!(
            parsed_key.key_data(),
            parse_public_key(approved_key).unwrap().key_data()
        );
        let target = authorized_key_target_for_test(temp_dir.path());

        target.install(&parsed_key).unwrap();

        let installed = fs::read_to_string(temp_dir.path().join(".ssh/authorized_keys")).unwrap();
        assert_eq!(installed, format!("{approved_key}\n"));
    }

    #[test]
    fn an_existing_key_comment_does_not_duplicate_the_key() {
        let temp_dir = TempDir::new().unwrap();
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
        let target = authorized_key_target_for_test(temp_dir.path());
        fs::create_dir(temp_dir.path().join(".ssh")).unwrap();
        let existing = format!("# Operator keys\n{key} existing comment\n");
        fs::write(&target.authorized_keys_path, &existing).unwrap();
        let offered_key = parse_public_key(&format!("{key} another comment")).unwrap();

        assert!(!target.install(&offered_key).unwrap());

        assert_eq!(
            fs::read_to_string(&target.authorized_keys_path).unwrap(),
            existing
        );
    }

    #[test]
    fn concurrent_key_installations_append_one_complete_entry() {
        let temp_dir = TempDir::new().unwrap();
        let target = authorized_key_target_for_test(temp_dir.path());
        let key = parse_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        )
        .unwrap();
        let start = Arc::new(Barrier::new(8));
        let installers = (0..8)
            .map(|_| {
                let target = target.clone();
                let key = key.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    target.install(&key).unwrap()
                })
            })
            .collect::<Vec<_>>();

        let installed = installers
            .into_iter()
            .map(|task| usize::from(task.join().unwrap()))
            .sum::<usize>();

        assert_eq!(installed, 1);
        assert_eq!(
            fs::read_to_string(&target.authorized_keys_path).unwrap(),
            format!("{}\n", key.to_openssh().unwrap()),
        );
    }

    #[test]
    fn key_installation_preserves_an_unterminated_existing_line() {
        let temp_dir = TempDir::new().unwrap();
        let target = authorized_key_target_for_test(temp_dir.path());
        let key = parse_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        )
        .unwrap();
        fs::create_dir(temp_dir.path().join(".ssh")).unwrap();
        fs::write(&target.authorized_keys_path, "# Existing keys").unwrap();

        assert!(target.install(&key).unwrap());

        assert_eq!(
            fs::read_to_string(&target.authorized_keys_path).unwrap(),
            format!("# Existing keys\n{}\n", key.to_openssh().unwrap()),
        );
    }
}
