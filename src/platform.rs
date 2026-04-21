use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::path::Path;
use std::process::Command as StdCommand;

use anyhow::{Result, bail};
use portable_pty::CommandBuilder;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Linux,
    Macos,
    Windows,
}

impl OperatingSystem {
    pub(crate) fn current() -> Result<Self> {
        match env::consts::OS {
            "linux" => Ok(Self::Linux),
            "macos" => Ok(Self::Macos),
            "windows" => Ok(Self::Windows),
            other => bail!("unsupported client operating system `{other}`"),
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Linux => "Linux",
            Self::Macos => "macOS",
            Self::Windows => "Windows",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Platform {
    operating_system: OperatingSystem,
    architecture: String,
}

impl Platform {
    pub fn current() -> Result<Self> {
        Ok(Self {
            operating_system: OperatingSystem::current()?,
            architecture: env::consts::ARCH.to_string(),
        })
    }

    pub fn operating_system(&self) -> OperatingSystem {
        self.operating_system
    }

    pub fn architecture(&self) -> &str {
        &self.architecture
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}-{}",
            self.operating_system.display_name(),
            self.architecture
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShellFamily {
    Posix,
    PowerShell,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellLaunch {
    program: String,
    args: Vec<String>,
    family: ShellFamily,
    label: String,
}

impl ShellLaunch {
    pub fn detect_for_current_platform() -> Result<Self> {
        match OperatingSystem::current()? {
            OperatingSystem::Windows => detect_windows_shell(
                env::var_os("PATH").as_deref(),
                env::var_os("ProgramFiles").as_deref(),
                env::var_os("ProgramW6432").as_deref(),
                env::var_os("SystemRoot").as_deref(),
            ),
            OperatingSystem::Linux | OperatingSystem::Macos => {
                Ok(detect_posix_shell(env::var("SHELL").ok()))
            }
        }
    }

    pub(crate) fn build_command(&self) -> CommandBuilder {
        let mut command = CommandBuilder::new(&self.program);
        for argument in &self.args {
            command.arg(argument);
        }
        command
    }

    pub(crate) fn build_exec_command(&self, command_text: &str) -> StdCommand {
        let mut command = StdCommand::new(&self.program);
        for argument in self.exec_arguments(command_text) {
            command.arg(argument);
        }
        command
    }

    pub(crate) fn build_exec_pty_command(&self, command_text: &str) -> CommandBuilder {
        let mut command = CommandBuilder::new(&self.program);
        for argument in self.exec_arguments(command_text) {
            command.arg(argument);
        }
        command
    }

    #[cfg(test)]
    pub(crate) fn family(&self) -> ShellFamily {
        self.family
    }

    #[cfg(test)]
    pub(crate) fn program(&self) -> &str {
        &self.program
    }

    #[cfg(test)]
    pub(crate) fn arguments(&self) -> &[String] {
        &self.args
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    fn exec_arguments(&self, command_text: &str) -> Vec<String> {
        let mut arguments = self.args.clone();
        match self.family {
            ShellFamily::Posix => arguments.push("-c".to_string()),
            ShellFamily::PowerShell => arguments.push("-Command".to_string()),
        }
        arguments.push(command_text.to_string());
        arguments
    }
}

fn detect_posix_shell(shell_from_environment: Option<String>) -> ShellLaunch {
    let program = shell_from_environment
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/bin/sh".to_string());
    let label = Path::new(&program)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(program.as_str())
        .to_string();
    ShellLaunch {
        program,
        args: vec!["-l".to_string()],
        family: ShellFamily::Posix,
        label,
    }
}

fn detect_windows_shell(
    search_path: Option<&OsStr>,
    program_files: Option<&OsStr>,
    program_w6432: Option<&OsStr>,
    system_root: Option<&OsStr>,
) -> Result<ShellLaunch> {
    let program = resolve_executable_in_search_path(search_path, &["pwsh.exe", "powershell.exe"])
        .or_else(|| {
            resolve_windows_shell_in_standard_locations(
                program_files,
                program_w6432,
                system_root,
            )
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "failed to locate PowerShell; expected pwsh.exe or powershell.exe on PATH or in standard Windows install locations"
            )
        })?;

    let executable_name = Path::new(&program)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(program.as_str())
        .to_ascii_lowercase();
    let label = if executable_name == "pwsh.exe" {
        "PowerShell 7"
    } else {
        "Windows PowerShell"
    };

    Ok(ShellLaunch {
        program,
        args: vec!["-NoLogo".to_string()],
        family: ShellFamily::PowerShell,
        label: label.to_string(),
    })
}

fn resolve_windows_shell_in_standard_locations(
    program_files: Option<&OsStr>,
    program_w6432: Option<&OsStr>,
    system_root: Option<&OsStr>,
) -> Option<String> {
    for root in [program_files, program_w6432].into_iter().flatten() {
        let candidate = Path::new(root)
            .join("PowerShell")
            .join("7")
            .join("pwsh.exe");
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }

    let system_root = system_root?;
    let candidate = Path::new(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    if candidate.is_file() {
        return Some(candidate.to_string_lossy().to_string());
    }

    None
}

fn resolve_executable_in_search_path(
    search_path: Option<&OsStr>,
    candidates: &[&str],
) -> Option<String> {
    let search_path = search_path?;
    for directory in env::split_paths(search_path) {
        for candidate in candidates {
            let candidate_path = directory.join(candidate);
            if candidate_path.is_file() {
                return Some(candidate_path.to_string_lossy().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::path::Path;

    use tempfile::TempDir;

    use super::{
        ShellFamily, detect_posix_shell, detect_windows_shell, resolve_executable_in_search_path,
        resolve_windows_shell_in_standard_locations,
    };

    #[test]
    fn posix_shell_defaults_to_bin_sh_login_shell() {
        let shell = detect_posix_shell(None);

        assert_eq!(shell.program(), "/bin/sh");
        assert_eq!(shell.arguments(), ["-l"]);
        assert_eq!(shell.family(), ShellFamily::Posix);
        assert_eq!(shell.label(), "sh");
    }

    #[test]
    fn windows_shell_prefers_pwsh_when_present() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("pwsh.exe"), []).unwrap();
        std::fs::write(temp_dir.path().join("powershell.exe"), []).unwrap();

        let search_path = OsString::from(temp_dir.path());
        let shell = detect_windows_shell(Some(search_path.as_os_str()), None, None, None).unwrap();

        assert_eq!(shell.family(), ShellFamily::PowerShell);
        assert_eq!(shell.label(), "PowerShell 7");
        assert_eq!(shell.arguments(), ["-NoLogo"]);
    }

    #[test]
    fn windows_shell_uses_standard_install_location_when_path_is_missing() {
        let program_files = TempDir::new().unwrap();
        let program_w6432 = TempDir::new().unwrap();
        let system_root = TempDir::new().unwrap();
        let pwsh_path = program_files
            .path()
            .join("PowerShell")
            .join("7")
            .join("pwsh.exe");
        std::fs::create_dir_all(pwsh_path.parent().unwrap()).unwrap();
        std::fs::write(&pwsh_path, []).unwrap();

        let resolved = resolve_windows_shell_in_standard_locations(
            Some(program_files.path().as_os_str()),
            Some(program_w6432.path().as_os_str()),
            Some(system_root.path().as_os_str()),
        )
        .unwrap();

        assert_eq!(resolved, pwsh_path.to_string_lossy());
    }

    #[test]
    fn path_resolution_returns_first_matching_candidate() {
        let first_dir = TempDir::new().unwrap();
        let second_dir = TempDir::new().unwrap();
        std::fs::write(second_dir.path().join("powershell.exe"), []).unwrap();

        let search_path = env::join_paths([first_dir.path(), second_dir.path()]).unwrap();
        let resolved = resolve_executable_in_search_path(
            Some(search_path.as_os_str()),
            &["pwsh.exe", "powershell.exe"],
        )
        .unwrap();

        assert_eq!(
            Path::new(&resolved).file_name().and_then(OsStr::to_str),
            Some("powershell.exe")
        );
    }
}
