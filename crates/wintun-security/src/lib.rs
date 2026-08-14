#![cfg(target_os = "windows")]

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use anyhow::{Context, Result, anyhow, bail, ensure};
use rand::random;
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetSecurityInfo,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
    GetSecurityDescriptorGroup, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_SEQUENTIAL_SCAN, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_TYPE_DISK,
    GetDriveTypeW, GetFileType, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
    GetVolumePathNameW, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};
use windows_sys::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

const CACHE_DIRECTORY_NAME: &str = "SSHPortal";
const EXPECTED_PUBLISHER: &str = "WireGuard LLC";
const SECURITY_DESCRIPTOR: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

#[cfg(target_arch = "x86_64")]
const EXPECTED_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
#[cfg(target_arch = "x86_64")]
const EXPECTED_LENGTH: u64 = 427_552;
#[cfg(target_arch = "x86")]
const EXPECTED_SHA256: &str = "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931";
#[cfg(target_arch = "x86")]
const EXPECTED_LENGTH: u64 = 550_928;
#[cfg(target_arch = "arm")]
const EXPECTED_SHA256: &str = "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9";
#[cfg(target_arch = "arm")]
const EXPECTED_LENGTH: u64 = 364_552;
#[cfg(target_arch = "aarch64")]
const EXPECTED_SHA256: &str = "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80";
#[cfg(target_arch = "aarch64")]
const EXPECTED_LENGTH: u64 = 222_488;

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "aarch64"
)))]
compile_error!("Wintun is not available for this Windows architecture");

/// Holds the verified Wintun image and its containing directory against mutation until the caller
/// has loaded the DLL.
#[derive(Debug)]
pub struct VerifiedWintun {
    path: PathBuf,
    file: Option<File>,
    directory: Option<File>,
}

impl VerifiedWintun {
    /// Copies the bundled Wintun image into an administrator-owned cache and verifies the exact
    /// locked file that the Windows loader will receive.
    ///
    /// The returned guard must remain alive until the DLL has been loaded.
    ///
    pub fn prepare(bundled_path: &Path) -> Result<Self> {
        restrict_process_dll_search_to_system32()?;
        let descriptor = SecurityDescriptor::new()?;
        let cache_directory = program_data_directory()?.join(CACHE_DIRECTORY_NAME);
        secure_cache_directory(&cache_directory, &descriptor)?;

        let mut staged_image = stage_fresh_image(bundled_path, &cache_directory, &descriptor)?;
        let cache_path = staged_image.path().to_path_buf();

        // The directory and file locks close the final verification-to-load replacement window.
        // They are deliberately held by this guard rather than hidden inside a short helper.
        let directory = open_directory(&cache_directory, FILE_SHARE_READ)
            .context("failed to lock the secure Wintun cache directory")?;
        validate_directory(&directory, &cache_directory)?;
        let mut file = open_file(&cache_path, GENERIC_READ, FILE_SHARE_READ)
            .context("failed to lock the cached Wintun image")?;
        validate_locked_wintun(&mut file, &cache_path)?;
        let path = final_path(&file).context("failed to canonicalize the cached Wintun image")?;
        staged_image.keep();

        Ok(Self {
            path,
            file: Some(file),
            directory: Some(directory),
        })
    }

    /// Returns the canonical path of the verified, locked Wintun image.
    ///
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Restricts default dynamic-library resolution to the Windows system directory.
///
/// Fully qualified library paths remain usable. Calls that name only a library file can no longer
/// resolve it from the executable directory, current directory, or `PATH`.
///
pub fn restrict_process_dll_search_to_system32() -> Result<()> {
    let configured = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if configured == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to restrict default DLL resolution to System32");
    }
    Ok(())
}

impl Drop for VerifiedWintun {
    fn drop(&mut self) {
        drop(self.file.take());
        drop(self.directory.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn new() -> Result<Self> {
        let encoded = wide(SECURITY_DESCRIPTOR);
        let mut descriptor = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to construct the Wintun cache security descriptor");
        }
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    fn apply_to_handle(&self, handle: HANDLE) -> Result<()> {
        let mut owner: PSID = null_mut();
        let mut owner_defaulted = 0;
        let mut group: PSID = null_mut();
        let mut group_defaulted = 0;
        let mut dacl: *mut ACL = null_mut();
        let mut dacl_present = 0;
        let mut dacl_defaulted = 0;
        let owner_read =
            unsafe { GetSecurityDescriptorOwner(self.0, &mut owner, &mut owner_defaulted) };
        let group_read =
            unsafe { GetSecurityDescriptorGroup(self.0, &mut group, &mut group_defaulted) };
        let dacl_read = unsafe {
            GetSecurityDescriptorDacl(self.0, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
        };
        ensure!(
            owner_read != 0 && group_read != 0 && dacl_read != 0 && dacl_present != 0,
            "the Wintun cache security descriptor is incomplete"
        );

        let security_information = OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | PROTECTED_DACL_SECURITY_INFORMATION;
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                security_information,
                owner,
                group,
                dacl,
                null(),
            )
        };
        ensure!(
            status == ERROR_SUCCESS,
            "SetSecurityInfo failed with error {status}"
        );
        Ok(())
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn program_data_directory() -> Result<PathBuf> {
    let mut raw_path = null_mut();
    let status =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut raw_path) };
    if status < 0 {
        bail!("SHGetKnownFolderPath(FOLDERID_ProgramData) failed with HRESULT 0x{status:08x}");
    }
    ensure!(
        !raw_path.is_null(),
        "Windows returned an empty ProgramData path"
    );

    let mut length = 0_usize;
    while unsafe { *raw_path.add(length) } != 0 {
        length += 1;
    }
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw_path, length)
    }));
    unsafe {
        CoTaskMemFree(raw_path.cast());
    }
    ensure!(
        path.is_absolute(),
        "Windows returned a relative ProgramData path"
    );
    Ok(path)
}

fn secure_cache_directory(path: &Path, descriptor: &SecurityDescriptor) -> Result<()> {
    let encoded = wide(path.as_os_str());
    let attributes = descriptor.attributes();
    let created = unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) };
    if created == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error).with_context(|| {
                format!("failed to create secure Wintun cache at {}", path.display())
            });
        }
    }

    let directory = open_directory_with_access(
        path,
        FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
        FILE_SHARE_READ,
    )
    .with_context(|| format!("failed to inspect Wintun cache at {}", path.display()))?;
    validate_directory(&directory, path)?;
    descriptor
        .apply_to_handle(directory.as_raw_handle())
        .context("administrator privileges are required to secure the Wintun cache")?;
    drop(directory);
    Ok(())
}

fn stage_fresh_image(
    bundled_path: &Path,
    cache_directory: &Path,
    descriptor: &SecurityDescriptor,
) -> Result<StagedImage> {
    let mut bundled =
        open_file(bundled_path, GENERIC_READ, FILE_SHARE_READ).with_context(|| {
            format!(
                "failed to open bundled Wintun image at {}",
                bundled_path.display()
            )
        })?;
    validate_regular_file(&bundled, bundled_path)?;
    verify_sha256(&mut bundled, bundled_path)?;

    let cache_path = cache_directory.join(format!(
        "wintun-{EXPECTED_SHA256}-{:032x}.dll",
        random::<u128>()
    ));
    let mut cached = create_secure_file(&cache_path, descriptor).with_context(|| {
        format!(
            "failed to create cached Wintun image at {}",
            cache_path.display()
        )
    })?;
    let staged_image = StagedImage::new(cache_path.clone());
    bundled.seek(SeekFrom::Start(0))?;
    let copied = std::io::copy(&mut bundled, &mut cached)
        .context("failed to copy Wintun into its secure cache")?;
    ensure!(
        copied == EXPECTED_LENGTH,
        "copied {copied} bytes of Wintun; expected {EXPECTED_LENGTH}"
    );
    cached
        .flush()
        .context("failed to flush the cached Wintun image")?;
    cached
        .sync_all()
        .context("failed to persist the cached Wintun image")?;
    verify_sha256(&mut cached, &cache_path)?;
    drop(cached);
    Ok(staged_image)
}

struct StagedImage {
    path: PathBuf,
    remove_on_drop: bool,
}

impl StagedImage {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            remove_on_drop: true,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn keep(&mut self) {
        self.remove_on_drop = false;
    }
}

impl Drop for StagedImage {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn create_secure_file(path: &Path, descriptor: &SecurityDescriptor) -> Result<File> {
    let encoded = wide(path.as_os_str());
    let attributes = descriptor.attributes();
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            null_mut(),
        )
    };
    file_from_handle(handle)
}

fn open_file(path: &Path, access: u32, share: u32) -> Result<File> {
    let encoded = wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            null_mut(),
        )
    };
    file_from_handle(handle)
}

fn open_directory(path: &Path, share: u32) -> Result<File> {
    open_directory_with_access(path, FILE_READ_ATTRIBUTES, share)
}

fn open_directory_with_access(path: &Path, access: u32, share: u32) -> Result<File> {
    let encoded = wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    file_from_handle(handle)
}

fn file_from_handle(handle: HANDLE) -> Result<File> {
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("CreateFileW failed");
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn validate_regular_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "{} must not be a reparse point",
        path.display()
    );
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    ensure!(
        metadata.len() == EXPECTED_LENGTH,
        "{} has unexpected length {}; expected {EXPECTED_LENGTH}",
        path.display(),
        metadata.len()
    );
    let file_type = unsafe { GetFileType(file.as_raw_handle()) };
    ensure!(
        file_type == FILE_TYPE_DISK,
        "{} is not a disk file",
        path.display()
    );
    Ok(())
}

fn validate_directory(directory: &File, path: &Path) -> Result<()> {
    let metadata = directory
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "{} must not be a reparse point",
        path.display()
    );
    ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0,
        "{} is not a directory",
        path.display()
    );
    let file_type = unsafe { GetFileType(directory.as_raw_handle()) };
    ensure!(
        file_type == FILE_TYPE_DISK,
        "{} is not a disk directory",
        path.display()
    );
    validate_secure_volume(directory, path)?;
    Ok(())
}

fn validate_secure_volume(directory: &File, path: &Path) -> Result<()> {
    let mut filesystem_flags = 0_u32;
    let volume_read = unsafe {
        GetVolumeInformationByHandleW(
            directory.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut filesystem_flags,
            null_mut(),
            0,
        )
    };
    if volume_read == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!("failed to inspect the volume containing {}", path.display())
        });
    }
    ensure!(
        filesystem_flags & FILE_PERSISTENT_ACLS != 0,
        "{} is on a volume without persistent ACLs",
        path.display()
    );

    let canonical_path = final_path(directory)?;
    let encoded_path = wide(canonical_path.as_os_str());
    let mut volume_path = vec![0_u16; 32_768];
    let path_read = unsafe {
        GetVolumePathNameW(
            encoded_path.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    };
    if path_read == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to locate the volume containing {}", path.display()));
    }
    ensure!(
        unsafe { GetDriveTypeW(volume_path.as_ptr()) } == DRIVE_FIXED,
        "{} is not on a fixed local volume",
        path.display()
    );
    Ok(())
}

fn validate_locked_wintun(file: &mut File, path: &Path) -> Result<()> {
    validate_regular_file(file, path)?;
    verify_sha256(file, path)?;
    let publisher = verify_authenticode(file, path)?;
    ensure!(
        publisher == EXPECTED_PUBLISHER,
        "{} is signed by {publisher:?}, not {EXPECTED_PUBLISHER:?}",
        path.display()
    );
    Ok(())
}

fn verify_sha256(file: &mut File, path: &Path) -> Result<()> {
    let actual = sha256_hex(file)?;
    ensure!(
        actual == EXPECTED_SHA256,
        "{} has unexpected SHA-256 {actual}; expected {EXPECTED_SHA256}",
        path.display()
    );
    Ok(())
}

fn sha256_hex(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0))?;
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(encoded)
}

fn verify_authenticode(file: &File, path: &Path) -> Result<String> {
    let encoded = wide(path.as_os_str());
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: encoded.as_ptr(),
        hFile: file.as_raw_handle(),
        pgKnownSubject: null_mut(),
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: null_mut(),
        pwszURLReference: null_mut(),
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4 | WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: null_mut(),
    };
    let mut policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &mut policy,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        )
    };
    let verification_result = if status == ERROR_SUCCESS as i32 {
        authenticode_publisher(&trust_data)
    } else {
        Err(anyhow!(
            "{} failed Authenticode verification with status 0x{:08x}",
            path.display(),
            status as u32
        ))
    };

    if !trust_data.hWVTStateData.is_null() {
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                null_mut(),
                &mut policy,
                (&mut trust_data as *mut WINTRUST_DATA).cast(),
            );
        }
    }
    verification_result
}

fn authenticode_publisher(trust_data: &WINTRUST_DATA) -> Result<String> {
    let provider = unsafe { WTHelperProvDataFromStateData(trust_data.hWVTStateData) };
    ensure!(
        !provider.is_null(),
        "WinVerifyTrust returned no provider state"
    );
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    ensure!(
        !signer.is_null(),
        "WinVerifyTrust returned no primary signer"
    );
    let certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    ensure!(
        !certificate.is_null(),
        "WinVerifyTrust returned no signer certificate"
    );
    let certificate_context = unsafe { (*certificate).pCert };
    ensure!(
        !certificate_context.is_null(),
        "WinVerifyTrust returned an empty signer certificate"
    );
    certificate_name(certificate_context)
}

fn certificate_name(certificate: *const CERT_CONTEXT) -> Result<String> {
    let name_length = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            null(),
            null_mut(),
            0,
        )
    };
    ensure!(
        name_length > 1,
        "the Authenticode signer has no display name"
    );
    let mut name = vec![0_u16; name_length as usize];
    let copied = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            null(),
            name.as_mut_ptr(),
            name_length,
        )
    };
    ensure!(
        copied == name_length,
        "failed to read the Authenticode signer name"
    );
    String::from_utf16(&name[..name.len() - 1])
        .map_err(|error| anyhow!("the Authenticode signer name is invalid UTF-16: {error}"))
}

fn final_path(file: &File) -> Result<PathBuf> {
    let handle = file.as_raw_handle();
    let required = unsafe { GetFinalPathNameByHandleW(handle, null_mut(), 0, 0) };
    if required == 0 {
        return Err(std::io::Error::last_os_error()).context("GetFinalPathNameByHandleW failed");
    }
    let mut encoded = vec![0_u16; required as usize + 1];
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, encoded.as_mut_ptr(), encoded.len() as u32, 0) };
    if length == 0 || length as usize >= encoded.len() {
        return Err(std::io::Error::last_os_error())
            .context("GetFinalPathNameByHandleW returned an invalid path");
    }
    Ok(PathBuf::from(OsString::from_wide(
        &encoded[..length as usize],
    )))
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

    use super::{VerifiedWintun, restrict_process_dll_search_to_system32, wide};

    static CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn excludes_the_application_directory_from_default_dll_resolution() {
        let _test_lock = CACHE_TEST_LOCK
            .lock()
            .expect("cache test lock was poisoned");
        let fixture = PathBuf::from(
            std::env::var_os("SSHPORTAL_REJECTED_WINTUN_DLL")
                .expect("SSHPORTAL_REJECTED_WINTUN_DLL must name the compiled regression fixture"),
        );
        let marker = PathBuf::from(
            std::env::var_os("SSHPORTAL_REJECTED_WINTUN_MARKER")
                .expect("SSHPORTAL_REJECTED_WINTUN_MARKER must name the DllMain marker"),
        );
        let executable = std::env::current_exe().expect("failed to locate the test executable");
        let application_directory = executable
            .parent()
            .expect("the test executable has no containing directory");
        let probe_path = application_directory.join("sshportal-dll-search-probe.dll");
        if marker.exists() {
            std::fs::remove_file(&marker).expect("failed to remove stale DllMain marker");
        }
        if probe_path.exists() {
            std::fs::remove_file(&probe_path).expect("failed to remove stale DLL search probe");
        }
        std::fs::copy(&fixture, &probe_path)
            .expect("failed to plant the DLL search regression fixture");

        restrict_process_dll_search_to_system32()
            .expect("failed to restrict default DLL resolution");
        let encoded = wide("sshportal-dll-search-probe.dll");
        let module = unsafe { LoadLibraryW(encoded.as_ptr()) };
        if !module.is_null() {
            unsafe {
                FreeLibrary(module);
            }
        }
        std::fs::remove_file(&probe_path).expect("failed to remove the DLL search probe");

        assert!(
            module.is_null(),
            "LoadLibraryW resolved a basename-only DLL from outside System32"
        );
        assert!(
            !marker.exists(),
            "the application-directory DLL search probe executed DllMain"
        );
    }

    #[test]
    fn rejects_untrusted_dll_without_executing_dll_main() {
        let _test_lock = CACHE_TEST_LOCK
            .lock()
            .expect("cache test lock was poisoned");
        let fixture = PathBuf::from(
            std::env::var_os("SSHPORTAL_REJECTED_WINTUN_DLL")
                .expect("SSHPORTAL_REJECTED_WINTUN_DLL must name the compiled regression fixture"),
        );
        let marker = PathBuf::from(
            std::env::var_os("SSHPORTAL_REJECTED_WINTUN_MARKER")
                .expect("SSHPORTAL_REJECTED_WINTUN_MARKER must name the DllMain marker"),
        );
        if marker.exists() {
            std::fs::remove_file(&marker).expect("failed to remove stale DllMain marker");
        }

        let error =
            VerifiedWintun::prepare(&fixture).expect_err("an untrusted DLL must be rejected");

        assert!(format!("{error:#}").contains("unexpected"));
        assert!(
            !marker.exists(),
            "the rejected DLL executed DllMain before validation"
        );
    }

    #[test]
    fn loads_the_exact_verified_image_while_it_is_locked() {
        let _test_lock = CACHE_TEST_LOCK
            .lock()
            .expect("cache test lock was poisoned");
        let trusted = PathBuf::from(
            std::env::var_os("SSHPORTAL_TRUSTED_WINTUN_DLL")
                .expect("SSHPORTAL_TRUSTED_WINTUN_DLL must name the bundled Wintun DLL"),
        );
        let verified = VerifiedWintun::prepare(&trusted).expect("trusted Wintun was rejected");
        let cached_path = verified.path().to_path_buf();
        let encoded = wide(verified.path().as_os_str());

        let module = unsafe { LoadLibraryW(encoded.as_ptr()) };
        assert!(
            !module.is_null(),
            "LoadLibraryW could not load the verified, locked Wintun image: {}",
            std::io::Error::last_os_error()
        );
        unsafe {
            FreeLibrary(module);
        }
        drop(verified);

        assert!(
            !cached_path.exists(),
            "the private Wintun cache image was not removed after unloading"
        );
    }
}
