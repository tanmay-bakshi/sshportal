#!/bin/bash

set -euo pipefail

readonly target="x86_64-pc-windows-msvc"
readonly rust_toolchain="1.91.0"
readonly cargo_xwin_version="0.21.4"

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/.." && pwd)"
readonly wintun_checksum_file="$script_directory/wintun-amd64.sha256"
readonly windows_system_dlls_file="$script_directory/windows-system-dlls.txt"

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

find_llvm_readobj() {
    local candidate
    local homebrew_prefix

    if command -v llvm-readobj >/dev/null 2>&1; then
        command -v llvm-readobj
        return
    fi

    for candidate in \
        /opt/homebrew/opt/llvm/bin/llvm-readobj \
        /usr/local/opt/llvm/bin/llvm-readobj
    do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done

    if command -v brew >/dev/null 2>&1; then
        homebrew_prefix="$(brew --prefix llvm 2>/dev/null || true)"
        candidate="$homebrew_prefix/bin/llvm-readobj"
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    fi

    fail "llvm-readobj was not found; install LLVM with 'brew install llvm'"
}

find_lld_link() {
    local candidate
    local homebrew_prefix

    if command -v lld-link >/dev/null 2>&1; then
        command -v lld-link
        return
    fi

    for candidate in \
        /opt/homebrew/opt/lld/bin/lld-link \
        /usr/local/opt/lld/bin/lld-link
    do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done

    if command -v brew >/dev/null 2>&1; then
        homebrew_prefix="$(brew --prefix lld 2>/dev/null || true)"
        candidate="$homebrew_prefix/bin/lld-link"
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    fi

    fail "lld-link was not found; install LLD with 'brew install lld'"
}

verify_imports() {
    local binary_path="$1"
    local imported_dll
    local imported_dll_lowercase
    local import_names

    "$llvm_readobj" --file-headers "$binary_path" |
        grep -Fq 'Machine: IMAGE_FILE_MACHINE_AMD64' ||
        fail "$binary_path is not an x86-64 PE executable"
    "$llvm_readobj" --coff-load-config "$binary_path" |
        grep -Fq 'DependentLoadFlags: 0x800' ||
        fail "$binary_path does not restrict static imports to System32"

    import_names="$(
        "$llvm_readobj" --coff-imports "$binary_path" |
            sed -n 's/^[[:space:]]*Name: //p'
    )"
    [[ -n "$import_names" ]] || fail "$binary_path has no readable PE import table"

    while IFS= read -r imported_dll; do
        imported_dll_lowercase="$(printf '%s' "$imported_dll" | tr '[:upper:]' '[:lower:]')"
        grep -Fxiq -- "$imported_dll_lowercase" "$windows_system_dlls_file" ||
            fail "$binary_path unexpectedly imports non-system DLL $imported_dll"
    done <<< "$import_names"

    printf '%s\n' "$binary_path imports only Windows system DLLs:"
    printf '%s\n' "$import_names" | sed 's/^/  /'
}

[[ "$(uname -s)" == "Darwin" ]] || fail "this build entrypoint requires macOS"

require_command cargo
require_command cmp
require_command grep
require_command jq
require_command rustup
require_command sed
require_command shasum
require_command tr
require_command zip

[[ -f "$wintun_checksum_file" ]] || fail "Wintun checksum file not found: $wintun_checksum_file"
expected_wintun_sha256="$(sed -n '1{s/[[:space:]].*$//;p;}' "$wintun_checksum_file")"
[[ "$expected_wintun_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    fail "invalid Wintun checksum in $wintun_checksum_file"
readonly expected_wintun_sha256
[[ -f "$windows_system_dlls_file" ]] ||
    fail "Windows system DLL allowlist not found: $windows_system_dlls_file"
grep -Eq '^[a-z0-9_.-]+\.dll$' "$windows_system_dlls_file" ||
    fail "Windows system DLL allowlist is empty or malformed"
if grep -Evq '^[a-z0-9_.-]+\.dll$' "$windows_system_dlls_file"; then
    fail "Windows system DLL allowlist is malformed"
fi

llvm_readobj="$(find_llvm_readobj)"
llvm_directory="$(dirname "$llvm_readobj")"
lld_link="$(find_lld_link)"
lld_directory="$(dirname "$lld_link")"
PATH="$llvm_directory:$lld_directory:$PATH"
export PATH

require_command clang-cl
require_command llvm-lib
require_command lld-link

if ! rustup run "$rust_toolchain" rustc --version >/dev/null 2>&1; then
    fail "Rust $rust_toolchain is not installed; run 'rustup toolchain install $rust_toolchain --profile minimal --target $target'"
fi

if ! rustup target list --toolchain "$rust_toolchain" --installed | grep -Fxq "$target"; then
    fail "Rust target $target is not installed for $rust_toolchain; run 'rustup target add --toolchain $rust_toolchain $target'"
fi

xwin_version_output="$(cargo "+$rust_toolchain" xwin --version 2>/dev/null || true)"
case "$xwin_version_output" in
    *" $cargo_xwin_version")
        ;;
    *)
        fail "cargo-xwin $cargo_xwin_version is required; run 'cargo install --locked --version $cargo_xwin_version cargo-xwin'"
        ;;
esac

cd "$repository_root"

feature_tree="$(
    cargo "+$rust_toolchain" tree \
        --locked \
        --target "$target" \
        --edges features \
        --invert wintun-bindings
)"
printf '%s\n' "$feature_tree"
if grep -Fq 'wintun-bindings feature "verify_binary_signature"' <<< "$feature_tree"; then
    fail "wintun-bindings/verify_binary_signature executes the DLL before verification"
fi

export CARGO_INCREMENTAL=0
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=/ignore:4099"

cargo "+$rust_toolchain" xwin build \
    --locked \
    --release \
    --target "$target" \
    --bins

release_directory="$repository_root/target/$target/release"
client_binary="$release_directory/sshportal-client.exe"
server_binary="$release_directory/sshportal-server.exe"

[[ -f "$client_binary" ]] || fail "build did not produce $client_binary"
[[ -f "$server_binary" ]] || fail "build did not produce $server_binary"

verify_imports "$client_binary"
verify_imports "$server_binary"

metadata="$(
    cargo "+$rust_toolchain" metadata \
        --locked \
        --format-version 1 \
        --filter-platform "$target"
)"

package_version="$(
    jq -er '
        [.packages[] | select(.name == "sshportal")] |
        if length == 1 then .[0].version else error("expected one sshportal package") end
    ' <<< "$metadata"
)"
wintun_manifest="$(
    jq -er '
        [.packages[] | select(.name == "wintun-bindings")] |
        if length == 1 then .[0].manifest_path else error("expected one wintun-bindings package") end
    ' <<< "$metadata"
)"
wintun_binary="$(dirname "$wintun_manifest")/wintun/bin/amd64/wintun.dll"
wintun_license="$(dirname "$wintun_manifest")/wintun/LICENSE.txt"

[[ -f "$wintun_binary" ]] || fail "wintun-bindings did not contain $wintun_binary"
[[ -f "$wintun_license" ]] || fail "wintun-bindings did not contain $wintun_license"
cmp -s <(tr -d '\r' < "$wintun_license") "$repository_root/licenses/WINTUN.txt" ||
    fail "the bundled Wintun redistribution license does not match the pinned DLL"
actual_wintun_sha256="$(shasum -a 256 "$wintun_binary" | sed 's/[[:space:]].*$//')"
if [[ "$actual_wintun_sha256" != "$expected_wintun_sha256" ]]; then
    fail "unexpected Wintun DLL SHA-256: $actual_wintun_sha256"
fi

"$llvm_readobj" --file-headers "$wintun_binary" |
    grep -Fq 'Machine: IMAGE_FILE_MACHINE_AMD64' ||
    fail "$wintun_binary is not an x86-64 PE DLL"

archive_stem="sshportal-v$package_version-$target"
dist_directory="$repository_root/dist"
staging_root="$(mktemp -d -t sshportal-windows-release)"
package_directory="$staging_root/$archive_stem"
temporary_archive="$staging_root/$archive_stem.zip"
archive_path="$dist_directory/$archive_stem.zip"
checksum_path="$archive_path.sha256"

cleanup() {
    rm -rf -- "$staging_root"
}
trap cleanup EXIT

mkdir -p "$package_directory" "$dist_directory"
install -m 0755 "$client_binary" "$package_directory/sshportal-client.exe"
install -m 0755 "$server_binary" "$package_directory/sshportal-server.exe"
install -m 0644 "$wintun_binary" "$package_directory/wintun.dll"
install -m 0644 "$repository_root/README.md" "$package_directory/README.md"
install -m 0644 "$repository_root/LICENSE" "$package_directory/LICENSE"
install -m 0644 "$repository_root/licenses/WINTUN.txt" "$package_directory/WINTUN-LICENSE.txt"

(
    cd "$staging_root"
    COPYFILE_DISABLE=1 zip -q -X -r "$temporary_archive" "$archive_stem"
)

install -m 0644 "$temporary_archive" "$archive_path"
archive_sha256="$(shasum -a 256 "$archive_path" | sed 's/[[:space:]].*$//')"
printf '%s  %s\n' "$archive_sha256" "$(basename "$archive_path")" > "$checksum_path"

printf 'Wintun SHA-256 verified: %s\n' "$actual_wintun_sha256"
printf 'Windows release archive: %s\n' "$archive_path"
printf 'Archive SHA-256: %s\n' "$archive_sha256"
