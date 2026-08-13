#!/bin/bash

set -euo pipefail

repository_root="$(cd "$(dirname "$0")/../.." && pwd)"
mode="${1:---unsigned}"
package_directory="$repository_root/target/sshportal-macos-universal"
archive_path="$repository_root/target/sshportal-macos-universal.zip"
checksum_path="$archive_path.sha256"

case "$mode" in
  --unsigned)
    signing_arguments=(CODE_SIGNING_ALLOWED=NO)
    derived_data="$repository_root/target/macos-package-unsigned-derived"
    ;;
  --developer-id)
    : "${SSHPORTAL_APP_PROFILE:?Set SSHPORTAL_APP_PROFILE to the containing app Developer ID provisioning profile name.}"
    : "${SSHPORTAL_EXTENSION_PROFILE:?Set SSHPORTAL_EXTENSION_PROFILE to the app proxy Developer ID provisioning profile name.}"
    : "${SSHPORTAL_DEVELOPMENT_TEAM:?Set SSHPORTAL_DEVELOPMENT_TEAM to the paid Apple Developer team ID.}"
    signing_identity="${SSHPORTAL_DEVELOPER_IDENTITY:-Developer ID Application}"
    signing_arguments=(
      "CODE_SIGN_IDENTITY=$signing_identity"
      "DEVELOPMENT_TEAM=$SSHPORTAL_DEVELOPMENT_TEAM"
      "SSHPORTAL_APP_PROFILE=$SSHPORTAL_APP_PROFILE"
      "SSHPORTAL_EXTENSION_PROFILE=$SSHPORTAL_EXTENSION_PROFILE"
    )
    derived_data="$repository_root/target/macos-package-developer-id-derived"
    ;;
  *)
    echo "usage: $0 [--unsigned|--developer-id]" >&2
    exit 2
    ;;
esac

mkdir -p "$repository_root/target"

cargo build \
  --manifest-path "$repository_root/Cargo.toml" \
  --locked \
  --release \
  --target aarch64-apple-darwin \
  --bins
cargo build \
  --manifest-path "$repository_root/Cargo.toml" \
  --locked \
  --release \
  --target x86_64-apple-darwin \
  --bins

xcodebuild \
  -project "$repository_root/macos/SSHPortal.xcodeproj" \
  -scheme SSHPortal \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -derivedDataPath "$derived_data" \
  -quiet \
  ARCHS='arm64 x86_64' \
  ONLY_ACTIVE_ARCH=NO \
  "${signing_arguments[@]}" \
  build

staging_directory="$(mktemp -d "$repository_root/target/.sshportal-macos-universal.XXXXXX")"
trap 'rm -rf "$staging_directory"' EXIT

for binary in sshportal-client sshportal-server; do
  lipo -create \
    "$repository_root/target/aarch64-apple-darwin/release/$binary" \
    "$repository_root/target/x86_64-apple-darwin/release/$binary" \
    -output "$staging_directory/$binary"
  strip -S "$staging_directory/$binary"
  lipo "$staging_directory/$binary" -verify_arch arm64
  lipo "$staging_directory/$binary" -verify_arch x86_64
done

ditto \
  "$derived_data/Build/Products/Release/SSHPortal.app" \
  "$staging_directory/SSHPortal.app"
install -m 0644 "$repository_root/README.md" "$repository_root/LICENSE" "$staging_directory/"

companion_executable="$staging_directory/SSHPortal.app/Contents/MacOS/SSHPortal"
extension_bundle="$staging_directory/SSHPortal.app/Contents/Library/SystemExtensions/SSHPortalAppProxy.systemextension"
extension_executable="$extension_bundle/Contents/MacOS/SSHPortalAppProxy"
lipo "$companion_executable" -verify_arch arm64
lipo "$companion_executable" -verify_arch x86_64
lipo "$extension_executable" -verify_arch arm64
lipo "$extension_executable" -verify_arch x86_64

if [[ "$mode" == "--developer-id" ]]; then
  for binary in sshportal-client sshportal-server; do
    codesign \
      --force \
      --options runtime \
      --timestamp \
      --sign "$signing_identity" \
      "$staging_directory/$binary"
    codesign --verify --strict --verbose=2 "$staging_directory/$binary"
  done
  codesign --verify --strict --verbose=2 "$extension_bundle"
  codesign --verify --deep --strict --verbose=2 "$staging_directory/SSHPortal.app"
fi

case "$package_directory" in
  "$repository_root"/target/*) ;;
  *)
    echo "refusing to replace unexpected package path: $package_directory" >&2
    exit 1
    ;;
esac
rm -rf "$package_directory"
mv "$staging_directory" "$package_directory"
trap - EXIT

rm -f "$archive_path"
ditto -c -k --sequesterRsrc --keepParent "$package_directory" "$archive_path"

if [[ "$mode" == "--developer-id" && -n "${SSHPORTAL_NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit \
    "$archive_path" \
    --keychain-profile "$SSHPORTAL_NOTARY_PROFILE" \
    --wait
  xcrun stapler staple "$package_directory/SSHPortal.app"
  rm -f "$archive_path"
  ditto -c -k --sequesterRsrc --keepParent "$package_directory" "$archive_path"
  spctl --assess --type execute --verbose=2 "$package_directory/SSHPortal.app"
fi

archive_hash="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
printf '%s  %s\n' "$archive_hash" "$(basename "$archive_path")" > "$checksum_path"

echo "macOS package: $package_directory"
echo "macOS archive: $archive_path"
echo "macOS checksum: $checksum_path"
