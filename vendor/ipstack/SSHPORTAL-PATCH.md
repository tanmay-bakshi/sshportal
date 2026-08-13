# SSHPortal ipstack package

This directory contains the `ipstack` 1.0.1 library source under its upstream Apache 2.0 license.

- Crates.io archive SHA-256: `e889a45c1ce3e97268ad2249951528563ec1d02a120fecbd4db690beac34f7fd`
- Upstream Git revision: `a343ea8c696e761acce8dbcd6687c862ecd8aacd`

The upstream package runs a build script for every Windows target solely to copy a Wintun DLL for its own examples. That script searches for an upstream-only development dependency and therefore cannot run when `ipstack` is consumed through a macOS-to-Windows cross-build. The library itself has no generated code or other build-time requirements, so this package intentionally excludes that example-packaging script and its development dependencies. The remaining source differs only in whitespace cleanup and equivalent Markdown heading syntax.

SSHPortal packages the Wintun DLL used by its `tun` dependency explicitly in its Windows release build.
