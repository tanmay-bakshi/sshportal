# SSHPortal ipstack package

This directory contains the `ipstack` 1.0.1 library source under its upstream Apache 2.0 license.

- Crates.io archive SHA-256: `e889a45c1ce3e97268ad2249951528563ec1d02a120fecbd4db690beac34f7fd`
- Upstream Git revision: `a343ea8c696e761acce8dbcd6687c862ecd8aacd`

SSHPortal carries two integration changes in this package:

- TCP active shutdown registers a current task waker and wakes it when the final in-flight bytes are acknowledged. This guarantees that close-delimited responses emit a FIN promptly instead of leaving the virtual peer connected indefinitely.
- The upstream Windows build script and in-source Criterion benchmark harness are omitted. They package a Wintun DLL for upstream examples and rely on development-only dependencies that are not part of the published library.

SSHPortal packages the Wintun DLL used by its `tun` dependency explicitly in its Windows release build.
