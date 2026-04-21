FROM alpine:3.22 AS runtime

ARG TARGETARCH
ARG TARGET_TRIPLE

RUN apk add --no-cache bash ca-certificates

WORKDIR /support-workspace
COPY target /prebuilt-target

RUN set -eux; \
    resolved_target="${TARGET_TRIPLE:-}"; \
    if [ -z "${resolved_target}" ]; then \
        case "${TARGETARCH}" in \
            amd64) resolved_target="x86_64-unknown-linux-musl" ;; \
            arm64) resolved_target="aarch64-unknown-linux-musl" ;; \
            *) echo "unsupported Docker target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
        esac; \
    fi; \
    install -m 0755 "/prebuilt-target/${resolved_target}/release/sshportal-server" /usr/local/bin/sshportal-server; \
    install -m 0755 "/prebuilt-target/${resolved_target}/release/sshportal-client" /usr/local/bin/sshportal-client; \
    rm -rf /prebuilt-target

ENV HOME=/root
ENV SHELL=/bin/bash
ENV TERM=xterm-256color

CMD ["/bin/bash"]
