ARG SSHPORTAL_IMAGE=sshportal:e2e
FROM ${SSHPORTAL_IMAGE} AS sshportal

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash \
        ca-certificates \
        dbus \
        iproute2 \
        netcat-openbsd \
        systemd-resolved \
        wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=sshportal /usr/local/bin/sshportal-server /usr/local/bin/sshportal-server
COPY tools/vpn_e2e_server_entrypoint.sh /usr/local/bin/vpn-e2e-server-entrypoint

RUN chmod 0755 /usr/local/bin/vpn-e2e-server-entrypoint

WORKDIR /support-workspace
ENTRYPOINT ["/usr/local/bin/vpn-e2e-server-entrypoint"]
