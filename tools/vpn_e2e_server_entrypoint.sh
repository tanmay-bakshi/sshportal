#!/bin/bash

set -euo pipefail

physical_dns="$(awk '/^nameserver / { print $2; exit }' /etc/resolv.conf)"
physical_interface="$(ip route show default | awk 'NR == 1 { for (field = 1; field <= NF; field++) { if ($field == "dev") { print $(field + 1); exit } } }')"

if [[ -z "${physical_dns}" || -z "${physical_interface}" ]]; then
    echo "failed to discover the container's physical DNS path" >&2
    exit 1
fi

mkdir -p /run/dbus /run/systemd/resolve
chown systemd-resolve:systemd-resolve /run/systemd/resolve
dbus-uuidgen --ensure=/etc/machine-id
dbus-daemon --system --fork
/usr/lib/systemd/systemd-resolved &

resolved_ready=false
for _ in {1..100}; do
    if resolvectl status >/dev/null 2>&1; then
        resolved_ready=true
        break
    fi
    sleep 0.05
done
if [[ "${resolved_ready}" != true ]]; then
    echo "systemd-resolved did not become ready" >&2
    exit 1
fi

resolvectl dns "${physical_interface}" "${physical_dns}"
resolvectl default-route "${physical_interface}" true
printf 'nameserver 127.0.0.53\noptions edns0 trust-ad\n' > /etc/resolv.conf
touch /run/sshportal-vpn-e2e-ready

exec "$@"
