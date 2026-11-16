#!/bin/bash
# Install drs on a Debian/Ubuntu host, as root, from this checkout. Safe to re-run.
#
#   - the packages it needs, a system user drs, the code in /opt/drs;
#   - drs's own keys in /etc/drs/<instance>/ (created once, never replaced);
#   - /etc/drs/<instance>.toml from drs.example.toml, with the host name and
#     paths filled in (an existing one is kept);
#   - the systemd unit drs@.service;
# then lists the files still missing before `systemctl enable --now drs@<instance>`.
#
# Usage: deploy/install.sh <instance> <drs host>     e.g. deploy/install.sh example adfs.example.test
set -euo pipefail
[ $# -eq 2 ] || { sed -n '11p' "$0" >&2; exit 2; }
instance=$1 host=$2
src=$(cd "$(dirname "$0")/.." && pwd)
etc=/etc/drs/$instance
conf=/etc/drs/$instance.toml

apt-get install -y -q python3 python3-cryptography python3-ldap3 python3-gssapi >/dev/null
id drs >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin drs
if [ "$src" != /opt/drs ]; then
    install -d -m 0755 /opt/drs
    cp -r "$src/drs" "$src/deploy" "$src/drs.example.toml" /opt/drs/
fi
echo "code in /opt/drs"

bash /opt/drs/deploy/keys.sh "MS-Organization-Access ${instance^^}" "$etc"

if [ ! -e "$conf" ]; then
    sed -e "s|adfs.example.test|$host|" -e "s|/etc/drs/|$etc/|" /opt/drs/drs.example.toml > "$conf"
    chown root:drs "$conf"; chmod 0640 "$conf"
    echo "config: $conf created; set the [ldap] and [keycloak] values for your domain"
else
    echo "config: $conf kept"
fi

install -m 0644 /opt/drs/deploy/drs@.service /etc/systemd/system/drs@.service
[ -d /run/systemd/system ] && systemctl daemon-reload

missing=0
echo "files drs reads (each mode 0640 or tighter, group drs):"
for f in $(python3 - "$conf" <<'EOF'
import sys, tomllib
c = tomllib.load(open(sys.argv[1], "rb"))
for section in c.values():
    for key, value in section.items():
        if isinstance(value, str) and value.startswith("/"):
            print(value)
EOF
); do
    if [ -e "$f" ]; then echo "  ok       $f"; else echo "  MISSING  $f"; missing=1; fi
done
if [ $missing = 0 ]; then
    echo "Ready: systemctl enable --now drs@$instance"
else
    echo "Add the missing files (the TLS certificate and key, the AD CA, the keytab, the LDAP and Keycloak secrets), then: systemctl enable --now drs@$instance"
fi
