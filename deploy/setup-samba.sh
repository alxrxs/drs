#!/bin/bash
# Prepare a Samba AD domain for drs, on a Samba DC, as root. Safe to re-run.
#
# Creates, or leaves alone when they exist: the service account (svc-drs) with
# the SPN HTTP/<drs host>; CN=RegisteredDevices and the device registration
# service connection point that sends domain-joined PCs to the drs host; the
# group of users allowed to set up Hello; and exactly three rights for the
# account (write msDS-KeyCredentialLink on the users below the users' OU, and
# create, manage and delete msDS-Device objects in RegisteredDevices; never
# Key Admins). Then writes the account's keytab for drs.
#
# Usage: setup-samba.sh --host adfs.example.test --users-ou "OU=People,DC=example,DC=test"
#            [--account svc-drs] [--enrol-group WHfB-Enrol] [--keytab ./http.keytab]
set -euo pipefail

account=svc-drs group=WHfB-Enrol keytab=./http.keytab host='' users_ou=''
while [ $# -gt 0 ]; do
    case $1 in
        --host) host=$2 ;;
        --users-ou) users_ou=$2 ;;
        --account) account=$2 ;;
        --enrol-group) group=$2 ;;
        --keytab) keytab=$2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
    shift 2
done
[ -n "$host" ] && [ -n "$users_ou" ] || { sed -n '12,13p' "$0" >&2; exit 2; }

ST=samba-tool
SAM=/var/lib/samba/private/sam.ldb
base=$(ldbsearch -H $SAM -s base -b '' defaultNamingContext | awk '/^defaultNamingContext:/ {print $2}')
config="CN=Configuration,$base"
exists() { ldbsearch -H $SAM -b "$1" -s base dn 2>/dev/null | grep -q '^dn:'; }
step() { echo "  $*"; }
echo "drs: preparing $base for $host"

if ! $ST user show "$account" >/dev/null 2>&1; then
    read -rsp "Password for the new account $account (drs's LDAP bind): " pw; echo
    $ST user create "$account" "$pw" >/dev/null
    unset pw
    step "created $account"
else
    step "$account exists"
fi
$ST user setexpiry "$account" --noexpiry >/dev/null
if ! $ST spn list "$account" | grep -q "HTTP/$host"; then
    $ST spn add "HTTP/$host" "$account"
    step "SPN HTTP/$host added"
else
    step "SPN HTTP/$host exists"
fi

exists "CN=RegisteredDevices,$base" || { ldbadd -H $SAM >/dev/null <<EOF
dn: CN=RegisteredDevices,$base
objectClass: msDS-DeviceContainer
EOF
step "created CN=RegisteredDevices"; }
exists "CN=Device Registration Configuration,CN=Services,$config" || ldbadd -H $SAM >/dev/null <<EOF
dn: CN=Device Registration Configuration,CN=Services,$config
objectClass: container
EOF
scp="CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,$config"
if exists "$scp"; then
    ldbmodify -H $SAM >/dev/null <<EOF
dn: $scp
changetype: modify
replace: keywords
keywords: enterpriseDrsName:$host
EOF
else
    ldbadd -H $SAM >/dev/null <<EOF
dn: $scp
objectClass: serviceConnectionPoint
keywords: enterpriseDrsName:$host
EOF
fi
step "PCs are sent to $host"

if ! $ST group show "$group" >/dev/null 2>&1; then
    $ST group add "$group" --groupou="${users_ou%,"$base"}" >/dev/null
    step "created group $group (add the users allowed to set up Hello)"
else
    step "group $group exists"
fi

# The three rights, by schema GUID: msDS-KeyCredentialLink on user objects,
# and msDS-Device objects.
sid=$(ldbsearch -H $SAM "(sAMAccountName=$account)" objectSid | awk '/^objectSid:/ {print $2}')
keylink=5b47d60f-6090-40b2-9f37-2a4de88f3063 user=bf967aba-0de6-11d0-a285-00aa003049e2
device=5df2b673-6d41-4774-b3e8-d52e8ee9ff99
grant() { $ST dsacl get --objectdn="$1" 2>/dev/null | grep -qF "$2" || $ST dsacl set --objectdn="$1" --sddl="$2" >/dev/null; }
grant "$users_ou" "(OA;CIIO;WP;$keylink;$user;$sid)"
grant "CN=RegisteredDevices,$base" "(OA;;CCDC;$device;;$sid)"
grant "CN=RegisteredDevices,$base" "(OA;CIIO;RPWPSD;;$device;$sid)"
step "rights granted (Hello keys below $users_ou, devices in RegisteredDevices)"

rm -f "$keytab"
$ST domain exportkeytab "$keytab" --principal="HTTP/$host" >/dev/null 2>&1
step "keytab written to $keytab"
echo "Done. Copy $keytab to the drs host as /etc/drs/<instance>/http.keytab, and use $account's password in ldap-password."
