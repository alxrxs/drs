#!/bin/bash
# Create a drs instance's own keys in <dir> (default /etc/drs), once: a re-run
# never replaces one, since devices hold certificates from the issuer and
# tokens are checked against the signing key.
#   issuer.key/.pem   the DRS issuer: signs device certificates and the pctx
#   signing.key/.pem  signs the tokens drs issues (and only drs checks)
#   state.key         32 random bytes, base64: seals PRTs, nonces and codes
#
# HOW TO RUN (as root): deploy/keys.sh "<issuer name>" [<dir>]   e.g. "MS-Organization-Access EXAMPLE" /etc/drs/example
set -euo pipefail
D=${2:-/etc/drs}
name=${1:?usage: keys.sh <issuer name> [dir]}
umask 077
mkdir -p $D

new_ca() {  # <file stem> <CN> <days>
    [ -e "$D/$1.key" ] && { echo "$1: kept"; return; }
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days "$3" -subj "/CN=$2" \
        -addext "basicConstraints=critical,CA:true,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
        -keyout "$D/$1.key" -out "$D/$1.pem" 2>/dev/null
    echo "$1: created"
}
new_ca issuer "$name" 7300
new_ca signing "$name token signing" 7300
if [ ! -e $D/state.key ]; then
    head -c 32 /dev/urandom | base64 > $D/state.key
    echo "state: created"
fi
chown -R root:drs $D
chmod 0750 $D
chmod 0640 $D/*.key $D/state.key
chmod 0644 $D/*.pem
