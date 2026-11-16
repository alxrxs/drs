#!/bin/bash
# Configure a Keycloak realm as drs's second factor, with kcadm.sh. Safe to re-run.
#
#   - LDAP federation to AD (read-only, users named by UPN, objectGUID carried
#     as a claim); with --ldap-provider, an existing federation is used instead;
#   - the drs-mfa flow: password, then a one-time code, never a session cookie;
#   - "Configure OTP" off, so nobody can create a second factor mid-enrolment;
#   - the confidential client drs (PKCE S256, acr drs-mfa), whose secret is
#     written to ./keycloak-secret for drs.
#
# Usage: setup-keycloak.sh --server https://sso.example.test --realm example --drs-host adfs.example.test
#            ( --ldap-provider <name of the realm's existing AD federation>
#            | --ldap-url ldaps://dc1.example.test --users-dn "OU=People,DC=example,DC=test"
#              --bind-dn "CN=svc-keycloak,OU=Service Accounts,DC=example,DC=test" )
#            [--kcadm /opt/keycloak/bin/kcadm.sh] [--admin admin]
# The admin password and the bind password are asked for (or KC_ADMIN_PASSWORD,
# LDAP_BIND_PASSWORD in the environment).
set -euo pipefail

KC=$(command -v kcadm.sh || echo /opt/keycloak/bin/kcadm.sh)
admin=admin server='' R='' host='' provider='' ldap_url='' users_dn='' bind_dn=''
while [ $# -gt 0 ]; do
    case $1 in
        --server) server=$2 ;; --realm) R=$2 ;; --drs-host) host=$2 ;;
        --ldap-provider) provider=$2 ;; --ldap-url) ldap_url=$2 ;;
        --users-dn) users_dn=$2 ;; --bind-dn) bind_dn=$2 ;;
        --kcadm) KC=$2 ;; --admin) admin=$2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
    shift 2
done
usage() { sed -n '11,15p' "$0" >&2; exit 2; }
[ -n "$server" ] && [ -n "$R" ] && [ -n "$host" ] || usage
[ -n "$provider" ] || { [ -n "$ldap_url" ] && [ -n "$users_dn" ] && [ -n "$bind_dn" ]; } || usage
step() { echo "  $*"; }
# kcadm.sh, without its progress lines; real errors still reach stderr.
kc() { "$KC" "$@" 2> >(grep -v -E '^(Created new|Logging into|$)' >&2); }
[ -n "${KC_ADMIN_PASSWORD:-}" ] || { read -rsp "Keycloak password for $admin: " KC_ADMIN_PASSWORD; echo; }
kc config credentials --server "$server" --realm master --user "$admin" --password "$KC_ADMIN_PASSWORD" >/dev/null
echo "drs: configuring realm $R at $server for $host"

kc get "realms/$R" >/dev/null 2>&1 || { kc create realms -s realm="$R" -s enabled=true; step "created realm $R"; }
kc update "authentication/required-actions/CONFIGURE_TOTP" -r "$R" -s enabled=false -s defaultAction=false
step "Configure OTP off"

# LDAP federation: an existing one by name, or a new read-only one.
providers() { kc get components -r "$R" -q type=org.keycloak.storage.UserStorageProvider --fields id,name --format csv --noquotes; }
if [ -n "$provider" ]; then
    ldap=$(providers | awk -F, -v n="$provider" '$2 == n {print $1}')
    [ -n "$ldap" ] || { echo "no federation named $provider in realm $R" >&2; exit 1; }
else
    ldap=$(providers | awk -F, '$2 == "ad" {print $1}')
    if [ -z "$ldap" ]; then
        [ -n "${LDAP_BIND_PASSWORD:-}" ] || { read -rsp "Password for $bind_dn: " LDAP_BIND_PASSWORD; echo; }
        rid=$(kc get "realms/$R" --fields id --format csv --noquotes)
        ldap=$(kc create components -r "$R" -i -s name=ad -s providerId=ldap \
            -s providerType=org.keycloak.storage.UserStorageProvider -s parentId="$rid" \
            -s 'config.vendor=["ad"]' -s 'config.editMode=["READ_ONLY"]' \
            -s "config.connectionUrl=[\"$ldap_url\"]" -s "config.bindDn=[\"$bind_dn\"]" \
            -s "config.bindCredential=[\"$LDAP_BIND_PASSWORD\"]" -s "config.usersDn=[\"$users_dn\"]" \
            -s 'config.usernameLDAPAttribute=["userPrincipalName"]' -s 'config.rdnLDAPAttribute=["cn"]' \
            -s 'config.uuidLDAPAttribute=["objectGUID"]' \
            -s 'config.userObjectClasses=["person, organizationalPerson, user"]' \
            -s 'config.searchScope=["2"]' -s 'config.authType=["simple"]' -s 'config.useTruststoreSpi=["always"]' \
            -s 'config.importEnabled=["true"]' -s 'config.syncRegistrations=["false"]' -s 'config.pagination=["true"]')
        step "created LDAP federation ad"
    fi
fi
# drs sends the UPN as login_hint, so users must be named by it.
umap=$(kc get components -r "$R" -q parent="$ldap" --fields id,name --format csv --noquotes | awk -F, '$2 == "username" {print $1}')
[ -z "$umap" ] || kc update "components/$umap" -r "$R" -s 'config."ldap.attribute"=["userPrincipalName"]'
if ! kc get components -r "$R" -q parent="$ldap" --fields name --format csv --noquotes | grep -qx ad-object-guid; then
    kc create components -r "$R" -s name=ad-object-guid -s providerId=user-attribute-ldap-mapper \
        -s providerType=org.keycloak.storage.ldap.mappers.LDAPStorageMapper -s parentId="$ldap" \
        -s 'config."ldap.attribute"=["objectGUID"]' -s 'config."user.model.attribute"=["ad_object_guid"]' \
        -s 'config."is.binary.attribute"=["true"]' -s 'config."read.only"=["true"]' \
        -s 'config."always.read.value.from.ldap"=["true"]' -s 'config."is.mandatory.in.ldap"=["false"]'
fi
kc create "user-storage/$ldap/sync?action=triggerFullSync" -r "$R" >/dev/null
step "users federated from AD, named by UPN, objectGUID mapped"

# The step-up flow: level 1 the password, level 2 a one-time code.
if ! kc get authentication/flows -r "$R" --fields alias --format csv --noquotes | grep -qx drs-mfa; then
    kc create authentication/flows -r "$R" -s alias=drs-mfa -s providerId=basic-flow -s topLevel=true \
        -s builtIn=false -s description="drs: password, then a one-time code; never a cookie"
    for level in 1 2; do
        kc create authentication/flows/drs-mfa/executions/flow -r "$R" -s alias="drs-level-$level" \
            -s type=basic-flow -s provider=registration-page-form >/dev/null
    done
    kc create authentication/flows/drs-level-1/executions/execution -r "$R" -s provider=conditional-level-of-authentication
    kc create authentication/flows/drs-level-1/executions/execution -r "$R" -s provider=auth-username-password-form
    kc create authentication/flows/drs-level-2/executions/execution -r "$R" -s provider=conditional-level-of-authentication
    kc create authentication/flows/drs-level-2/executions/execution -r "$R" -s provider=auth-otp-form
fi
kc get authentication/flows/drs-mfa/executions -r "$R" | python3 -c '
import json, subprocess, sys
kc, realm = sys.argv[1], sys.argv[2]
level = 0
for e in json.load(sys.stdin):
    req = "CONDITIONAL" if e.get("displayName", "").startswith("drs-level-") else "REQUIRED"
    subprocess.run([kc, "update", "authentication/flows/drs-mfa/executions", "-r", realm, "-f", "-"],
                   input=json.dumps(dict(e, requirement=req)), text=True, check=True, capture_output=True)
    if e.get("providerId") == "conditional-level-of-authentication":
        level += 1
        if not e.get("authenticationConfig"):
            eid = e["id"]
            cfg = {"alias": f"drs-loa-{level}", "config": {"loa-condition-level": str(level), "loa-max-age": "0"}}
            subprocess.run([kc, "create", f"authentication/executions/{eid}/config", "-r", realm, "-f", "-"],
                           input=json.dumps(cfg), text=True, check=True, capture_output=True)
' "$KC" "$R"
step "flow drs-mfa: password, then a one-time code, no cookie"

# The client.
cid=$(kc get clients -r "$R" -q clientId=drs --fields id --format csv --noquotes)
if [ -z "$cid" ]; then
    cid=$(kc create clients -r "$R" -i -s clientId=drs -s protocol=openid-connect -s publicClient=false \
        -s standardFlowEnabled=true -s directAccessGrantsEnabled=false -s serviceAccountsEnabled=false)
    step "created client drs"
fi
flow=$(kc get authentication/flows -r "$R" --fields id,alias --format csv --noquotes | awk -F, '$2 == "drs-mfa" {print $1}')
kc update "clients/$cid" -r "$R" -s "redirectUris=[\"https://$host/adfs/drs/keycloak\"]" \
    -s 'attributes."pkce.code.challenge.method"=S256' \
    -s 'attributes."acr.loa.map"="{\"drs-mfa\":\"2\"}"' -s 'attributes."minimum.acr.value"=drs-mfa' \
    -s "authenticationFlowBindingOverrides.browser=$flow"
if ! kc get "clients/$cid/protocol-mappers/models" -r "$R" --fields name --format csv --noquotes | grep -qx ad-object-guid; then
    kc create "clients/$cid/protocol-mappers/models" -r "$R" -s name=ad-object-guid -s protocol=openid-connect \
        -s protocolMapper=oidc-usermodel-attribute-mapper \
        -s 'config."user.attribute"=ad_object_guid' -s 'config."claim.name"=ad_object_guid' \
        -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=false' -s 'config."jsonType.label"=String'
fi
(umask 077; kc get "clients/$cid/client-secret" -r "$R" --fields value --format csv --noquotes > keycloak-secret)
step "client drs: PKCE S256, acr drs-mfa, secret written to ./keycloak-secret"
echo "Done. Issuer for drs.toml: $server/realms/$R"
