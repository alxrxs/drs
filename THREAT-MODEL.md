# Threat model

drs can add a sign-in key to any account it may write: the "shadow credentials" power. Whoever controls it can sign in as those accounts. Everything below is about keeping that set small and noticing when it is used.

## What drs holds, and what each gives an attacker

| Asset | Where | What it gives | How it is contained |
|---|---|---|---|
| **The drs host** (root) | the service's VM or container | everything below, plus the LDAP account: a Hello key on any user in the Hello users' OU, and any device object | The account's rights are three ACEs (below), so the blast radius is the Hello users' OU, never admins (keep them out of that OU and out of `AdminSDHolder`'s reach: protected accounts lose inherited ACEs anyway), never DCs. Host hardening: one process, a dedicated user, the systemd sandbox in `deploy/drs@.service`, nothing else listening. Alerting on every key write (below) makes misuse loud. |
| **The LDAP service account's password** | `/etc/drs/<instance>/ldap-password` | the same directory rights, from anywhere that reaches a DC | The same three ACEs; rotate it like any service password (drs reads it at start). |
| **The token-signing key** | `/etc/drs/<instance>/signing.key` | forge drs's own tokens: a domain-join token (register a device for any computer account) or an `ngcmfa` access token for any user, so a Hello key for any user **drs may write**, without the second factor | drs is the only party that checks these tokens: the key cannot be used against anything else. It still gives "skip Keycloak", so it is file-mode 0640 root:drs and never leaves the host. Rotate by replacing the pair and restarting; tokens live five minutes, so nothing else needs re-issuing. |
| **The DRS issuer key** | `/etc/drs/<instance>/issuer.key` | issue device certificates: present one as a "registered device" | A certificate drs accepts must also match a registered device's `altSecurityIdentities` in AD, which only drs (or a directory admin) writes, so the issuer key alone opens nothing. It also signs the `pctx`, which clients store and never verify. Rotating it needs no re-registration: devices are found by their certificate's hash, not by its issuer. |
| **The state key** | `/etc/drs/<instance>/state.key` | open or forge PRTs, nonces and authorization codes; a forged code is an `ngcmfa` token without the second factor | Same files and mode as the signing key. Rotating it invalidates every PRT, which Windows renews at the next sign-in. |
| **The Keycloak client secret** | `/etc/drs/<instance>/keycloak-secret` | redeem codes Keycloak issued to drs | Only codes from a sign-in that passed the drs-mfa flow, for the user who signed in, within two minutes; PKCE binds each to drs's request. |
| **The keytab** | `/etc/drs/<instance>/http.keytab` | impersonate drs to Kerberos clients (`HTTP/<host>`) | Domain-join tokens only; the join writes a device object, never a user key. AES only. |

## What is never trusted from the client

- **Who the user is.** The UPN in the PRT comes from an LDAP bind as that user (the password Windows relays at sign-in). The UPN in the `ngcmfa` token comes from that PRT, and Keycloak must prove the same account (`objectGUID` claim equal to the enrolling user's). No request field names the user for a key write.
- **Who the device is.** The device ID is the computer account's objectGUID from a Kerberos-authenticated join, and later the device certificate's hash as recorded in AD.
- **The second factor.** Keycloak's ID token is checked for signature, issuer, audience, nonce, `auth_time` within two minutes, and the `acr` the step-up flow sets; a Kerberos ticket or a Keycloak session cookie never satisfies it.
- **The allow-list.** Membership of the enrolment group (nested) is checked at `/authorize`, before Keycloak, and again at the key write.

## Directory rights (the exact ACEs)

1. On the Hello users' OU: Allow `svc-drs` WriteProperty, object type `msDS-KeyCredentialLink` (`5b47d60f-6090-40b2-9f37-2a4de88f3063`), inherited to `user` (`bf967aba-0de6-11d0-a285-00aa003049e2`) descendants.
2. On `CN=RegisteredDevices`: Allow CreateChild and DeleteChild, object type `msDS-Device` (`5df2b673-6d41-4774-b3e8-d52e8ee9ff99`).
3. On `CN=RegisteredDevices`: Allow ReadProperty, WriteProperty and Delete, inherited to `msDS-Device` descendants.

Nothing else: not Key Admins or Enterprise Key Admins, no rights on DCs, admin accounts or `AdminSDHolder`.

## Detection

Alert on every change to `msDS-KeyCredentialLink`:

- **Windows DCs:** enable "Audit Directory Service Changes" (success) and a SACL on the Hello users' OU auditing writes to `msDS-KeyCredentialLink`; each change is event **5136** with the attribute name and the writer. A writer other than `svc-drs` is an incident; a write by `svc-drs` should match an `event=key` line in drs's log.
- **Samba DCs:** `log level = dsdb_password_json_audit:5` (or `dsdb_json_audit`) logs an "Auth info change" record per write.
- drs's own `event=key user= device= outcome=provisioned key_id=` line, for reconciliation.
