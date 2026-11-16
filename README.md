# drs

**Windows Hello for Business on-premises, without AD FS.**

drs is a small Python service that does the one job AD FS does in a Hello for Business *key trust* deployment: it registers your domain-joined Windows PCs and puts each user's Hello key in Active Directory. Keep your domain controllers, and replace the AD FS server with drs.

- **No AD FS, no Entra ID, no cloud.** PIN and biometric sign-in are checked by your own domain controllers.
- **Windows Server or Samba DCs**, with or without AD CS.
- **Keycloak** provides the second factor when a user sets up Hello.
- **Drop-in for AD FS:** drs answers on AD FS's own URLs, so PCs already registered with AD FS keep working.

## How it works

```
 Windows 11 PC ──HTTPS──▶ drs ──LDAPS──▶ Active Directory (Windows or Samba DCs)
       │                   └───OIDC──▶ Keycloak (second factor, at Hello set-up)
       └── Kerberos PKINIT, every PIN sign-in ──▶ domain controller
```

Hello key trust has two halves, and only one ever needed AD FS. **Signing in** is plain Kerberos against the public key in the user's `msDS-KeyCredentialLink`, which the domain controller handles on its own. **Getting the key there** is what AD FS's Device Registration Service did, and what drs does:

1. **Once per PC**, after the domain join: drs checks the computer's Kerberos ticket and registers it as a device.
2. **At every sign-in:** drs checks the user's password or Hello key and issues the token Windows needs.
3. **Once per user and PC**, at Hello set-up: drs sends the user to Keycloak for the second factor, then writes their new key to AD.

From then on, PIN sign-in goes straight to the domain controller, online or offline.

## Status

Tested end to end with AD FS stopped:

| Domain | Clients |
|---|---|
| Windows Server 2025 DC with AD CS | Windows 11 24H2, 25H2, 26H2 |
| Samba 4.25 DC alone, no AD CS | Windows 11 24H2, 26H2 |

Device join, Hello set-up, PIN sign-in online and offline, lock and unlock, PIN reset, re-enrolment and Credential Guard all work, and users outside the allowed group or without the second factor are refused.

> **Samba DCs need patches** that are not released yet: [samba!4794](https://gitlab.com/samba-team/samba/-/merge_requests/4794).

## Setup

You need: domain controllers at domain functional level 2016 or later, each with a KDC certificate; a Linux host for drs (Debian or Ubuntu, Python 3.11+); a TLS certificate for drs's host name from a CA your PCs trust; and Keycloak. The examples use the domain `example.test`, drs at `adfs.example.test`, and Hello users in `OU=People`.

**1. Prepare the directory** on a domain controller. This creates the `svc-drs` account with exactly the rights drs needs (never Key Admins), the pointer that sends PCs to drs, the `WHfB-Enrol` group of users allowed to set up Hello, and a keytab.

```powershell
# Windows DC
.\deploy\setup-ad.ps1 -DrsHost adfs.example.test -UsersOU "OU=People,DC=example,DC=test"
```
```sh
# Samba DC
deploy/setup-samba.sh --host adfs.example.test --users-ou "OU=People,DC=example,DC=test"
```

**2. Set up Keycloak.** This creates the AD federation, a flow that asks for the password and then a one-time code, and the `drs` client, and writes its secret to `./keycloak-secret`.

```sh
deploy/setup-keycloak.sh --server https://sso.example.test --realm example --drs-host adfs.example.test \
    --ldap-url ldaps://dc1.example.test --users-dn "OU=People,DC=example,DC=test" \
    --bind-dn "CN=svc-keycloak,OU=Service Accounts,DC=example,DC=test"
```

`--bind-dn` is any AD account that can read your users; Keycloak only reads. Already federating AD in that realm? Pass `--ldap-provider <its name>` instead of the three LDAP options.

**3. Install drs** on its host. This installs the packages and code, creates drs's own keys and a config with your host name filled in, and lists what is still missing.

```sh
git clone https://github.com/alxrxs/drs && cd drs
sudo deploy/install.sh example adfs.example.test
```

Copy in the files it lists (the TLS certificate and key, the AD CA, the keytab, the LDAP password and the Keycloak secret), set the `[ldap]` and `[keycloak]` values in `/etc/drs/example.toml` (every setting is explained in [drs.example.toml](drs.example.toml)), and start it:

```sh
sudo systemctl enable --now drs@example
sudo runuser -u drs -- python3 /opt/drs/deploy/check-directory.py /etc/drs/example.toml alice@example.test PC1$
```

**4. Turn it on for your PCs**, by Group Policy: *Use Windows Hello for Business* on, *Use a hardware security device* on, certificate trust and cloud trust off (that makes it key trust), and *Register domain joined computers as devices* on. Point the DNS name at drs. At the next sign-in, PCs register and users are asked to set up Hello.

## Replacing an existing AD FS

No PC needs to re-register:

1. Put AD FS's device registration resource ID (from `Get-AdfsDeviceRegistration`) in `resource_id`, and keep its federation host name.
2. Move the `HTTP/<host>` SPN from the AD FS account to `svc-drs`, point DNS at drs, and stop AD FS.

PCs cache their Kerberos ticket for the old account for up to 10 hours, and until then a new device registration fails (sign-in is unaffected). Run `klist -li 0x3e7 purge` as an administrator on a PC to clear it sooner.

## Security

drs can add a sign-in key to any account it can write to, so its rights are limited to one OU and never include administrators. [THREAT-MODEL.md](THREAT-MODEL.md) covers every key and secret drs holds, what each would give an attacker, and how it is contained. Read it before deploying.

drs logs one line per request and one per decision (device join, token, second factor, key write), with the user, device and outcome. It never logs tokens, keys, passwords or codes.

## More

- [FINDINGS.md](FINDINGS.md): what Windows actually sends and expects, where it differs from Microsoft's specifications.
- **Development:** `pip install -e '.[test]' && python3 -m pytest`. The tests cover every wire format and the whole enrolment as a real Windows 11 client performs it; the code is organised one file per concern under `drs/`.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
