"""drs's configuration: one TOML file (see drs.example.toml). Every name is
here; nothing about a particular domain is in the code."""
import tomllib
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    # The federation service name clients use: the SCP's enterpriseDrsName, the
    # TLS certificate's name and the Kerberos SPN HTTP/<host>.
    host: str
    listen: str
    port: int
    tls_cert: str
    tls_key: str
    # urn:ms-drs:<id> -- the resource and audience of every DRS token. Keep AD
    # FS's when replacing it, so already-registered clients go on working.
    resource_id: str
    upn_suffixes: tuple
    # LDAPS URIs, comma-separated; the service account's bind DN and password.
    ldap_uri: str
    ldap_bind_dn: str
    ldap_password_file: str
    ldap_ca_file: str
    ldap_base_dn: str
    ldap_devices_dn: str
    ldap_enrol_group_dn: str
    # The DRS issuer (device certificates, pctx) and the token-signing key.
    issuer_cert: str
    issuer_key: str
    signing_cert: str
    signing_key: str
    # 32 random bytes, base64: seals the PRTs, nonces and codes drs hands out.
    state_key_file: str
    keytab: str
    keycloak_issuer: str
    keycloak_client_id: str
    keycloak_client_secret_file: str
    keycloak_acr: str
    keycloak_guid_claim: str
    keycloak_max_age: int = 120
    # The CA Keycloak's TLS certificate chains to; empty: the system trust store.
    keycloak_ca_file: str = ""

    @property
    def resource(self):
        return f"urn:ms-drs:{self.resource_id}"

    @property
    def base_url(self):
        return f"https://{self.host}" + ("" if self.port == 443 else f":{self.port}")


# Sections whose keys are fields as they stand; the others' keys are prefixed
# with the section's name ([ldap] uri -> ldap_uri).
_UNPREFIXED = ("service", "keys")


def load(path):
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    flat = {}
    for section, values in raw.items():
        for key, value in values.items():
            flat[key if section in _UNPREFIXED else f"{section}_{key}"] = value
    flat["upn_suffixes"] = tuple(flat.get("upn_suffixes", ()))
    return Config(**flat)


def read_secret(path):
    with open(path, encoding="utf-8") as f:
        return f.read().strip()
