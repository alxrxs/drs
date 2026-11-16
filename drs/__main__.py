"""drs: Windows Hello for Business key-trust registration without AD FS.

HOW TO RUN: python3 -m drs /etc/drs/<instance>.toml   (systemd: deploy/drs@.service, one instance per domain)
"""
import base64
import logging
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import config as cfg
from .directory import Directory
from .http import Kerberos, serve
from .keycloak import Keycloak
from .pki import Issuer
from .seal import Sealer
from .service import Service


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    c = cfg.load(sys.argv[1])
    read = lambda p: open(p, "rb").read()  # noqa: E731
    issuer = Issuer(read(c.issuer_cert), read(c.issuer_key))
    signing_cert = x509.load_pem_x509_certificate(read(c.signing_cert))
    signer = serialization.load_pem_private_key(read(c.signing_key), password=None)
    directory = Directory(c.ldap_uri, c.ldap_bind_dn, cfg.read_secret(c.ldap_password_file), c.ldap_base_dn,
                          c.ldap_devices_dn, c.ldap_ca_file)
    keycloak = Keycloak(c.keycloak_issuer, c.keycloak_client_id, cfg.read_secret(c.keycloak_client_secret_file),
                        c.keycloak_acr, c.keycloak_guid_claim, c.keycloak_max_age, c.keycloak_ca_file or None)
    sealer = Sealer(base64.b64decode(cfg.read_secret(c.state_key_file)))
    service = Service(c, directory, issuer, signer, signing_cert, sealer, keycloak)
    serve(c, service, Kerberos(c.keytab, c.host))


if __name__ == "__main__":
    main()
