"""Checks against what a real AD FS DRS and a real Windows 11 client produced
in the drs lab (hellolab.test, Server 2025 AD FS, Windows 11 26H2)."""
import pathlib

from cryptography import x509

from drs import jose, pki

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def test_alt_security_identity_matches_adfs():
    cert = x509.load_der_x509_certificate((FIXTURES / "adfs-device-cert.der").read_bytes())
    # The value AD FS wrote to the device's msDS-Device object.
    assert pki.alt_security_identity(cert) == (
        "X509:<SHA1-TP-PUBKEY>1C99D369C047585D6C129DDB073C3128A84477DA"
        "llUAdTRuzWVwrD60HkEXUsG4vR8LLtq/3BZzxhpa7bg=")


def test_transport_key_is_a_pcp_blob_with_an_rsa_2048_key():
    key = jose.rsa_public_key((FIXTURES / "transport-key.pcpm").read_bytes())
    numbers = key.public_numbers()
    assert key.key_size == 2048 and numbers.e == 65537
    assert numbers.n.to_bytes(256, "big")[:8].hex() == "a4f9e3cc2504d005"
