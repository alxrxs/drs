import base64
import datetime
import json
import subprocess
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from drs import pki


def _issuer(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "MS-Organization-Access")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    (tmp_path / "issuer.pem").write_bytes(cert_pem)
    return pki.Issuer(cert_pem, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))


def _csr(bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "7E980AD9-B86D-4306-9425-9AC066FB014A")]))
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


def test_device_certificate_carries_the_four_guids(tmp_path):
    issuer = _issuer(tmp_path)
    ids = [uuid.uuid4() for _ in range(4)]
    cert = issuer.device_certificate(_csr(), *ids)
    assert cert.subject.rfc4514_string() == f"CN={ids[0]}"
    for oid, value in zip((pki.OID_DEVICE_ID, pki.OID_USER_GUID, pki.OID_DOMAIN_GUID, pki.OID_DSA_INVOCATION_ID), ids):
        assert cert.extensions.get_extension_for_oid(oid).value.value == b"\x04\x10" + value.bytes_le
    cert.verify_directly_issued_by(issuer.cert)


def test_device_certificate_refuses_a_small_key(tmp_path):
    import pytest
    with pytest.raises(ValueError, match="RSA-2048"):
        _issuer(tmp_path).device_certificate(_csr(1024), *[uuid.uuid4() for _ in range(4)])


def test_alt_security_identity_shape(tmp_path):
    cert = _issuer(tmp_path).device_certificate(_csr(), *[uuid.uuid4() for _ in range(4)])
    value = pki.alt_security_identity(cert)
    head = "X509:<SHA1-TP-PUBKEY>" + pki.thumbprint(cert)
    assert value.startswith(head) and len(base64.b64decode(value[len(head):])) == 32


def test_pctx_verifies_with_openssl(tmp_path):
    issuer = _issuer(tmp_path)
    der = base64.b64decode(issuer.pctx("dc-1.hellolab.test"))
    (tmp_path / "pctx.der").write_bytes(der)
    out = subprocess.run(["openssl", "cms", "-verify", "-inform", "DER", "-in", tmp_path / "pctx.der",
                          "-CAfile", tmp_path / "issuer.pem", "-binary"], capture_output=True, check=True)
    assert json.loads(out.stdout) == {"DomainControllerFqdn": "dc-1.hellolab.test"}
    info = subprocess.run(["openssl", "cms", "-cmsout", "-print", "-inform", "DER", "-in", tmp_path / "pctx.der"],
                          capture_output=True, text=True, check=True).stdout
    assert "sha256" in info and "rsaEncryption" in info
