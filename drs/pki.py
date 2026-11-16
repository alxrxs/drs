"""The DRS issuer's work: device certificates ([MS-DVRJ] 3.1.5.1.1.3), the
device's altSecurityIdentities value (2.3.3) and the signed pctx ([MS-KPP]
3.1.5.1.1.3 step 5)."""
import base64
import datetime
import hashlib
import json
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ObjectIdentifier

OID_DEVICE_ID = ObjectIdentifier("1.2.840.113556.1.5.284.2")
OID_USER_GUID = ObjectIdentifier("1.2.840.113556.1.5.284.3")
OID_DOMAIN_GUID = ObjectIdentifier("1.2.840.113556.1.5.284.4")
OID_DSA_INVOCATION_ID = ObjectIdentifier("1.2.840.113556.1.5.284.1")
OID_JOIN_TYPE = ObjectIdentifier("1.2.840.113556.1.5.284.7")


def _octets(raw):
    """A DER OCTET STRING holding `raw`, as an extension value."""
    if len(raw) > 127:
        raise ValueError("value too long for a short-form OCTET STRING")
    return bytes([0x04, len(raw)]) + raw


class Issuer:
    def __init__(self, cert_pem, key_pem):
        self.cert = x509.load_pem_x509_certificate(cert_pem)
        self.key = serialization.load_pem_private_key(key_pem, password=None)

    def device_certificate(self, csr_der, device_id, user_guid, domain_guid, invocation_id,
                           lifetime=datetime.timedelta(days=3650)):
        """The client's CSR signed as its device certificate. Subject is CN=<device id>, as
        a DRS issues it; the four GUIDs go in as extensions, each an OCTET STRING of the
        GUID's mixed-endian bytes."""
        csr = x509.load_der_x509_csr(csr_der)
        if not csr.is_signature_valid:
            raise ValueError("the certificate request's signature does not verify")
        if csr.public_key().key_size != 2048:
            raise ValueError("the certificate request is not RSA-2048")
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, str(device_id))]))
                   .issuer_name(self.cert.subject)
                   .public_key(csr.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=10))
                   .not_valid_after(now + lifetime)
                   # As AD FS issues it (lab capture): these two critical, no key usage.
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True))
        for oid, value in ((OID_DSA_INVOCATION_ID, invocation_id), (OID_DEVICE_ID, device_id),
                           (OID_USER_GUID, user_guid), (OID_DOMAIN_GUID, domain_guid)):
            builder = builder.add_extension(x509.UnrecognizedExtension(oid, _octets(uuid.UUID(str(value)).bytes_le)),
                                            critical=False)
        # AD FS adds the string "1" under .284.7 to a domain-joined device's
        # certificate; MS-DVRJ does not list it.
        builder = builder.add_extension(x509.UnrecognizedExtension(OID_JOIN_TYPE, _octets(b"1")), critical=False)
        return builder.sign(self.key, hashes.SHA256())

    def pctx(self, dc_fqdn):
        """base64 of a CMS SignedData (SHA-256 with RSA) over {"DomainControllerFqdn": ...}."""
        content = json.dumps({"DomainControllerFqdn": dc_fqdn}, separators=(",", ":")).encode()
        der = (pkcs7.PKCS7SignatureBuilder().set_data(content)
               .add_signer(self.cert, self.key, hashes.SHA256())
               .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
        return base64.b64encode(der).decode()


def thumbprint(cert):
    return cert.fingerprint(hashes.SHA1()).hex().upper()


def alt_security_identity(cert):
    """X509:<SHA1-TP-PUBKEY><thumbprint><base64 SHA-256 of the RSAPublicKey>.

    As AD FS writes it, which is not quite [MS-DVRJ] 2.3.3: no '+' between the
    two, and the hash is over the PKCS#1 RSAPublicKey, not the whole
    SubjectPublicKeyInfo (lab capture, Server 2025 AD FS)."""
    rsa_public_key = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    return f"X509:<SHA1-TP-PUBKEY>{thumbprint(cert)}{base64.b64encode(hashlib.sha256(rsa_public_key).digest()).decode()}"
