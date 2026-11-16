"""The token cryptography of [MS-OAPXBC]: the session key handed to a device,
the keys derived from it (SP800-108, label "AzureAD-SecureConversation"), the
HS256 requests a device signs with them, and the dir/A256GCM responses."""
import base64
import hashlib
import hmac
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode

from . import tpm

LABEL = b"AzureAD-SecureConversation"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text):
    if isinstance(text, str):
        text = text.encode()
    return base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))


def unb64(text):
    """Standard or URL-safe base64, padded or not: clients send both."""
    text = text.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(text + "=" * (-len(text) % 4))


def rsa_public_key(material):
    """An RSA public key from what Windows sends as a transport or NGC key: a
    BCRYPT_RSAKEY_BLOB (RSA1), a Platform Crypto Provider key blob (PCPM, a
    TPM-held key; the lab client's transport key), or DER SubjectPublicKeyInfo."""
    if material[:4] == b"RSA1":
        _, _bits, elen, mlen = struct.unpack_from("<4sIII", material)
        exponent = material[24:24 + elen]
        modulus = material[24 + elen:24 + elen + mlen]
        return rsa.RSAPublicNumbers(int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")).public_key()
    if material[:4] == b"PCPM":
        return tpm.parse_pcp(material).key
    key = serialization.load_der_public_key(material)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("not an RSA key")
    return key


def derive(session_key, ctx, payload=None):
    """The 256-bit key for one request or response. KDFv2 (`payload` given)
    derives from SHA256(ctx || payload) instead of ctx."""
    context = hashlib.sha256(ctx + payload).digest() if payload is not None else ctx
    return KBKDFHMAC(algorithm=hashes.SHA256(), mode=Mode.CounterMode, length=32, rlen=4, llen=4,
                     location=CounterLocation.BeforeFixed, label=LABEL, context=context,
                     fixed=None).derive(session_key)


def split_jws(token):
    header_b64, payload_b64, sig_b64 = token.split(".")
    return (json.loads(unb64url(header_b64)), unb64url(payload_b64),
            f"{header_b64}.{payload_b64}".encode(), unb64url(sig_b64))


def verify_session_signed(token, session_key):
    """The claims of an HS256 request signed with a key derived from
    `session_key`, after checking that signature."""
    header, payload, signing_input, sig = split_jws(token)
    if header.get("alg") != "HS256" or "ctx" not in header:
        raise ValueError("not a session-key signed request")
    ctx = unb64(header["ctx"])
    # KDFv2 hashes the payload into the context; clients have been seen to use
    # its decoded bytes and its base64url text (a second lab), so both are tried.
    candidates = [payload, signing_input.split(b".")[1]] if str(header.get("kdf_ver")) == "2" else [None]
    for context_payload in candidates:
        key = derive(session_key, ctx, context_payload)
        if hmac.compare_digest(hmac.new(key, signing_input, hashlib.sha256).digest(), sig):
            return json.loads(payload)
    raise ValueError("bad session-key signature")


def verify_rs256(token, public_key):
    header, payload, signing_input, sig = split_jws(token)
    if header.get("alg") != "RS256":
        raise ValueError(f"unexpected alg {header.get('alg')}")
    public_key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    return header, json.loads(payload)


def sign_rs256(claims, private_key, kid=None, x5t=None):
    header = {"alg": "RS256", "typ": "JWT"}
    if kid:
        header["kid"] = kid
    if x5t:
        header["x5t"] = x5t
    signing_input = f"{b64url(json.dumps(header, separators=(',', ':')).encode())}.{b64url(json.dumps(claims, separators=(',', ':')).encode())}"
    return f"{signing_input}.{b64url(private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()))}"


def session_key_jwe(session_key, transport_key):
    """The session key for a device, as a compact JWE whose "encrypted key" is
    the session key wrapped to the device's transport key (the raw material
    from its msDS-KeyCredentialLink). A TPM-held transport key (PCPM) gets a
    TPM 2.0 duplication blob, as AD FS sends; a software key (RSA1) gets
    RSA-OAEP, as Entra sends and ROADtools reads. Only that part is used."""
    header = b64url(json.dumps({"enc": "A256GCM", "alg": "RSA-OAEP"}, separators=(",", ":")).encode())
    if transport_key[:4] == b"PCPM":
        wrapped = tpm.duplicate_hmac_key(tpm.parse_pcp(transport_key), session_key)
    else:
        wrapped = rsa_public_key(transport_key).encrypt(
            session_key, padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None))
    iv = os.urandom(12)
    sealed = AESGCM(session_key).encrypt(iv, b"{}", header.encode())
    return ".".join((header, b64url(wrapped), b64url(iv), b64url(sealed[:-16]), b64url(sealed[-16:])))


def encrypt_for_session(session_key, payload):
    """A dir/A256GCM response under a key freshly derived from the session key."""
    ctx = os.urandom(24)
    header = b64url(json.dumps({"alg": "dir", "enc": "A256GCM", "ctx": base64.b64encode(ctx).decode(),
                                "kid": "session"}, separators=(",", ":")).encode())
    iv = os.urandom(12)
    sealed = AESGCM(derive(session_key, ctx)).encrypt(iv, json.dumps(payload).encode(), header.encode())
    return ".".join((header, "", b64url(iv), b64url(sealed[:-16]), b64url(sealed[-16:])))
