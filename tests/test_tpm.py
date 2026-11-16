"""The session key for a TPM-held transport key: built as TPM2_Import reads it,
checked here by doing what the TPM does with the transport key's private half."""
import hashlib
import hmac
import os
import pathlib
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from drs import jose, tpm

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def pcp_blob_for(key):
    """The lab client's real PCPM transport key, its modulus swapped for `key`'s."""
    blob = bytearray((FIXTURES / "transport-key.pcpm").read_bytes())
    real = jose.rsa_public_key(bytes(blob)).public_numbers().n.to_bytes(256, "big")
    at = bytes(blob).index(real)
    blob[at:at + 256] = key.public_key().public_numbers().n.to_bytes(256, "big")
    return bytes(blob)


def take(buf, pos):
    (n,) = struct.unpack_from(">H", buf, pos)
    return buf[pos + 2:pos + 2 + n], pos + 2 + n


def tpm2_import(private_key, blob):
    """TPM2_Import's checks for an outer-wrapped duplicate (Part 1 23.3)."""
    encrypted_seed, pos = take(blob, 0)
    duplicate, pos = take(blob, pos)
    public, pos = take(blob, pos)
    assert pos == len(blob)
    seed = private_key.decrypt(encrypted_seed, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                            algorithm=hashes.SHA256(), label=b"DUPLICATE\x00"))
    name = struct.pack(">H", tpm.TPM_ALG_SHA256) + hashlib.sha256(public).digest()
    outer, rest = take(duplicate, 0)
    enc_sensitive = duplicate[rest:]
    assert hmac.compare_digest(outer, hmac.new(tpm.kdfa(seed, b"INTEGRITY", b"", b"", 256), enc_sensitive + name,
                                               hashlib.sha256).digest())
    dec = Cipher(algorithms.AES(tpm.kdfa(seed, b"STORAGE", name, b"", 128)), modes.CFB(b"\x00" * 16)).decryptor()
    sensitive, _ = take(dec.update(enc_sensitive) + dec.finalize(), 0)
    (kind,) = struct.unpack_from(">H", sensitive)
    auth, p = take(sensitive, 2)
    obfuscation, p = take(sensitive, p)
    secret, p = take(sensitive, p)
    assert kind == tpm.TPM_ALG_KEYEDHASH and auth == b""
    assert public[-32:] == hashlib.sha256(obfuscation + secret).digest()  # unique binds the key
    return secret, (len(encrypted_seed), len(duplicate), len(public))


def test_the_session_key_imports_under_the_transport_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    session_key = os.urandom(32)
    blob = tpm.duplicate_hmac_key(tpm.parse_pcp(pcp_blob_for(key)), session_key)
    secret, sizes = tpm2_import(key, blob)
    assert secret == session_key
    assert sizes == (256, 108, 48)  # what AD FS sends for the same transport key


def test_the_jwe_carries_the_import_blob_for_a_tpm_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    session_key = os.urandom(32)
    jwe = jose.session_key_jwe(session_key, pcp_blob_for(key))
    assert tpm2_import(key, jose.unb64url(jwe.split(".")[1]))[0] == session_key


def test_the_parent_reads_like_the_real_transport_key():
    parent = tpm.parse_pcp((FIXTURES / "transport-key.pcpm").read_bytes())
    assert (parent.name_alg, parent.sym_bits, parent.key.key_size) == (tpm.TPM_ALG_SHA256, 128, 2048)
