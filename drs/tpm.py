"""Handing a secret to a TPM-held key: a TPM 2.0 duplication blob for TPM2_Import.

A client whose transport key lives in its TPM (a PCPM blob) does not decrypt
an RSA-OAEP session key: Windows imports it (NgcImportSymmetricPopKey) as a
KEYEDHASH object duplicated to the transport key, and refuses a plain OAEP
ciphertext with "Object was not found". This is the blob AD FS sends (lab
capture): TPM2B_ENCRYPTED_SECRET | TPM2B_PRIVATE | TPM2B_PUBLIC, built as TPM
2.0 Part 1, 23.3 (outer wrapper only) and 11.4.10.2 (KDFa) describe.
"""
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TPM_ALG_RSA = 0x0001
TPM_ALG_KEYEDHASH = 0x0008
TPM_ALG_HMAC = 0x0005
TPM_ALG_SHA256 = 0x000B
TPM_ALG_AES = 0x0006
TPM_ALG_CFB = 0x0043
TPM_ALG_NULL = 0x0010
# sign | noDA | userWithAuth: the attributes AD FS gives the imported key.
SESSION_KEY_ATTRIBUTES = 0x00040440


@dataclass
class Parent:
    """What duplicating to a key needs from its public area."""
    key: rsa.RSAPublicKey
    name_alg: int
    sym_bits: int


def tpm2b(data):
    return struct.pack(">H", len(data)) + data


def parse_pcp(blob):
    """The transport key's public area from a PCP key blob (PCPM): a little-
    endian header (magic, header length, type, flags, public size), then the
    key's TPM2B_PUBLIC in TPM byte order (big-endian, Part 2 12.2.4)."""
    _magic, header_len, _type, _flags, public_len = struct.unpack_from("<4sIIII", blob)
    public = blob[header_len:header_len + public_len]
    (size,) = struct.unpack_from(">H", public)
    alg, name_alg, _attributes, policy_len = struct.unpack_from(">HHIH", public, 2)
    if alg != TPM_ALG_RSA:
        raise ValueError(f"PCP key of TPM algorithm {alg:#x}, not RSA")
    pos = 12 + policy_len
    sym, = struct.unpack_from(">H", public, pos)
    sym_bits = 0
    if sym != TPM_ALG_NULL:
        sym_bits, _mode = struct.unpack_from(">HH", public, pos + 2)
        pos += 6
    else:
        pos += 2
    scheme, = struct.unpack_from(">H", public, pos)
    pos += 2 if scheme == TPM_ALG_NULL else 4
    _bits, exponent, modulus_len = struct.unpack_from(">HIH", public, pos)
    pos += 8
    if pos + modulus_len > 2 + size:
        raise ValueError("truncated PCP key blob")
    modulus = int.from_bytes(public[pos:pos + modulus_len], "big")
    return Parent(rsa.RSAPublicNumbers(exponent or 65537, modulus).public_key(), name_alg, sym_bits)


def kdfa(key, label, context_u, context_v, bits):
    """KDFa with SHA-256 (Part 1 11.4.10.2): the label carries its NUL."""
    out, counter = b"", 0
    while len(out) * 8 < bits:
        counter += 1
        out += hmac.new(key, struct.pack(">I", counter) + label + b"\x00" + context_u + context_v
                        + struct.pack(">I", bits), hashlib.sha256).digest()
    return out[:bits // 8]


def duplicate_hmac_key(parent, secret, seed=None, obfuscation=None):
    """`secret` as an HMAC-SHA256 key duplicated to `parent`: the three
    TPM2_Import inputs, concatenated as Windows reads them."""
    if parent.name_alg != TPM_ALG_SHA256 or parent.sym_bits not in (128, 256):
        raise ValueError("the transport key is not a SHA-256 storage key with an AES parent")
    obfuscation = obfuscation if obfuscation is not None else os.urandom(32)
    # The object: an HMAC key whose unique field is H(obfuscation || key).
    public = (struct.pack(">HHI", TPM_ALG_KEYEDHASH, TPM_ALG_SHA256, SESSION_KEY_ATTRIBUTES) + tpm2b(b"")
              + struct.pack(">HH", TPM_ALG_HMAC, TPM_ALG_SHA256) + tpm2b(hashlib.sha256(obfuscation + secret).digest()))
    name = struct.pack(">H", TPM_ALG_SHA256) + hashlib.sha256(public).digest()
    sensitive = tpm2b(struct.pack(">H", TPM_ALG_KEYEDHASH) + tpm2b(b"") + tpm2b(obfuscation) + tpm2b(secret))
    # The outer wrapper: a seed only the parent can recover.
    seed = seed if seed is not None else os.urandom(32)
    encrypted_seed = parent.key.encrypt(seed, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                                                            label=b"DUPLICATE\x00"))
    sym_key = kdfa(seed, b"STORAGE", name, b"", parent.sym_bits)
    enc = Cipher(algorithms.AES(sym_key), modes.CFB(b"\x00" * 16)).encryptor()
    enc_sensitive = enc.update(sensitive) + enc.finalize()
    hmac_key = kdfa(seed, b"INTEGRITY", b"", b"", 256)
    outer = hmac.new(hmac_key, enc_sensitive + name, hashlib.sha256).digest()
    return tpm2b(encrypted_seed) + tpm2b(tpm2b(outer) + enc_sensitive) + tpm2b(public)
