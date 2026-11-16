"""The session-key cryptography, checked against ROADtools' client-side
implementation (roadlib), which interoperates with Entra's real servers."""
import base64
import hashlib
import hmac
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from roadtools.roadlib.auth import Authentication
from roadtools.roadlib.deviceauth import DeviceAuthentication

from drs import jose


def test_bcrypt_blob_from_roadlib_round_trips():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    blob = DeviceAuthentication().create_pubkey_blob_from_key(key)
    assert jose.rsa_public_key(blob).public_numbers() == key.public_key().public_numbers()


def test_session_key_unwraps_like_a_client():
    transport = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    session_key = os.urandom(32)
    blob = DeviceAuthentication().create_pubkey_blob_from_key(transport)
    _, wrapped, *_ = jose.session_key_jwe(session_key, blob).split(".")
    # What roadlib does with session_key_jwe: unwrap the encrypted key, nothing else.
    unwrapped = transport.decrypt(jose.unb64url(wrapped), padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None))
    assert unwrapped == session_key


def test_response_decrypts_with_roadlib():
    session_key = os.urandom(32)
    jwe = jose.encrypt_for_session(session_key, {"access_token": "x", "token_type": "bearer"})
    assert Authentication().decrypt_auth_response(jwe, session_key, asjson=True) == {"access_token": "x", "token_type": "bearer"}


def test_derive_matches_roadlib():
    session_key, ctx = os.urandom(32), os.urandom(24)
    assert jose.derive(session_key, ctx) == Authentication().calculate_derived_key(session_key, ctx)[1]


def _signed(session_key, claims, kdf_v2):
    ctx = os.urandom(24)
    header = {"alg": "HS256", "ctx": base64.b64encode(ctx).decode()}
    if kdf_v2:
        header["kdf_ver"] = 2
    payload = json.dumps(claims).encode()
    key = jose.derive(session_key, ctx, payload if kdf_v2 else None)
    signing_input = f"{jose.b64url(json.dumps(header).encode())}.{jose.b64url(payload)}"
    return f"{signing_input}.{jose.b64url(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())}"


@pytest.mark.parametrize("kdf_v2", [False, True])
def test_session_signed_request_verifies(kdf_v2):
    session_key = os.urandom(32)
    token = _signed(session_key, {"grant_type": "refresh_token"}, kdf_v2)
    assert jose.verify_session_signed(token, session_key) == {"grant_type": "refresh_token"}
    with pytest.raises(ValueError, match="signature"):
        jose.verify_session_signed(token, os.urandom(32))
