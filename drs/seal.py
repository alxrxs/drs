"""Opaque tokens drs hands out and gets back -- PRTs, nonces, authorization
codes, Keycloak state: JSON sealed with AES-256-GCM under one server key, so
drs keeps no session store. The kind is bound as associated data, so a token
of one kind is never accepted as another."""
import base64
import json
import os
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SealError(Exception):
    pass


class Sealer:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("the state key must be 32 bytes")
        self._aead = AESGCM(key)

    def seal(self, kind, payload, ttl):
        body = dict(payload, exp=int(time.time()) + ttl)
        nonce = os.urandom(12)
        sealed = self._aead.encrypt(nonce, json.dumps(body, separators=(",", ":")).encode(), kind.encode())
        return base64.urlsafe_b64encode(nonce + sealed).rstrip(b"=").decode()

    def open(self, kind, token):
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            body = json.loads(self._aead.decrypt(raw[:12], raw[12:], kind.encode()))
        except (InvalidTag, ValueError, TypeError) as e:
            raise SealError(f"not a valid {kind}") from e
        if body.get("exp", 0) < time.time():
            raise SealError(f"expired {kind}")
        return body
