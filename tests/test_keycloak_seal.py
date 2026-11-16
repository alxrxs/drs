import os
import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from drs import jose
from drs.keycloak import Keycloak, SecondFactorError
from drs.seal import SealError, Sealer

ISSUER = "https://sso.lab.test/realms/lab"
GUID = uuid.uuid4()


@pytest.fixture
def kc():
    k = Keycloak(ISSUER, "drs", "secret", "drs-mfa", "ad_object_guid", max_age=120)
    return k


def claims(**over):
    now = int(time.time())
    base = {"iss": ISSUER, "aud": "drs", "nonce": "n1", "exp": now + 60, "auth_time": now - 5, "acr": "drs-mfa",
            "ad_object_guid": str(GUID)}
    return {**base, **over}


def test_a_fresh_second_factor_passes(kc):
    kc.check(claims(), "n1", str(GUID))


@pytest.mark.parametrize("over, why", [
    ({"nonce": "other"}, "nonce"),
    ({"auth_time": int(time.time()) - 600}, "fresh"),
    ({"acr": "1"}, "second-factor flow"),
    ({"aud": "someone-else"}, "not Keycloak"),
    ({"iss": "https://evil.test/realms/lab"}, "not Keycloak"),
    ({"ad_object_guid": str(uuid.uuid4())}, "another account"),
])
def test_what_is_refused(kc, over, why):
    with pytest.raises(SecondFactorError, match=why):
        kc.check(claims(**over), "n1", str(GUID))


def test_guid_as_base64_bytes_is_understood(kc):
    import base64
    kc.check(claims(ad_object_guid=base64.b64encode(GUID.bytes_le).decode()), "n1", str(GUID))


def test_a_forged_id_token_is_refused(kc, monkeypatch):
    real = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(kc, "_key", lambda kid: real.public_key())
    token = jose.sign_rs256(claims(), forger, kid="k1")
    with pytest.raises(Exception):
        jose.verify_rs256(token, kc._key("k1"))


def test_sealed_kinds_do_not_cross():
    s = Sealer(os.urandom(32))
    code = s.seal("code", {"upn": "a"}, 60)
    assert s.open("code", code)["upn"] == "a"
    with pytest.raises(SealError):
        s.open("prt", code)
    with pytest.raises(SealError, match="expired"):
        s.open("code", s.seal("code", {}, -1))
    with pytest.raises(SealError):
        Sealer(os.urandom(32)).open("code", code)
