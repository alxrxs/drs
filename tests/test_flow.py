"""The whole enrolment, in the order and shape the lab capture recorded a
Windows 11 client running it against AD FS, driven through drs's Service with
an in-memory directory and a stand-in Keycloak."""
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import time
import types
import urllib.parse
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from roadtools.roadlib.deviceauth import DeviceAuthentication

from drs import jose, keycred, pki
from drs.directory import Device, KeyCredential, Principal
from drs.keycloak import SecondFactorError
from drs.seal import Sealer
from drs.service import DRS_CLIENT_ID, DRS_REDIRECT_URI, JWT_BEARER, Refused, Service

GROUP = "CN=WHfB-Enrol,OU=People,DC=lab,DC=test"
RESOURCE_ID = "434DF4A9-3CF2-4C1D-917E-2CD2B72F515A"


def _ca(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    return cert, key


class FakeDirectory:
    def __init__(self):
        self.users = {}
        self.members = set()
        self.devices = {}
        self.computers = {}
        self.writes = []

    def session(self):
        import contextlib
        return contextlib.nullcontext(self)

    def add_user(self, name, member):
        p = Principal(dn=f"CN={name},OU=People,DC=lab,DC=test", upn=f"{name}@lab.test", guid=uuid.uuid4(),
                      display_name=name.title(), given_name=name.title(), family_name="Tester",
                      sid=f"S-1-5-21-1-2-3-{1100 + len(self.users)}")
        self.users[p.upn] = (p, "pw-" + name)
        if member:
            self.members.add(p.dn)
        return p

    def user_by_upn(self, conn, upn):
        return self.users.get(upn, (None,))[0]

    def computer(self, conn, sam):
        return self.computers.get(sam)

    def is_member(self, conn, principal, group_dn):
        return group_dn == GROUP and principal.dn in self.members

    def domain_guid(self, conn):
        return uuid.UUID(int=4)

    def invocation_id(self, conn):
        return uuid.UUID(int=1)

    def dc_hostname(self, conn):
        return "dc1.lab.test"

    def device(self, conn, device_id):
        return self.devices.get(str(device_id))

    def device_by_alt_security_identity(self, conn, value):
        return next((d for d in self.devices.values() if value in d.alt), None)

    def upsert_device(self, conn, device_id, owner_sid, alt, transport_key, os_type, os_version, name):
        dn = f"CN={device_id},CN=RegisteredDevices,DC=lab,DC=test"
        link = keycred.KeyCredential(key_material=transport_key, key_usage=keycred.KEY_USAGE_STK,
                                     device_id=device_id).to_dn_binary(dn)
        d = Device(dn=dn, device_id=device_id, enabled=True, key_credential_links=[link])
        d.alt = [alt]
        self.devices[str(device_id)] = d

    def add_ngc_key(self, conn, user, device_id, material):
        self.writes = [(dn, link) for dn, link in self.writes
                       if dn != user.dn or KeyCredential.from_value(link).device_id != device_id]
        self.writes.append((user.dn, keycred.KeyCredential(key_material=material, key_usage=keycred.KEY_USAGE_NGC,
                                                           device_id=device_id).to_dn_binary(user.dn)))

    def user_keys(self, conn, user):
        return [KeyCredential.from_value(link) for dn, link in self.writes if dn == user.dn]

    def check_password(self, user_dn, password):
        return any(p.dn == user_dn and pw == password for p, pw in self.users.values())


class FakeKeycloak:
    def __init__(self):
        self.next_guid = None
        self.fail = None

    def authorization_url(self, state, nonce, verifier, login_hint, redirect_uri):
        self.state, self.nonce, self.hint = state, nonce, login_hint
        return "https://sso.lab.test/auth?" + urllib.parse.urlencode({"state": state})

    def redeem(self, code, verifier, redirect_uri):
        return {"acr": "drs-mfa", "guid": self.next_guid}

    def check(self, claims, nonce, user_guid):
        if self.fail:
            raise SecondFactorError(self.fail)
        if nonce != self.nonce or claims["guid"] != user_guid:
            raise SecondFactorError("Keycloak proved another account than the one enrolling")


@pytest.fixture
def drs():
    issuer_cert, issuer_key = _ca("MS-Organization-Access")
    signing_cert, signing_key = _ca("drs token signing")
    pem = lambda c, k: (c.public_bytes(serialization.Encoding.PEM),  # noqa: E731
                        k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    config = types.SimpleNamespace(host="drs.lab.test", base_url="https://drs.lab.test",
                                   resource=f"urn:ms-drs:{RESOURCE_ID}", ldap_enrol_group_dn=GROUP)
    directory, keycloak = FakeDirectory(), FakeKeycloak()
    s = Service(config, directory, pki.Issuer(*pem(issuer_cert, issuer_key)), signing_key, signing_cert,
                Sealer(os.urandom(32)), keycloak)
    return s, directory, keycloak


class Client:
    """What the capture shows Windows doing, step by step."""

    def __init__(self, drs, name):
        self.s, self.dir, self.kc = drs
        self.device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.transport = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        guid = uuid.uuid4()
        self.dir.computers[f"{name}$"] = Principal(dn=f"CN={name},CN=Computers,DC=lab,DC=test",
                                                   upn=f"{name.lower()}$@lab.test", guid=guid,
                                                   sid="S-1-5-21-1-2-3-2000", nt_name=f"LAB\\{name}$")

    def join(self, name):
        token = self.s.join_token(f"{name}$@LAB.TEST")
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, str(uuid.uuid4()).upper())]))
               .sign(self.device_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
        body = json.dumps({"CertificateRequest": {"Type": "pkcs10", "Data": base64.b64encode(csr).decode()},
                           "TransportKey": base64.b64encode(
                               DeviceAuthentication().create_pubkey_blob_from_key(self.transport)).decode(),
                           "TargetDomain": "drs.lab.test", "DeviceType": "Windows", "OSVersion": "10.0.26300.9457",
                           "DeviceDisplayName": name, "JoinType": 6, "attributes": {"ReuseDevice": "true"}})
        resp = self.s.join(token, body.encode() + b"\x00")  # Windows ends the body with a NUL
        self.cert = x509.load_der_x509_certificate(base64.b64decode(resp["Certificate"]["RawBody"]))
        return resp

    def prt(self, upn=None, password=None, renew=None, hello=None, client_id="38aa3b87-a06d-4817-b275-7a316988d93b"):
        """A device-signed PRT request: the password at sign-in, a renewal, or
        (hello = (upn, Hello private key)) an assertion signed with the Hello
        key, as at a PIN sign-in (shape from the lab, 24H2)."""
        nonce = self.s.token({"grant_type": "srv_challenge"})[1]["Nonce"]
        x5c = base64.b64encode(self.cert.public_bytes(serialization.Encoding.DER)).decode()
        header = {"alg": "RS256", "typ": "JWT", "x5c": x5c, "kdf_ver": 2}
        claims = {"client_id": client_id, "request_nonce": nonce,
                  "scope": "openid aza ugs", "win_ver": "10.0.26100.9278"}
        if hello is not None:
            hello_upn, key = hello
            material = DeviceAuthentication().create_pubkey_blob_from_key(key)
            a_header = {"alg": "RS256", "typ": "JWT", "use": "ngc",
                        "kid": base64.b64encode(hashlib.sha256(material).digest()).decode()}
            a_body = {"aud": "HTTPS://DRS.LAB.TEST/ADFS/LS/", "iss": hello_upn, "request_nonce": nonce,
                      # Windows sends the times as strings.
                      "scope": "openid aza ugs", "iat": str(int(time.time())), "exp": str(int(time.time()) + 300)}
            a_input = f"{jose.b64url(json.dumps(a_header).encode())}.{jose.b64url(json.dumps(a_body).encode())}"
            assertion = f"{a_input}.{jose.b64url(key.sign(a_input.encode(), padding.PKCS1v15(), hashes.SHA256()))}"
            claims.update({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion,
                           "username": hello_upn})
        else:
            claims.update({"grant_type": "refresh_token", "refresh_token": renew} if renew is not None
                          else {"grant_type": "password", "username": upn, "password": password})
        signing_input = f"{jose.b64url(json.dumps(header).encode())}.{jose.b64url(json.dumps(claims).encode())}"
        sig = self.device_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        status, resp = self.s.token({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                     "request": f"{signing_input}.{jose.b64url(sig)}", "windows_api_version": "2.2"})
        wrapped = jose.unb64url(resp["session_key_jwe"].split(".")[1])
        self.session_key = self.transport.decrypt(wrapped, padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None))
        self.prt_token = resp["refresh_token"]
        return resp

    def session_signed(self, claims):
        ctx = os.urandom(24)
        header = {"alg": "HS256", "kdf_ver": 2, "ctx": base64.b64encode(ctx).decode()}
        payload = json.dumps(dict(claims, refresh_token=self.prt_token)).encode()
        key = jose.derive(self.session_key, ctx, payload)
        signing_input = f"{jose.b64url(json.dumps(header).encode())}.{jose.b64url(payload)}"
        return f"{signing_input}.{jose.b64url(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())}"

    def enrol(self, guid):
        status, body = self.s.token({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                     "request": self.session_signed({"grant_type": "refresh_token",
                                                                     "resource": f"urn:ms-drs:{RESOURCE_ID}"}),
                                     "amr_values": "ngcmfa"})
        assert (status, body["error"]) == (401, "interaction_required")
        query = {"response_type": "code", "client_id": DRS_CLIENT_ID, "redirect_uri": DRS_REDIRECT_URI,
                 "amr_values": "ngcmfa", "response_mode": "form_post"}
        url = self.s.authorize(query, self.session_signed({"iat": int(time.time())}))
        self.kc.next_guid = guid
        page = self.s.callback({"state": self.kc.state, "code": "kc-code"})
        assert DRS_REDIRECT_URI.lower() in page
        self.code = re.search(r'name="code" value="([^"]+)"', page).group(1)
        status, tokens = self.s.token({"grant_type": "authorization_code", "code": self.code,
                                       "client_id": DRS_CLIENT_ID, "redirect_uri": DRS_REDIRECT_URI})
        self.setup_tokens = tokens
        self.ngc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kngc = DeviceAuthentication().create_pubkey_blob_from_key(self.ngc)
        return url, self.s.provision_key(tokens["access_token"],
                                         json.dumps({"kngc": base64.b64encode(kngc).decode()}).encode())


def test_full_enrolment(drs):
    s, directory, kc = drs
    user = directory.add_user("hello1", member=True)
    c = Client(drs, "LAB-W11")
    joined = c.join("LAB-W11")
    assert joined["MembershipChanges"] == [{"LocalSID": "S-1-5-32-544", "AddSIDs": []}]
    device = directory.devices[str(directory.computers["LAB-W11$"].guid)]
    assert c.cert.subject.rfc4514_string() == f"CN={device.device_id}"
    prt = c.prt("hello1@lab.test", "pw-hello1")
    assert prt["token_type"] == "pop" and len(c.session_key) == 32
    url, result = c.enrol(str(user.guid))
    assert kc.hint == "hello1@lab.test" and url.startswith("https://sso.lab.test/")
    assert result["upn"] == "hello1@lab.test" and result["pctx"]
    (dn, link), = directory.writes
    entries = keycred.parse(keycred.parse_dn_binary(link)[0])
    assert dn == user.dn and entries[keycred.KEY_USAGE] == b"\x01"
    assert uuid.UUID(bytes_le=entries[keycred.DEVICE_ID]) == device.device_id


def test_a_code_is_used_once(drs):
    s, directory, _ = drs
    user = directory.add_user("hello1", member=True)
    c = Client(drs, "LAB-W11")
    c.join("LAB-W11")
    c.prt("hello1@lab.test", "pw-hello1")
    c.enrol(str(user.guid))
    with pytest.raises(Refused, match="already used"):
        s.token({"grant_type": "authorization_code", "code": c.code, "client_id": DRS_CLIENT_ID,
                 "redirect_uri": DRS_REDIRECT_URI})


def test_outside_the_group_never_reaches_keycloak(drs):
    s, directory, kc = drs
    directory.add_user("outsider", member=False)
    c = Client(drs, "LAB-W11")
    c.join("LAB-W11")
    c.prt("outsider@lab.test", "pw-outsider")
    with pytest.raises(Refused, match="may not enrol"):
        c.enrol("ignored")
    assert not hasattr(kc, "state")


def test_keycloak_proving_another_account_is_refused(drs):
    s, directory, _ = drs
    directory.add_user("hello1", member=True)
    c = Client(drs, "LAB-W11")
    c.join("LAB-W11")
    c.prt("hello1@lab.test", "pw-hello1")
    with pytest.raises(SecondFactorError, match="another account"):
        c.enrol(str(uuid.uuid4()))
    assert not directory.writes


def test_a_wrong_password_gets_no_prt(drs):
    s, directory, _ = drs
    directory.add_user("hello1", member=True)
    c = Client(drs, "LAB-W11")
    c.join("LAB-W11")
    with pytest.raises(Refused, match="password"):
        c.prt("hello1@lab.test", "wrong")


def test_a_prt_renews_on_its_own_device_only(drs):
    s, directory, _ = drs
    directory.add_user("hello1", member=True)
    a = Client(drs, "PC-A")
    a.join("PC-A")
    a.prt("hello1@lab.test", "pw-hello1")
    first = a.prt_token
    a.prt(renew=first)
    assert a.prt_token != first and len(a.session_key) == 32
    b = Client(drs, "PC-B")
    b.join("PC-B")
    with pytest.raises(Refused, match="another device"):
        b.prt(renew=a.prt_token)


def test_a_prt_drs_cannot_open_is_invalid_grant(drs):
    s, directory, _ = drs
    directory.add_user("hello1", member=True)
    c = Client(drs, "PC-A")
    c.join("PC-A")
    with pytest.raises(Refused) as refused:
        c.prt(renew="an-AD-FS-issued-PRT")
    assert (refused.value.status, refused.value.error) == (400, "invalid_grant")


def test_kdf_v2_over_the_encoded_payload_verifies():
    session_key, ctx = os.urandom(32), os.urandom(24)
    header = {"alg": "HS256", "kdf_ver": 2, "ctx": base64.b64encode(ctx).decode()}
    payload = json.dumps({"x": 1}).encode()
    signing_input = f"{jose.b64url(json.dumps(header).encode())}.{jose.b64url(payload)}"
    key = jose.derive(session_key, ctx, jose.b64url(payload).encode())
    token = f"{signing_input}.{jose.b64url(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())}"
    assert jose.verify_session_signed(token, session_key) == {"x": 1}


def test_windows_names_the_account_after_sub(drs):
    s, directory, _ = drs
    user = directory.add_user("hello1", member=True)
    c = Client(drs, "PC-A")
    c.join("PC-A")
    claims = json.loads(jose.unb64url(c.prt("hello1@lab.test", "pw-hello1")["id_token"].split(".")[1]))
    assert claims["sub"] == "Hello1" and claims["upn"] == user.upn


def test_a_pin_sign_in_gets_a_prt_with_the_hello_key(drs):
    s, directory, _ = drs
    user = directory.add_user("hello1", member=True)
    a = Client(drs, "PC-A")
    a.join("PC-A")
    a.prt("hello1@lab.test", "pw-hello1")
    a.enrol(str(user.guid))
    a.prt(hello=("hello1@lab.test", a.ngc))
    assert len(a.session_key) == 32
    # Another key, or the same key from another device, gets nothing.
    with pytest.raises(Refused, match="no such Windows Hello key"):
        a.prt(hello=("hello1@lab.test", rsa.generate_private_key(public_exponent=65537, key_size=2048)))
    b = Client(drs, "PC-B")
    b.join("PC-B")
    with pytest.raises(Refused, match="another device"):
        b.prt(hello=("hello1@lab.test", a.ngc))


def test_device_signed_requests_from_other_clients_get_no_prt(drs):
    s, directory, _ = drs
    directory.add_user("hello1", member=True)
    c = Client(drs, "PC-A")
    c.join("PC-A")
    c.prt("hello1@lab.test", "pw-hello1")
    # Windows' retry of a failed Hello set-up: device-signed, the DRS client.
    with pytest.raises(Refused) as refused:
        c.prt(renew=c.prt_token, client_id=DRS_CLIENT_ID)
    assert (refused.value.status, refused.value.error) == (401, "interaction_required")
    with pytest.raises(Refused) as refused:
        c.prt(renew=c.prt_token, client_id="ecd6b820-32c2-49b6-98a6-444530e5a77a")
    assert (refused.value.status, refused.value.error) == (400, "invalid_client")


def _claims(token):
    return json.loads(jose.unb64url(token.split(".")[1]))


def test_session_signed_requests_as_ad_fs_answers_them(drs, monkeypatch):
    s, directory, _ = drs
    user = directory.add_user("hello1", member=True)
    c = Client(drs, "PC-A")
    c.join("PC-A")
    first = c.prt("hello1@lab.test", "pw-hello1")
    c.enrol(str(user.guid))
    hello = c.prt(hello=("hello1@lab.test", c.ngc))
    assert "mfa_auth_time" in _claims(hello["id_token"])
    signed_at = _claims(hello["id_token"])["auth_time"]
    monkeypatch.setattr(time, "time", lambda: signed_at + 600)
    # A renewal signed with the session key: a new PRT, the original sign-in time.
    status, renewed = s.token({"grant_type": JWT_BEARER, "request": c.session_signed(
        {"client_id": "38aa3b87-a06d-4817-b275-7a316988d93b", "grant_type": "refresh_token",
         "scope": "openid aza ugs", "request_nonce": "n1"})})
    assert status == 200 and renewed["refresh_token"] != c.prt_token
    assert _claims(renewed["id_token"])["auth_time"] == signed_at
    assert _claims(renewed["id_token"])["nonce"] == "n1"
    # A first-party client AD FS has never heard of.
    with pytest.raises(Refused) as refused:
        s.token({"grant_type": JWT_BEARER, "request": c.session_signed(
            {"client_id": "ecd6b820-32c2-49b6-98a6-444530e5a77a", "grant_type": "refresh_token",
             "scope": "openid aza profile offline_access"})})
    assert (refused.value.status, refused.value.error) == (400, "invalid_client")
    assert first["token_type"] == "pop"


def test_the_hello_set_up_id_token_names_the_account(drs):
    s, directory, _ = drs
    user = directory.add_user("hello1", member=True)
    c = Client(drs, "PC-A")
    c.join("PC-A")
    c.prt("hello1@lab.test", "pw-hello1")
    c.enrol(str(user.guid))
    claims = _claims(c.setup_tokens["id_token"])
    assert (claims["name"], claims["given_name"], claims["family_name"]) == ("Hello1", "Hello1", "Tester")
