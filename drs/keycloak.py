"""The second factor: an OpenID Connect authorization-code flow (PKCE) to the
Keycloak client whose flow always demands TOTP or a passkey. drs trusts the
result only after checking the ID token's signature, issuer, audience, nonce,
freshness (auth_time), the acr that flow sets, and that the AD objectGUID it
carries is the account being enrolled."""
import base64
import hashlib
import json
import ssl
import threading
import time
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa

from . import jose


class SecondFactorError(Exception):
    pass


class Keycloak:
    def __init__(self, issuer, client_id, client_secret, acr, guid_claim, max_age=120, ca_file=None):
        self.issuer, self.client_id, self.client_secret = issuer.rstrip("/"), client_id, client_secret
        self.acr, self.guid_claim, self.max_age = acr, guid_claim, max_age
        self._ctx = ssl.create_default_context(cafile=ca_file)
        self._meta, self._keys, self._lock = None, {}, threading.Lock()

    def _get(self, url):
        with urllib.request.urlopen(url, context=self._ctx, timeout=10) as r:
            return json.load(r)

    def _metadata(self):
        if self._meta is None:
            self._meta = self._get(f"{self.issuer}/.well-known/openid-configuration")
            if self._meta.get("issuer") != self.issuer:
                raise SecondFactorError("Keycloak's metadata names another issuer")
        return self._meta

    def _key(self, kid):
        with self._lock:
            if kid not in self._keys:  # a rotated key: fetch the set again
                self._keys = {k["kid"]: rsa.RSAPublicNumbers(int.from_bytes(jose.unb64url(k["e"]), "big"),
                                                             int.from_bytes(jose.unb64url(k["n"]), "big")).public_key()
                              for k in self._get(self._metadata()["jwks_uri"])["keys"]
                              if k.get("kty") == "RSA" and k.get("use", "sig") == "sig"}
            if kid not in self._keys:
                raise SecondFactorError(f"Keycloak has no signing key {kid}")
            return self._keys[kid]

    def authorization_url(self, state, nonce, verifier, login_hint, redirect_uri):
        challenge = jose.b64url(hashlib.sha256(verifier.encode()).digest())
        query = {"response_type": "code", "client_id": self.client_id, "redirect_uri": redirect_uri,
                 "scope": "openid", "state": state, "nonce": nonce, "code_challenge": challenge,
                 "code_challenge_method": "S256", "login_hint": login_hint, "prompt": "login",
                 "max_age": "0", "acr_values": self.acr}
        return f"{self._metadata()['authorization_endpoint']}?{urllib.parse.urlencode(query)}"

    def redeem(self, code, verifier, redirect_uri):
        """The code for an ID token, at Keycloak's token endpoint, as the client."""
        body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code,
                                       "redirect_uri": redirect_uri, "code_verifier": verifier}).encode()
        auth = base64.b64encode(f"{urllib.parse.quote(self.client_id)}:{urllib.parse.quote(self.client_secret)}"
                                .encode()).decode()
        req = urllib.request.Request(self._metadata()["token_endpoint"], data=body,
                                     headers={"Authorization": f"Basic {auth}",
                                              "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as r:
                id_token = json.load(r)["id_token"]
        except Exception as e:
            raise SecondFactorError("Keycloak refused the code") from e
        header = json.loads(jose.unb64url(id_token.split(".")[0]))
        try:
            _, claims = jose.verify_rs256(id_token, self._key(header.get("kid")))
        except Exception as e:
            raise SecondFactorError("the ID token's signature does not verify") from e
        return claims

    def check(self, claims, nonce, user_guid):
        now = time.time()
        aud = claims.get("aud")
        if claims.get("iss") != self.issuer or (aud != self.client_id and self.client_id not in (aud or [])):
            raise SecondFactorError("the ID token is not Keycloak's for drs")
        if claims.get("nonce") != nonce:
            raise SecondFactorError("the ID token's nonce is not this request's")
        if not claims.get("exp", 0) > now or now - claims.get("auth_time", 0) > self.max_age:
            raise SecondFactorError("the second factor is not fresh")
        if claims.get("acr") != self.acr:
            raise SecondFactorError(f"the sign-in did not pass the second-factor flow (acr {claims.get('acr')!r})")
        if _guid(claims.get(self.guid_claim)) != user_guid.lower():
            raise SecondFactorError("Keycloak proved another account than the one enrolling")


def _guid(value):
    """objectGUID as Keycloak's LDAP federation may hand it over: the GUID's
    text, or its 16 bytes base64."""
    if not value:
        return ""
    try:
        return str(uuid.UUID(value)).lower()
    except ValueError:
        return str(uuid.UUID(bytes_le=base64.b64decode(value))).lower()
