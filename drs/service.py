"""The protocol: what each endpoint does, as plain methods over parsed requests,
so tests drive it without HTTP. drs serves AD FS's own paths at the same
federation host, so it replaces an AD FS DRS in place: already-joined clients
and the device-registration SCP keep working.

The sequence a domain-joined Windows client runs (lab capture, Windows 11 26H2
against Server 2025 AD FS; see FINDINGS.md):
  1. device join, as the computer (Automatic-Device-Join): contract -> mex ->
     WS-Trust windowstransport (Kerberos) -> POST /EnrollmentServer/device/
  2. at user sign-in: srv_challenge -> device-signed password grant: the PRT
  3. at PIN setup: session-signed refresh for urn:ms-drs with amr_values=ngcmfa
     -> interaction_required -> /authorize (the web view, carrying the PRT in
     x-ms-RefreshTokenCredential) -> second factor -> code -> token -> the
     ngcmfa access token -> POST /EnrollmentServer/key/
"""
import base64
import datetime
import hashlib
import html
import json
import logging
import os
import secrets
import threading
import time
import urllib.parse
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding

from . import jose, keycred, pki
from .seal import SealError

log = logging.getLogger("drs")

# The Windows broker and the DRS client, as Windows names them ([MS-OAPXBC]).
BROKER_CLIENT_ID = "38aa3b87-a06d-4817-b275-7a316988d93b"
DRS_CLIENT_ID = "dd762716-544d-4aeb-a526-687b73838a22"
DRS_REDIRECT_URI = f"ms-appx-web://Microsoft.AAD.BrokerPlugin/{DRS_CLIENT_ID}"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"

NONCE_TTL = 300
PRT_TTL = 14 * 86400
CODE_TTL = 120
ACCESS_TTL = 300
STATE_TTL = 600

AMR_NGC_MFA = ["http://schemas.microsoft.com/claims/multipleauthn", "http://schemas.microsoft.com/claims/ngcmfa"]


class Refused(Exception):
    """A request drs refuses: HTTP status, an error code and a reason. The
    reason is logged and returned; it never carries a token or a secret."""

    def __init__(self, status, error, reason):
        super().__init__(reason)
        self.status, self.error, self.reason = status, error, reason


class Service:
    def __init__(self, config, directory, issuer, signer, signing_cert, sealer, keycloak):
        self.c = config
        self.dir = directory
        self.issuer = issuer
        self.signer = signer
        self.signing_cert = signing_cert
        self.sealer = sealer
        self.keycloak = keycloak
        self._used = {}
        self._used_lock = threading.Lock()

    # --- metadata -------------------------------------------------------------

    def contract(self):
        """[MS-DVRD]: every endpoint a client needs, all on this host."""
        b, r = self.c.base_url, self.c.resource
        return {
            "DeviceRegistrationService": {"RegistrationEndpoint": f"{b}/EnrollmentServer/DeviceEnrollmentWebService.svc",
                                          "RegistrationResourceId": r, "ServiceVersion": "1.0"},
            "AuthenticationService": {"OAuth2": {"AuthCodeEndpoint": f"{b}/adfs/oauth2/authorize",
                                                 "TokenEndpoint": f"{b}/adfs/oauth2/token"}},
            "IdentityProviderService": {"PassiveAuthEndpoint": f"{b}/adfs/ls"},
            "DeviceJoinService": {"JoinEndpoint": f"{b}/EnrollmentServer/device/", "JoinResourceId": r,
                                  "ServiceVersion": "1.0"},
            "WebBrowserZones": {"Intranet": {"Endpoints": [f"{b}/"]}, "Trusted": None, "Untrusted": None},
            "KeyProvisioningService": {"KeyProvisionEndpoint": f"{b}/EnrollmentServer/key/",
                                       "KeyProvisionResourceId": r, "ServiceVersion": "1.0"},
        }

    def openid_configuration(self):
        b = self.c.base_url
        return {
            "issuer": f"{b}/adfs",
            "authorization_endpoint": f"{b}/adfs/oauth2/authorize/",
            "token_endpoint": f"{b}/adfs/oauth2/token/",
            "jwks_uri": f"{b}/adfs/discovery/keys",
            "response_types_supported": ["code"],
            "response_modes_supported": ["form_post"],
            "grant_types_supported": ["authorization_code", JWT_BEARER, "srv_challenge"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "access_token_issuer": f"http://{self.c.host}/adfs/services/trust",
            # The broker uses KDFv2 only when the server says it can.
            "capabilities": ["kdf_ver2"],
        }

    # --- device join: the computer's token, then the device ---------------------

    def join_token(self, principal):
        """The JWT windowstransport issues to a domain computer that proved itself
        with Kerberos ([MS-DVRJ] 3.1.5.1.1.3 step 1 lists what the join checks)."""
        sam = principal.split("@", 1)[0]
        with self.dir.session() as conn:
            computer = self.dir.computer(conn, sam)
        if computer is None:
            raise Refused(401, "invalid_grant", f"no computer account {sam}")
        guid_b64 = base64.b64encode(computer.guid.bytes_le).decode()
        now = int(time.time())
        claims = {
            "aud": self.c.resource, "iss": f"http://{self.c.host}/adfs/services/trust",
            "iat": now, "nbf": now, "exp": now + ACCESS_TTL,
            "upn": computer.upn, "primarysid": computer.sid, "unique_name": computer.nt_name,
            "http://schemas.microsoft.com/authorization/claims/PermitDeviceRegistration": "true",
            "http://schemas.microsoft.com/ws/2012/01/accounttype": "DJ",
            "http://schemas.microsoft.com/identity/claims/onpremobjectguid": guid_b64,
            "http://schemas.microsoft.com/identity/claims/objectidentifier": guid_b64,
            "authmethod": "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows",
            "ver": "1.0",
        }
        log.info("event=join_token computer=%s outcome=issued", sam)
        return jose.sign_rs256(claims, self.signer, kid=self._x5t(), x5t=self._x5t())

    def join(self, bearer, body):
        """[MS-DVRJ] 3.1.5.1.1: register (or re-register) a domain-joined device."""
        claims = self._verify_own(bearer)
        if claims.get("http://schemas.microsoft.com/ws/2012/01/accounttype") != "DJ" or \
                claims.get("http://schemas.microsoft.com/authorization/claims/PermitDeviceRegistration") != "true":
            raise Refused(400, "invalid_request", "the token is not a domain-join token")
        req = _json_body(body)
        if (req.get("CertificateRequest") or {}).get("Type") != "pkcs10" or req.get("JoinType") != 6:
            raise Refused(400, "invalid_request", "not a JoinType 6 pkcs10 request")
        device_id = uuid.UUID(bytes_le=base64.b64decode(claims["http://schemas.microsoft.com/identity/claims/onpremobjectguid"]))
        transport_key = base64.b64decode(req["TransportKey"])
        jose.rsa_public_key(transport_key)  # refuse a key nothing could encrypt to
        with self.dir.session() as conn:
            cert = self.issuer.device_certificate(base64.b64decode(req["CertificateRequest"]["Data"]), device_id,
                                                  device_id, self.dir.domain_guid(conn), self.dir.invocation_id(conn))
            self.dir.upsert_device(conn, device_id, claims["primarysid"], pki.alt_security_identity(cert),
                                   transport_key, req.get("DeviceType", "Windows"), req.get("OSVersion", ""),
                                   req.get("DeviceDisplayName", ""))
        log.info("event=device_join device=%s computer=%s outcome=joined", device_id, claims.get("upn"))
        return {"Certificate": {"Thumbprint": pki.thumbprint(cert),
                                "RawBody": base64.b64encode(cert.public_bytes(Encoding.DER)).decode()},
                "User": {"Upn": claims.get("upn")},
                "MembershipChanges": [{"LocalSID": "S-1-5-32-544", "AddSIDs": []}]}

    def delete_device(self, client_cert_der, device_id):
        """[MS-DVRJ] 3.1.5.1.2: the device, proving itself with its certificate."""
        if not client_cert_der:
            raise Refused(401, "invalid_client", "no client certificate")
        cert = x509.load_der_x509_certificate(client_cert_der)
        with self.dir.session() as conn:
            device = self.dir.device_by_alt_security_identity(conn, pki.alt_security_identity(cert))
            if device is None or str(device.device_id) != str(uuid.UUID(device_id)):
                raise Refused(401, "invalid_client", "the certificate is not that device's")
            self.dir.delete_device(conn, device.dn)
        log.info("event=device_delete device=%s outcome=deleted", device_id)

    # --- the token endpoint -------------------------------------------------------

    def token(self, form):
        grant = form.get("grant_type")
        if grant == "srv_challenge":
            return 200, {"Nonce": self.sealer.seal("nonce", {"n": secrets.token_urlsafe(16)}, NONCE_TTL)}
        if grant == "authorization_code":
            return 200, self._redeem(form)
        if grant == JWT_BEARER and form.get("request"):
            header = json.loads(jose.unb64url(form["request"].split(".")[0]))
            if header.get("alg") == "RS256" and header.get("x5c"):
                return 200, self._device_signed(form["request"], header)
            if header.get("alg") == "HS256":
                return self._session_signed(form)
        raise Refused(400, "unsupported_grant_type", f"grant {grant!r} is not served")

    def _device_signed(self, request, header):
        """[MS-OAPXBC] 3.2.5.1.2: a request the device signs with its certificate
        -- a new PRT for the password Windows relays at sign-in, or a renewal of
        one drs issued to that same device. A renewal drs cannot open (one AD FS
        issued, or sealed under an older state key) is invalid_grant, so the
        client falls back to its password at the next sign-in."""
        cert = x509.load_der_x509_certificate(base64.b64decode(header["x5c"] if isinstance(header["x5c"], str)
                                                               else header["x5c"][0]))
        try:
            _, claims = jose.verify_rs256(request, cert.public_key())
        except Exception as e:
            raise Refused(400, "invalid_grant", "the device's signature does not verify") from e
        self._check_nonce(claims.get("request_nonce"))
        grant = claims.get("grant_type")
        # Only the broker gets a PRT. Windows retries a failed Hello set-up as
        # the DRS client on this path, and a PRT handed to that request leaves
        # it with a stale one (0x801C044D; a second lab): AD FS sends it back to
        # /authorize instead.
        client_id = claims.get("client_id", BROKER_CLIENT_ID)
        if client_id == DRS_CLIENT_ID:
            raise Refused(401, "interaction_required",
                          "MSIS9700: The JWT bearer request requires fresh authentication.")
        if client_id != BROKER_CLIENT_ID:
            raise Refused(400, "invalid_client", "MSIS9607: The 'client_id' parameter in the request is invalid. "
                                                 "No registered client is found with this identifier.")
        if grant not in ("password", "refresh_token", JWT_BEARER):
            # What AD FS answers too (device_token, for instance).
            raise Refused(400, "invalid_request", f"device-signed grant {grant!r} is not served")
        with self.dir.session() as conn:
            device = self.dir.device_by_alt_security_identity(conn, pki.alt_security_identity(cert))
            if device is None or not device.enabled:
                raise Refused(400, "invalid_grant", "the certificate is not a registered, enabled device's")
            if grant == "refresh_token":
                old = self._open_prt(claims.get("refresh_token", ""))
                if old["device"] != str(device.device_id):
                    raise Refused(400, "invalid_grant", "the PRT belongs to another device")
                user = self.dir.user_by_upn(conn, old["upn"])
                if user is None:
                    raise Refused(400, "invalid_grant", "the PRT's user no longer exists")
            elif grant == JWT_BEARER:
                user = self._hello_assertion(conn, claims, device)
            else:
                upn = claims.get("username", "")
                user = self.dir.user_by_upn(conn, upn)
                if user is None or not self.dir.check_password(user.dn, claims.get("password", "")):
                    log.info("event=prt user=%s device=%s outcome=refused reason=bad_credentials", upn,
                             device.device_id)
                    raise Refused(400, "invalid_grant", "the user name or password is wrong")
        # A renewal keeps the original sign-in's times (as AD FS does); a Hello-key
        # sign-in is a fresh multi-factor one; a password sign-in is fresh.
        now = int(time.time())
        if grant == "refresh_token":
            auth_time, mfa = old.get("at", now), old.get("mfa")
        else:
            auth_time, mfa = now, now if grant == JWT_BEARER else None
        return self._issue_prt(user, device, grant, claims.get("client_id", BROKER_CLIENT_ID),
                               claims.get("request_nonce"), auth_time, mfa)

    def _issue_prt(self, user, device, grant, client_id, nonce, auth_time, mfa):
        """A new PRT and its session key, wrapped to the device's transport key."""
        transport = device.transport_key()
        if transport is None:
            raise Refused(400, "invalid_grant", "the device holds no transport key")
        session_key = os.urandom(32)
        prt = self.sealer.seal("prt", {"upn": user.upn, "sid": user.sid, "guid": str(user.guid),
                                       "device": str(device.device_id),
                                       "at": auth_time, "mfa": mfa,
                                       "sk": base64.b64encode(session_key).decode()}, PRT_TTL)
        log.info("event=prt user=%s device=%s grant=%s outcome=issued", user.upn, device.device_id, grant)
        return {"token_type": "pop", "refresh_token": prt, "refresh_token_expires_in": PRT_TTL,
                "session_key_jwe": jose.session_key_jwe(session_key, transport),
                "id_token": self._id_token(user, client_id, nonce, mfa=mfa, auth_time=auth_time)}

    def _hello_assertion(self, conn, claims, device):
        """[MS-OAPXBC] 3.2.5.1.2.1.2: the user, from an assertion signed with
        their Windows Hello key -- what Windows sends at a PIN or biometric
        sign-in. `kid` is the key's KeyID (base64 SHA-256 of its material);
        the key must be the user's, NGC, and bound to the requesting device."""
        try:
            header, payload, signing_input, sig = jose.split_jws(claims.get("assertion", ""))
            body = json.loads(payload)
        except Exception as e:
            raise Refused(400, "invalid_grant", "the assertion is not a JWT") from e
        now = time.time()
        if header.get("alg") != "RS256" or body.get("request_nonce") != claims.get("request_nonce") or \
                str(body.get("aud", "")).lower().rstrip("/") != f"{self.c.base_url}/adfs/ls".lower() or \
                not _number(body.get("exp")) > now:
            raise Refused(400, "invalid_grant", "the assertion is not for this request")
        user = self.dir.user_by_upn(conn, body.get("iss", ""))
        key = user and next((k for k in self.dir.user_keys(conn, user)
                             if base64.b64encode(k.key_id).decode() == header.get("kid")), None)
        if key is None or key.usage != keycred.KEY_USAGE_NGC:
            raise Refused(400, "invalid_grant", "no such Windows Hello key")
        if key.device_id is not None and key.device_id != device.device_id:
            raise Refused(400, "invalid_grant", "the key is bound to another device")
        try:
            jose.rsa_public_key(key.material).verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except Exception as e:
            raise Refused(400, "invalid_grant", "the assertion's signature does not verify") from e
        return user

    def _session_signed(self, form):
        """[MS-OAPXBC] 3.2.5.1.3: a request signed with the PRT's session key. A
        token for the DRS with ngcmfa always needs the second factor afresh, as
        on AD FS: the answer sends the client to /authorize."""
        prt, claims = self._open_session_signed(form["request"])
        resource = claims.get("resource") or form.get("resource") or ""
        client_id = claims.get("client_id") or form.get("client_id") or ""
        if resource.lower().startswith("urn:ms-drs:"):
            log.info("event=token user=%s device=%s outcome=interaction_required", prt["upn"], prt["device"])
            return 401, {"error": "interaction_required",
                         "error_description": "MSIS9700: The JWT bearer request requires fresh authentication."}
        if client_id == BROKER_CLIENT_ID and claims.get("grant_type") == "refresh_token":
            # A PRT renewal signed with the PRT's own session key (a second lab's AD FS
            # capture): a whole new PRT, keeping the original sign-in's times.
            with self.dir.session() as conn:
                device = self.dir.device(conn, uuid.UUID(prt["device"]))
                user = self.dir.user_by_upn(conn, prt["upn"])
            if device is None or not device.enabled or user is None:
                raise Refused(400, "invalid_grant", "the PRT's device or user no longer exists")
            return 200, self._issue_prt(user, device, "refresh_token", client_id, claims.get("request_nonce"),
                                        prt.get("at", int(time.time())), prt.get("mfa"))
        if client_id not in (BROKER_CLIENT_ID, DRS_CLIENT_ID):
            raise Refused(400, "invalid_client", "MSIS9607: The 'client_id' parameter in the request is invalid. "
                                                 "No registered client is found with this identifier.")
        raise Refused(400, "invalid_request", "only the DRS resource is served")

    def _open_session_signed(self, request):
        header = json.loads(jose.unb64url(request.split(".")[0]))
        claims = json.loads(jose.unb64url(request.split(".")[1]))
        prt = self._open_prt(claims.get("refresh_token", ""))
        try:
            jose.verify_session_signed(request, base64.b64decode(prt["sk"]))
        except ValueError as e:
            raise Refused(400, "invalid_grant", "the session-key signature does not verify") from e
        return prt, claims

    def _open_prt(self, token):
        try:
            return self.sealer.open("prt", token)
        except SealError as e:
            raise Refused(400, "invalid_grant", str(e)) from e

    # --- /authorize: the second factor at Keycloak --------------------------------

    def authorize(self, query, prt_cookie):
        """The Hello web view: who it is comes from the PRT it carries, never from a
        parameter; the second factor is Keycloak's. Returns the Keycloak URL."""
        if query.get("client_id") != DRS_CLIENT_ID or query.get("redirect_uri") != DRS_REDIRECT_URI:
            raise Refused(400, "invalid_request", "only the Windows DRS client is served")
        if not prt_cookie or prt_cookie == "NA":
            raise Refused(401, "login_required", "no PRT on the request")
        prt, _ = self._open_session_signed(prt_cookie)
        with self.dir.session() as conn:
            user = self.dir.user_by_upn(conn, prt["upn"])
            allowed = user is not None and self.dir.is_member(conn, user, self.c.ldap_enrol_group_dn)
        if not allowed:
            log.info("event=authorize user=%s outcome=refused reason=not_in_enrol_group", prt["upn"])
            raise Refused(403, "access_denied", "the user may not enrol Windows Hello")
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(24)
        state = self.sealer.seal("state", {"upn": prt["upn"], "sid": prt["sid"], "guid": prt["guid"],
                                           "device": prt["device"], "v": verifier, "n": nonce}, STATE_TTL)
        log.info("event=authorize user=%s device=%s outcome=to_keycloak", prt["upn"], prt["device"])
        return self.keycloak.authorization_url(state, nonce, verifier, prt["upn"], self._callback_uri())

    def callback(self, query):
        """Back from Keycloak: check the second factor, then hand the web view an
        authorization code for the DRS token, as a form post to its redirect URI."""
        try:
            state = self.sealer.open("state", query.get("state", ""))
        except SealError as e:
            raise Refused(400, "invalid_request", str(e)) from e
        if query.get("error"):
            raise Refused(401, "access_denied", f"Keycloak: {query['error']}")
        claims = self.keycloak.redeem(query.get("code", ""), state["v"], self._callback_uri())
        self.keycloak.check(claims, state["n"], state["guid"])
        code = self.sealer.seal("code", {k: state[k] for k in ("upn", "sid", "guid", "device")}
                                | {"jti": secrets.token_urlsafe(12), "mfa": int(time.time())}, CODE_TTL)
        log.info("event=second_factor user=%s device=%s outcome=passed acr=%s", state["upn"], state["device"],
                 claims.get("acr"))
        return (f'<html><head><title>Working...</title></head><body><form method="POST" name="hiddenform" '
                f'action="{html.escape(DRS_REDIRECT_URI.lower())}"><input type="hidden" name="code" '
                f'value="{html.escape(code)}" /><noscript><p>Script is disabled. Click Submit to continue.</p>'
                f'<input type="submit" value="Submit" /></noscript></form><script language="javascript">'
                f"window.setTimeout('document.forms[0].submit()', 0);</script></body></html>")

    def _redeem(self, form):
        if form.get("client_id") != DRS_CLIENT_ID or form.get("redirect_uri") != DRS_REDIRECT_URI:
            raise Refused(400, "invalid_client", "only the Windows DRS client is served")
        try:
            code = self.sealer.open("code", form.get("code", ""))
        except SealError as e:
            raise Refused(400, "invalid_grant", str(e)) from e
        self._once(code["jti"], CODE_TTL)
        # Read afresh: this id_token is the one Windows names the work account from.
        with self.dir.session() as conn:
            user = self.dir.user_by_upn(conn, code["upn"])
        if user is None or str(user.guid) != code["guid"]:
            raise Refused(400, "invalid_grant", "the user no longer exists")
        log.info("event=token user=%s device=%s outcome=ngcmfa_issued", code["upn"], code["device"])
        return {"access_token": self._access_token(code), "token_type": "bearer", "expires_in": ACCESS_TTL,
                "resource": self.c.resource, "id_token": self._id_token(user, DRS_CLIENT_ID, None, mfa=code["mfa"])}

    # --- key provisioning ---------------------------------------------------------

    def provision_key(self, bearer, body):
        """[MS-KPP] 3.1.5.1.1: one more NGC key on the user."""
        claims = self._verify_own(bearer)
        if not set(AMR_NGC_MFA) & set(claims.get("amr") or []):
            raise Refused(401, "invalid_token", "the token carries no second factor")
        req = _json_body(body)
        material = base64.b64decode(req.get("kngc", ""))
        jose.rsa_public_key(material)  # a key the KDC could use
        device_id = uuid.UUID(claims["deviceid"])
        with self.dir.session() as conn:
            if self.dir.device(conn, device_id) is None:
                raise Refused(401, "invalid_token", "no such device")
            user = self.dir.user_by_upn(conn, claims["upn"])
            if user is None or str(user.guid) != claims.get("user_guid"):
                raise Refused(400, "invalid_request", "the user is not the one the second factor proved")
            if not self.dir.is_member(conn, user, self.c.ldap_enrol_group_dn):
                raise Refused(403, "access_denied", "the user may not enrol Windows Hello")
            self.dir.add_ngc_key(conn, user, device_id, material)
            dc = self.dir.dc_hostname(conn)
        kid = str(uuid.uuid4())
        log.info("event=key user=%s device=%s outcome=provisioned key_id=%s", user.upn, device_id,
                 base64.b64encode(hashlib.sha256(material).digest()).decode())
        return {"kid": kid, "upn": user.upn, "pctx": self.issuer.pctx(dc)}

    # --- tokens drs signs ------------------------------------------------------------

    def _access_token(self, code):
        now = int(time.time())
        return jose.sign_rs256({
            "aud": self.c.resource, "iss": f"http://{self.c.host}/adfs/services/trust",
            "iat": now, "nbf": now, "exp": now + ACCESS_TTL,
            "deviceid": code["device"], "upn": code["upn"], "primarysid": code["sid"],
            "user_guid": code["guid"],
            "amr": AMR_NGC_MFA, "mfa_auth_time": _iso(code["mfa"]), "appid": DRS_CLIENT_ID, "ver": "1.0",
        }, self.signer, kid=self._x5t(), x5t=self._x5t())

    def _id_token(self, user, audience, nonce, mfa=None, auth_time=None):
        now = int(time.time())
        claims = {"aud": audience, "iss": f"{self.c.base_url}/adfs", "iat": now, "nbf": now, "exp": now + 3600,
                  # Windows labels the Hello work account with `sub` when it creates it
                  # (FINDINGS), so it carries the display name; drs never reads it back.
                  "auth_time": auth_time or now, "sub": user.display_name or user.upn,
                  "upn": user.upn, "unique_name": user.upn, "sid": user.sid}
        # The Hello set-up's id_token names the work account (FINDINGS); a claim
        # AD has no value for is left out, as AD FS leaves it out.
        for claim, value in (("name", user.display_name), ("given_name", user.given_name),
                             ("family_name", user.family_name)):
            if value:
                claims[claim] = value
        if nonce:
            claims["nonce"] = nonce
        if mfa:
            claims["mfa_auth_time"] = mfa
        return jose.sign_rs256(claims, self.signer, kid=self._x5t(), x5t=self._x5t())

    def _verify_own(self, bearer):
        try:
            _, claims = jose.verify_rs256(bearer, self.signing_cert.public_key())
        except Exception as e:
            raise Refused(401, "invalid_token", "not a token drs issued") from e
        now = time.time()
        if claims.get("aud") != self.c.resource or not claims.get("nbf", 0) - 60 <= now <= claims.get("exp", 0):
            raise Refused(401, "invalid_token", "the token is expired or for another audience")
        return claims

    def _check_nonce(self, nonce):
        try:
            self.sealer.open("nonce", nonce or "")
        except SealError as e:
            raise Refused(400, "invalid_grant", str(e)) from e

    def _once(self, jti, ttl):
        now = time.time()
        with self._used_lock:
            for k in [k for k, exp in self._used.items() if exp < now]:
                del self._used[k]
            if jti in self._used:
                raise Refused(400, "invalid_grant", "the code was already used")
            self._used[jti] = now + ttl

    def _x5t(self):
        return jose.b64url(self.signing_cert.fingerprint(hashes.SHA1()))

    def _callback_uri(self):
        return f"{self.c.base_url}/adfs/drs/keycloak"


def _json_body(body):
    """JSON from a Windows client, which ends the body with a NUL byte."""
    try:
        return json.loads(body.rstrip(b"\x00").decode("utf-8"))
    except ValueError as e:
        raise Refused(400, "invalid_request", "the body is not JSON") from e


def _number(value):
    """A JWT time claim, which Windows sends as a string ("1794345836")."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _iso(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
