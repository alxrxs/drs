"""drs's HTTP front: TLS (with an optional client certificate, which only a
device DELETE uses), the AD FS paths Windows clients call, Kerberos for the
domain-join token, and one structured log line per request. Logged paths drop
the query string, which can carry codes; no header or body is ever logged."""
import base64
import importlib.resources
import json
import logging
import ssl
import sys
import time
import urllib.parse
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .keycloak import SecondFactorError
from .service import Refused

log = logging.getLogger("drs")
MAX_BODY = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "drs"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    service = None       # set by serve()
    kerberos = None

    def log_message(self, fmt, *args):  # the per-request line is ours, below
        pass

    # --- plumbing ---------------------------------------------------------------

    def _path(self):
        return urllib.parse.urlsplit(self.path).path.rstrip("/").lower()

    def _query(self):
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise Refused(413, "invalid_request", "the body is too large")
        return self.rfile.read(length)

    def _bearer(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise Refused(401, "invalid_token", "no bearer token")
        return auth[7:].strip()

    def _send(self, status, body, content_type="application/json", headers=()):
        data = body if isinstance(body, bytes) else (json.dumps(body) if not isinstance(body, str) else body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)
        self._status = status

    def _refuse(self, e):
        self._reason = e.reason
        if self._path().startswith("/enrollmentserver"):
            body = {"ErrorType": e.error, "Message": e.reason, "TraceId": str(uuid.uuid4()),
                    "Time": time.strftime("%m-%d-%Y %H:%M:%SZ", time.gmtime())}
        else:
            body = {"error": e.error, "error_description": e.reason}
        self._send(e.status, body)

    def _dispatch(self, method):
        start, self._status, self._reason = time.monotonic(), 0, ""
        try:
            self._route(method)
        except Refused as e:
            self._refuse(e)
        except SecondFactorError as e:
            self._refuse(Refused(401, "access_denied", str(e)))
        except Exception:
            log.exception("event=error path=%s", self._path())
            self._refuse(Refused(500, "server_error", "internal error"))
        log.info("event=request method=%s path=%s status=%s ms=%d%s", method, self._path(), self._status,
                 (time.monotonic() - start) * 1000, f' reason="{self._reason}"' if self._reason else "")

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    # --- routes -------------------------------------------------------------------

    def _route(self, method):
        s, path = self.service, self._path()
        if method == "GET" and path == "/enrollmentserver/contract":
            return self._send(200, s.contract(), "application/json; charset=utf-8")
        if method == "GET" and path == "/adfs/.well-known/openid-configuration":
            return self._send(200, s.openid_configuration())
        if method == "GET" and path == "/adfs/services/trust/mex":
            return self._send(200, MEX.replace("{host}", s.c.host), "text/xml; charset=UTF-8")
        if method == "POST" and path == "/adfs/services/trust/2005/windowstransport":
            return self._windowstransport()
        if method == "POST" and path == "/enrollmentserver/device":
            return self._send(200, s.join(self._bearer(), self._body()))
        if method == "PUT" and path.startswith("/enrollmentserver/device/"):
            # Windows updates a device this way after provisioning; AD FS refuses it too.
            raise Refused(400, "AuthenticationError", "device update is not served")
        if method == "DELETE" and path.startswith("/enrollmentserver/device/"):
            s.delete_device(self.connection.getpeercert(binary_form=True), path.rsplit("/", 1)[1])
            return self._send(200, b"")
        if method == "POST" and path == "/adfs/oauth2/token":
            form = dict(urllib.parse.parse_qsl(self._body().decode()))
            status, body = s.token(form)
            return self._send(status, body, "application/json;charset=UTF-8")
        if method == "GET" and path == "/adfs/oauth2/authorize":
            url = s.authorize(self._query(), self.headers.get("x-ms-RefreshTokenCredential"))
            return self._send(302, b"", "text/html", [("Location", url)])
        if method == "GET" and path == "/adfs/drs/keycloak":
            return self._send(200, s.callback(self._query()), "text/html; charset=utf-8")
        if method == "POST" and path == "/enrollmentserver/key":
            return self._send(200, s.provision_key(self._bearer(), self._body()))
        raise Refused(404, "not_found", "no such endpoint")

    def _windowstransport(self):
        """WS-Trust 2005 Issue over Negotiate: the computer proves itself with
        Kerberos and gets the domain-join JWT, as a BinarySecurityToken."""
        self._body()
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Negotiate "):
            return self._send(401, b"", "text/plain", [("WWW-Authenticate", "Negotiate")])
        principal, out_token = self.kerberos.accept(base64.b64decode(auth[10:]))
        jwt = self.service.join_token(principal)
        now = time.time()
        body = RSTR.format(created=_iso(now), expires=_iso(now + 300), resource=self.service.c.resource,
                           token=base64.b64encode(jwt.encode()).decode(), id=uuid.uuid4())
        headers = [("WWW-Authenticate", f"Negotiate {base64.b64encode(out_token).decode()}")] if out_token else []
        self._send(200, body, "application/soap+xml; charset=utf-8", headers)


class Kerberos:
    """The acceptor for HTTP/<host>, from the configured keytab."""

    def __init__(self, keytab, host):
        import gssapi
        self._gssapi = gssapi
        self._creds = gssapi.Credentials(usage="accept", name=gssapi.Name(f"HTTP@{host}",
                                                                          gssapi.NameType.hostbased_service),
                                         store={"keytab": keytab})

    def accept(self, token):
        ctx = self._gssapi.SecurityContext(creds=self._creds, usage="accept")
        # python-gssapi raises a failed step's error again on the next property
        # read, so everything that touches ctx is inside the try.
        try:
            out = ctx.step(token)
            complete, initiator = ctx.complete, str(ctx.initiator_name) if ctx.complete else None
        except self._gssapi.exceptions.GSSError as e:
            log.info("event=kerberos outcome=refused reason=\"%s\"", str(e).split("Minor", 1)[-1].strip()[:200])
            raise Refused(401, "invalid_client", "Kerberos authentication failed") from e
        if not complete:
            raise Refused(401, "invalid_client", "Kerberos needs another round, which drs does not do")
        return initiator, out


def _iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(epoch))


MEX = importlib.resources.files(__package__).joinpath("mex.xml").read_text()

RSTR = ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">'
        '<s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue</a:Action>'
        '</s:Header><s:Body><t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">'
        '<t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        '{created}</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        '{expires}</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">'
        '<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>{resource}</wsa:Address>'
        '</wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><wsse:BinarySecurityToken wsu:Id="_{id}" '
        'ValueType="urn:ietf:params:oauth:token-type:jwt" '
        'EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" '
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{token}'
        '</wsse:BinarySecurityToken></t:RequestedSecurityToken>'
        '<t:TokenType>urn:ietf:params:oauth:token-type:jwt</t:TokenType>'
        '<t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>'
        '<t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>'
        '</t:RequestSecurityTokenResponse></s:Body></s:Envelope>')


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """A client that drops the connection (a keep-alive closed, a failed
        handshake) is one line, not a traceback."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, ssl.SSLError, TimeoutError)):
            log.info("event=connection client=%s outcome=%s", client_address[0], type(exc).__name__)
        else:
            super().handle_error(request, client_address)


def serve(config, service, kerberos):
    Handler.service, Handler.kerberos = service, kerberos
    httpd = Server((config.listen, config.port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(config.tls_cert, config.tls_key)
    # Never ask for a client certificate: Windows' registration client aborts
    # any handshake that does (WinHTTP 0x80072f0c, CLIENT_AUTH_CERT_NEEDED). So
    # DELETE, which proves the device by its certificate, is refused here.
    ctx.verify_mode = ssl.CERT_NONE
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    log.info("event=start host=%s port=%d resource=%s", config.host, config.port, config.resource)
    httpd.serve_forever()
