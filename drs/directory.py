"""Active Directory over LDAPS, as one service account: the reads and the two
writes drs makes. Plain LDAP operations only, so a Windows DC and a Samba DC
take the same code."""
import contextlib
import datetime
import ssl
import uuid
from dataclasses import dataclass

import ldap3
from ldap3.utils.conv import escape_filter_chars

from . import keycred

DEVICE_ATTRS = ["msDS-DeviceID", "altSecurityIdentities", "msDS-KeyCredentialLink", "msDS-IsEnabled"]


@dataclass
class Principal:
    dn: str
    upn: str
    guid: uuid.UUID
    sid: str
    nt_name: str = ""
    display_name: str = ""
    given_name: str = ""
    family_name: str = ""


@dataclass
class Device:
    dn: str
    device_id: uuid.UUID
    enabled: bool
    key_credential_links: list

    def transport_key(self):
        """The device's transport key: the KeyMaterial of its STK key credential."""
        for value in self.key_credential_links:
            blob, _ = keycred.parse_dn_binary(value)
            entries = keycred.parse(blob)
            if entries.get(keycred.KEY_USAGE) == bytes([keycred.KEY_USAGE_STK]):
                return entries[keycred.KEY_MATERIAL]
        return None


@dataclass
class KeyCredential:
    """One msDS-KeyCredentialLink value, as drs reads it."""
    key_id: bytes
    material: bytes
    usage: int
    device_id: uuid.UUID | None

    @classmethod
    def from_value(cls, value):
        entries = keycred.parse(keycred.parse_dn_binary(value)[0])
        device = entries.get(keycred.DEVICE_ID)
        return cls(key_id=entries[keycred.KEY_ID], material=entries[keycred.KEY_MATERIAL],
                   usage=entries[keycred.KEY_USAGE][0], device_id=uuid.UUID(bytes_le=device) if device else None)


class Directory:
    def __init__(self, uri, bind_dn, password, base_dn, devices_dn, ca_file=None):
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file, version=ssl.PROTOCOL_TLS_CLIENT)
        self.servers = [ldap3.Server(u.strip(), use_ssl=True, tls=tls, get_info=ldap3.NONE, connect_timeout=5)
                        for u in uri.split(",")]
        self.bind_dn, self.password = bind_dn, password
        self.base_dn, self.devices_dn = base_dn, devices_dn
        self.domain = ".".join(p.split("=", 1)[1] for p in base_dn.split(",")).upper()

    def _pool(self):
        return ldap3.ServerPool(self.servers, ldap3.FIRST, active=True, exhaust=False)

    @contextlib.contextmanager
    def session(self):
        conn = ldap3.Connection(self._pool(), self.bind_dn, self.password, auto_bind=True,
                                raise_exceptions=True, receive_timeout=15)
        try:
            yield conn
        finally:
            conn.unbind()

    @staticmethod
    def dc_hostname(conn):
        """The DC this connection reached: the pctx names it."""
        return conn.server.host

    # --- reads ---------------------------------------------------------------

    def _principal(self, conn, flt):
        conn.search(self.base_dn, flt, attributes=["userPrincipalName", "objectGUID", "objectSid", "sAMAccountName",
                                                 "displayName", "givenName", "sn"])
        if len(conn.entries) != 1:
            return None
        e = conn.entries[0]
        sam = str(e.sAMAccountName)
        upn = str(e.userPrincipalName) if e.userPrincipalName else f"{sam.lower()}@{self.domain.lower()}"
        return Principal(dn=e.entry_dn, upn=upn, guid=_guid(e.objectGUID), sid=_sid(e.objectSid.raw_values[0]),
                         nt_name=f"{self.domain.split('.')[0]}\\{sam}",
                         display_name=str(e.displayName) if e.displayName else "",
                         given_name=str(e.givenName) if e.givenName else "",
                         family_name=str(e.sn) if e.sn else "")

    def user_by_upn(self, conn, upn):
        return self._principal(conn, "(&(objectCategory=person)(objectClass=user)"
                                     f"(userPrincipalName={escape_filter_chars(upn)}))")

    def computer(self, conn, sam):
        """A computer account by sAMAccountName (NAME$)."""
        return self._principal(conn, f"(&(objectClass=computer)(sAMAccountName={escape_filter_chars(sam)}))")

    def is_member(self, conn, principal, group_dn):
        """Membership, nested included (LDAP_MATCHING_RULE_IN_CHAIN)."""
        conn.search(group_dn, f"(member:1.2.840.113556.1.4.1941:={escape_filter_chars(principal.dn)})",
                    search_scope=ldap3.BASE, attributes=["distinguishedName"])
        return len(conn.entries) == 1

    def domain_guid(self, conn):
        conn.search(self.base_dn, "(objectClass=domain)", search_scope=ldap3.BASE, attributes=["objectGUID"])
        return _guid(conn.entries[0].objectGUID)

    @staticmethod
    def invocation_id(conn):
        """The invocationId of the DSA this connection reached."""
        conn.search("", "(objectClass=*)", search_scope=ldap3.BASE, attributes=["dsServiceName"])
        dsa = str(conn.entries[0].dsServiceName)
        conn.search(dsa, "(objectClass=*)", search_scope=ldap3.BASE, attributes=["invocationId"])
        return _guid(conn.entries[0].invocationId)

    def _device(self, conn, flt):
        conn.search(self.devices_dn, f"(&(objectClass=msDS-Device){flt})", search_scope=ldap3.LEVEL,
                    attributes=DEVICE_ATTRS)
        if len(conn.entries) != 1:
            return None
        e = conn.entries[0]
        return Device(dn=e.entry_dn, device_id=uuid.UUID(bytes_le=e["msDS-DeviceID"].raw_values[0]),
                      enabled=str(e["msDS-IsEnabled"]).upper() != "FALSE",
                      key_credential_links=[v.decode() if isinstance(v, bytes) else str(v)
                                            for v in e["msDS-KeyCredentialLink"].raw_values])

    @staticmethod
    def user_keys(conn, user):
        """The user's key credentials; a value that does not parse is skipped."""
        conn.search(user.dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=["msDS-KeyCredentialLink"])
        keys = []
        for raw in conn.entries[0]["msDS-KeyCredentialLink"].raw_values if conn.entries else []:
            try:
                keys.append(KeyCredential.from_value(raw.decode() if isinstance(raw, bytes) else str(raw)))
            except (ValueError, KeyError, IndexError):
                continue
        return keys

    def device(self, conn, device_id):
        return self._device(conn, f"(msDS-DeviceID={_guid_filter(device_id)})")

    def device_by_alt_security_identity(self, conn, value):
        return self._device(conn, f"(altSecurityIdentities={escape_filter_chars(value)})")

    # --- writes --------------------------------------------------------------

    def upsert_device(self, conn, device_id, owner_sid, alt_security_identity, transport_key,
                      os_type, os_version, display_name):
        """[MS-DVRJ] 3.1.5.1.1.3 steps 4-6: create or update the msDS-Device.
        The transport key replaces every earlier key on the object."""
        now = keycred.filetime(datetime.datetime.now(datetime.timezone.utc))
        existing = self.device(conn, device_id)
        dn = existing.dn if existing else f"CN={device_id},{self.devices_dn}"
        link = keycred.KeyCredential(key_material=transport_key, key_usage=keycred.KEY_USAGE_STK,
                                     device_id=device_id, created=now).to_dn_binary(dn)
        attrs = {
            "msDS-DeviceOSType": os_type, "msDS-DeviceOSVersion": os_version, "displayName": display_name,
            "msDS-RegisteredUsers": owner_sid, "msDS-RegisteredOwner": owner_sid,
            "msDS-IsEnabled": True, "msDS-DeviceTrustType": 2, "msDS-DeviceObjectVersion": 2,
            "msDS-CloudIsManaged": False, "msDS-IsManaged": False,
            "msDS-ApproximateLastLogonTimeStamp": now, "msDS-KeyCredentialLink": link,
        }
        # Without the schema, ldap3 would send True as "True"; LDAP wants TRUE.
        attrs = {k: ("TRUE" if v else "FALSE") if isinstance(v, bool) else str(v) if isinstance(v, int) else v
                 for k, v in attrs.items()}
        if existing:
            changes = {k: [(ldap3.MODIFY_REPLACE, [v])] for k, v in attrs.items()}
            changes["altSecurityIdentities"] = [(ldap3.MODIFY_ADD, [alt_security_identity])]
            conn.modify(dn, changes)
        else:
            # The key credential's DN-Binary value names the device itself, which
            # Samba refuses before the object exists (Windows accepts it), so the
            # key goes in a second write.
            link = attrs.pop("msDS-KeyCredentialLink")
            conn.add(dn, ["top", "msDS-Device"], {**attrs, "msDS-DeviceID": device_id.bytes_le,
                                                  "altSecurityIdentities": alt_security_identity})
            conn.modify(dn, {"msDS-KeyCredentialLink": [(ldap3.MODIFY_REPLACE, [link])]})
        return dn

    @classmethod
    def add_ngc_key(cls, conn, user, device_id, key_material):
        """[MS-KPP] 3.1.5.1.1.3 step 4: the user's NGC key for this device.
        Written as AD FS writes it (lab capture, Server 2025): DeviceId present,
        and CustomKeyInformation flags 0, not the 0x02 the specification states.
        A device holds one Hello container per user, and a PIN reset or
        re-enrolment replaces it without telling the server, so the user's
        earlier NGC keys bound to this device are removed in the same write."""
        link = keycred.KeyCredential(key_material=key_material, key_usage=keycred.KEY_USAGE_NGC,
                                     device_id=device_id, flags=0).to_dn_binary(user.dn)
        conn.search(user.dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=["msDS-KeyCredentialLink"])
        stale = []
        for raw in conn.entries[0]["msDS-KeyCredentialLink"].raw_values if conn.entries else []:
            value = raw.decode() if isinstance(raw, bytes) else str(raw)
            try:
                key = KeyCredential.from_value(value)
            except (ValueError, KeyError, IndexError):
                continue
            if key.usage == keycred.KEY_USAGE_NGC and key.device_id == device_id:
                stale.append(value)
        changes = [(ldap3.MODIFY_ADD, [link])]
        if stale:
            changes.insert(0, (ldap3.MODIFY_DELETE, stale))
        conn.modify(user.dn, {"msDS-KeyCredentialLink": changes})
        return link

    @staticmethod
    def delete_device(conn, dn):
        conn.delete(dn)

    def check_password(self, user_dn, password):
        """A simple bind as the user over LDAPS. Never stored, never logged."""
        if not password:
            return False
        try:
            ldap3.Connection(self._pool(), user_dn, password, auto_bind=True, raise_exceptions=True,
                             receive_timeout=15).unbind()
            return True
        except ldap3.core.exceptions.LDAPBindError:
            return False


def _guid(attribute):
    """A GUID attribute as ldap3 returns it without the schema: its 16 raw
    (mixed-endian) bytes."""
    return uuid.UUID(bytes_le=attribute.raw_values[0])


def _sid(raw):
    """A binary SID as S-1-<authority>-<sub>...: revision, count, 48-bit
    big-endian authority, then little-endian 32-bit sub-authorities."""
    count = raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    subs = [int.from_bytes(raw[8 + 4 * i:12 + 4 * i], "little") for i in range(count)]
    return "-".join(["S", str(raw[0]), str(authority)] + [str(s) for s in subs])


def _guid_filter(guid):
    """A GUID as an LDAP filter value: its mixed-endian bytes, each escaped."""
    return "".join(f"\\{b:02x}" for b in guid.bytes_le)
