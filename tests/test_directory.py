"""The directory's writes, against ldap3's in-memory server."""
import uuid

import ldap3
from cryptography.hazmat.primitives.asymmetric import rsa
from roadtools.roadlib.deviceauth import DeviceAuthentication

from drs import keycred
from drs.directory import Directory, KeyCredential, Principal

DN = "CN=hello1,OU=People,DC=lab,DC=test"


def _material():
    return DeviceAuthentication().create_pubkey_blob_from_key(
        rsa.generate_private_key(public_exponent=65537, key_size=2048))


def _keys(conn):
    conn.search(DN, "(objectClass=*)", search_scope=ldap3.BASE, attributes=["msDS-KeyCredentialLink"])
    return [KeyCredential.from_value(v.decode() if isinstance(v, bytes) else v)
            for v in conn.entries[0]["msDS-KeyCredentialLink"].raw_values]


def test_a_new_key_replaces_that_devices_earlier_one_only():
    conn = ldap3.Connection(ldap3.Server("mock"), user="cn=admin", password="x", client_strategy=ldap3.MOCK_SYNC)
    conn.bind()
    pc_a, pc_b = uuid.uuid4(), uuid.uuid4()
    other = keycred.KeyCredential(key_material=_material(), key_usage=keycred.KEY_USAGE_NGC,
                                  device_id=pc_b).to_dn_binary(DN)
    old = keycred.KeyCredential(key_material=_material(), key_usage=keycred.KEY_USAGE_NGC,
                                device_id=pc_a).to_dn_binary(DN)
    conn.strategy.add_entry(DN, {"objectClass": ["user"], "msDS-KeyCredentialLink": [other, old]})
    user = Principal(dn=DN, upn="hello1@lab.test", guid=uuid.uuid4(), sid="S-1-5-21-1")
    new_material = _material()
    Directory.add_ngc_key(conn, user, pc_a, new_material)
    keys = _keys(conn)
    assert sorted(k.device_id for k in keys) == sorted([pc_a, pc_b])
    assert next(k for k in keys if k.device_id == pc_a).material == new_material
