import hashlib
import struct
import uuid

import pytest

from drs import keycred as k

MATERIAL = b"RSA1" + bytes(range(256)) + b"\x01\x00\x01"


def test_round_trip_and_hashes():
    c = k.KeyCredential(key_material=MATERIAL, key_usage=k.KEY_USAGE_NGC, flags=0x02,
                        device_id=uuid.UUID("4b56d3ae-420a-4c7a-90c1-24ae8287b978"),
                        created=134_000_000_000_000_001, last_logon=134_000_000_000_000_009)
    blob = c.to_blob()
    e = k.parse(blob)
    assert e[k.KEY_ID] == hashlib.sha256(MATERIAL).digest()
    assert e[k.KEY_USAGE] == b"\x01" and e[k.KEY_SOURCE] == b"\x00"
    assert e[k.CUSTOM_KEY_INFORMATION] == b"\x01\x02"
    assert uuid.UUID(bytes_le=e[k.DEVICE_ID]) == c.device_id
    # FILETIME is kept to the tick: a datetime would lose the last digit.
    assert struct.unpack("<Q", e[k.KEY_CREATION_TIME])[0] == 134_000_000_000_000_001
    assert struct.unpack("<Q", e[k.KEY_APPROXIMATE_LAST_LOGON])[0] == 134_000_000_000_000_009


def test_entries_in_identifier_order():
    blob = k.KeyCredential(key_material=MATERIAL, key_usage=k.KEY_USAGE_STK,
                           device_id=uuid.uuid4()).to_blob()
    pos, ids = 4, []
    while pos < len(blob):
        length, ident = struct.unpack_from("<HB", blob, pos)
        ids.append(ident)
        pos += 3 + length
    assert ids == sorted(ids) == [1, 2, 3, 4, 5, 6, 7, 8, 9]


def test_dn_binary_length_counts_hex_characters():
    c = k.KeyCredential(key_material=MATERIAL, key_usage=k.KEY_USAGE_NGC)
    value = c.to_dn_binary("CN=u,OU=People,DC=lab,DC=test")
    tag, length, hexblob, dn = value.split(":", 3)
    assert tag == "B" and int(length) == len(hexblob) == 2 * len(c.to_blob())
    assert k.parse_dn_binary(value) == (c.to_blob(), "CN=u,OU=People,DC=lab,DC=test")


def test_tampered_blob_is_refused():
    blob = bytearray(k.KeyCredential(key_material=MATERIAL, key_usage=k.KEY_USAGE_NGC).to_blob())
    blob[-1] ^= 1
    with pytest.raises(ValueError, match="KeyHash"):
        k.parse(bytes(blob))
