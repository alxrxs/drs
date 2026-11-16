"""KEYCREDENTIALLINK_BLOB ([MS-ADTS] 2.2.20) and its DN-Binary attribute value.

A blob is a version (0x200) followed by entries, each a 16-bit little-endian
length, a one-byte identifier and the value, in identifier order. KeyID is the
SHA-256 of KeyMaterial; KeyHash is the SHA-256 of every entry after it.
"""
import datetime
import hashlib
import struct
import uuid
from dataclasses import dataclass, field

VERSION = 0x200

KEY_ID = 0x01
KEY_HASH = 0x02
KEY_MATERIAL = 0x03
KEY_USAGE = 0x04
KEY_SOURCE = 0x05
DEVICE_ID = 0x06
CUSTOM_KEY_INFORMATION = 0x07
KEY_APPROXIMATE_LAST_LOGON = 0x08
KEY_CREATION_TIME = 0x09

KEY_USAGE_NGC = 0x01
# A device's transport key ([MS-DVRJ] 3.1.5.1.1.3).
KEY_USAGE_STK = 0x02
KEY_SOURCE_AD = 0x00

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetime(when):
    """`when` (an aware datetime) as a FILETIME: 100 ns ticks since 1601."""
    delta = when - _FILETIME_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def from_filetime(ticks):
    return _FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)


@dataclass
class KeyCredential:
    key_material: bytes
    key_usage: int
    device_id: uuid.UUID | None = None
    flags: int = 0
    key_source: int = KEY_SOURCE_AD
    # FILETIME ticks, kept as integers: a datetime drops the last 100 ns digit,
    # which changes KeyHash.
    created: int = field(default_factory=lambda: filetime(datetime.datetime.now(datetime.timezone.utc)))
    last_logon: int | None = None

    @property
    def key_id(self):
        return hashlib.sha256(self.key_material).digest()

    def _tail(self):
        entries = [(KEY_MATERIAL, self.key_material),
                   (KEY_USAGE, bytes([self.key_usage])),
                   (KEY_SOURCE, bytes([self.key_source]))]
        if self.device_id is not None:
            entries.append((DEVICE_ID, self.device_id.bytes_le))
        entries.append((CUSTOM_KEY_INFORMATION, bytes([1, self.flags])))
        entries.append((KEY_APPROXIMATE_LAST_LOGON, struct.pack("<Q", self.last_logon or self.created)))
        entries.append((KEY_CREATION_TIME, struct.pack("<Q", self.created)))
        return b"".join(_entry(i, v) for i, v in entries)

    def to_blob(self):
        tail = self._tail()
        return (struct.pack("<I", VERSION) + _entry(KEY_ID, self.key_id)
                + _entry(KEY_HASH, hashlib.sha256(tail).digest()) + tail)

    def to_dn_binary(self, dn):
        """The attribute value: B:<hex length>:<hex blob>:<owner DN>."""
        h = self.to_blob().hex().upper()
        return f"B:{len(h)}:{h}:{dn}"


def _entry(identifier, value):
    return struct.pack("<HB", len(value), identifier) + value


def parse(blob):
    """Every entry of a blob, as {identifier: value}, after checking its
    version, KeyID and KeyHash."""
    (version,) = struct.unpack_from("<I", blob)
    if version != VERSION:
        raise ValueError(f"unsupported KEYCREDENTIALLINK version {version:#x}")
    entries, offsets, pos = {}, {}, 4
    while pos < len(blob):
        length, identifier = struct.unpack_from("<HB", blob, pos)
        offsets[identifier] = pos
        entries[identifier] = blob[pos + 3:pos + 3 + length]
        pos += 3 + length
    if pos != len(blob):
        raise ValueError("truncated KEYCREDENTIALLINK entry")
    if hashlib.sha256(entries[KEY_MATERIAL]).digest() != entries.get(KEY_ID):
        raise ValueError("KeyID is not the SHA-256 of KeyMaterial")
    after_hash = offsets[KEY_HASH] + 3 + len(entries[KEY_HASH])
    if hashlib.sha256(blob[after_hash:]).digest() != entries[KEY_HASH]:
        raise ValueError("KeyHash does not cover the entries after it")
    return entries


def parse_dn_binary(value):
    """(blob, owner DN) from a B:<len>:<hex>:<dn> value."""
    tag, length, hexblob, dn = value.split(":", 3)
    if tag != "B" or int(length) != len(hexblob):
        raise ValueError("not a DN-Binary value")
    return bytes.fromhex(hexblob), dn
