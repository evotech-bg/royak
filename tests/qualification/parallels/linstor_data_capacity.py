"""Exact accounting for the qualification profile, not a storage-size tolerance.

Independent observations must supply the real LVM extent and allocation plus
the kernel DRBD size and block sysfs sector count. No guest operations here.
The integer metadata arithmetic follows the pinned LINSTOR MetaData contract:
https://github.com/LINBIT/linstor-server/blob/75d5fa72d504ccfe55c421ccccda9505af8371f8/server/src/main/java/com/linbit/drbd/md/MetaData.java
Only internal metadata, 7 peer slots, 1x32KiB AL and 4KiB bitmap blocks are
accepted. Other profiles require separate qualification, not a guessed margin.
"""
import hashlib
import os
import stat

KIB = 1024
PROFILE = dict(peer_slots=7, al_stripes=1, al_stripe_size_kib=32, bitmap_block_kib=4)


def positive_int(value, name):
    if type(value) is not int or value <= 0:
        raise ValueError(name+' must be a positive integer')
    return value


def align_up(value, quantum):
    return ((value+quantum-1)//quantum)*quantum


def internal_metadata_kib(gross_kib):
    """Bitmap for all configured slots + aligned AL + metadata superblock."""
    positive_int(gross_kib, 'gross_kib')
    per_slot_bytes = align_up((align_up(gross_kib, 4)+31)//32, 8)
    bitmap_kib = align_up((per_slot_bytes*PROFILE['peer_slots']+1023)//1024, 4)
    return bitmap_kib+PROFILE['al_stripe_size_kib']+4


def expected_capacity(requested_bytes, extent_bytes):
    for value, name in [(requested_bytes, 'requested_bytes'), (extent_bytes, 'extent_bytes')]:
        positive_int(value, name)
    if requested_bytes % (4*KIB) or not 4*KIB <= requested_bytes <= 2*1024**3:
        raise ValueError('qualification request must be 4KiB aligned and at most 2GiB')
    if extent_bytes % (4*KIB) or extent_bytes > 64*1024**2:
        raise ValueError('unsupported observed LVM extent')
    requested_kib = requested_bytes//KIB
    gross_kib = max(68, requested_kib+36)
    # The bitmap must cover the metadata itself as well as the requested data.
    for _ in range(32):
        new_gross = max(68, requested_kib+internal_metadata_kib(gross_kib))
        if new_gross == gross_kib:
            break
        gross_kib = new_gross
    else:
        raise ValueError('metadata accounting did not converge')
    allocated_bytes = align_up(gross_kib*KIB, extent_bytes)
    metadata_bytes = internal_metadata_kib(allocated_bytes//KIB)*KIB
    exposed_bytes = allocated_bytes-metadata_bytes
    if exposed_bytes < requested_bytes:
        raise ValueError('allocated volume does not cover requested usable capacity')
    return dict(requested_bytes=requested_bytes, extent_bytes=extent_bytes,
                minimum_gross_bytes=gross_kib*KIB, allocated_bytes=allocated_bytes,
                metadata_bytes=metadata_bytes, exposed_bytes=exposed_bytes)


def validate_capacity(*, requested_bytes, extent_bytes, allocated_bytes,
                      drbd_size_kib, sysfs_sectors, profile):
    if (type(profile) is not dict or set(profile) != set(PROFILE)
            or any(type(profile[k]) is not int for k in PROFILE) or profile != PROFILE):
        raise ValueError('unqualified DRBD metadata profile')
    expected = expected_capacity(requested_bytes, extent_bytes)
    for value, name in [(allocated_bytes, 'allocated_bytes'), (drbd_size_kib, 'drbd_size_kib'),
                        (sysfs_sectors, 'sysfs_sectors')]:
        positive_int(value, name)
    if allocated_bytes != expected['allocated_bytes']:
        raise ValueError('LVM allocation differs from exact extent/metadata accounting')
    if drbd_size_kib*KIB != expected['exposed_bytes']:
        raise ValueError('DRBD size differs from exact allocated-device accounting')
    if sysfs_sectors*512 != expected['exposed_bytes']:
        raise ValueError('sysfs size differs from DRBD capacity')
    return dict(expected, metadata_profile=dict(PROFILE))


def digest_exact_device(path, exposed_bytes):
    """Stream all exposed bytes. A short device or an unaccounted tail is fatal."""
    positive_int(exposed_bytes, 'exposed_bytes')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISBLK(before.st_mode) or stat.S_ISREG(before.st_mode)):
            raise ValueError('not a block device or local regression-test file')
        if stat.S_ISREG(before.st_mode) and before.st_size != exposed_bytes:
            raise ValueError('regular test file size differs from exposed bytes')
        remaining = exposed_bytes
        digest = hashlib.sha256()
        while remaining:
            part = os.read(fd, min(1024**2, remaining))
            if not part:
                raise ValueError('short read before exposed-device end')
            digest.update(part)
            remaining -= len(part)
        if os.read(fd, 1):
            raise ValueError('device has an unaccounted tail')
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_rdev, s.st_mode, s.st_size)
        if identity(before) != identity(after):
            raise ValueError('device identity changed during hashing')
        return dict(bytes=exposed_bytes, sha256=digest.hexdigest())
    finally:
        os.close(fd)
