"""Read-only diagnostic for the pinned DRBD v09 internal-superblock layout.

No drbdadm/drbdmeta invocation, configuration, lock files or metadata writes.
This is geometry evidence only, NOT a DRBD recovery/integrity implementation.
Format source: LINBIT/drbd-headers bdf8650ea6e32d1c4518b7ad6c2d7469896d17ff,
the submodule of installed drbd-utils e1e02e77e6d068f626cef7c3998ed08b0fde7669.
"""
import base64
import fcntl
import hashlib
import mmap
import os
from pathlib import Path
import re
import stat
import struct
import sys

BLOCK_BYTES=4096
MAGIC=0x8374026d
BLKGETSIZE64=0x80081272
HEADER_COMMIT='bdf8650ea6e32d1c4518b7ad6c2d7469896d17ff'
UTILS_COMMIT='e1e02e77e6d068f626cef7c3998ed08b0fde7669'


def exact_positive(value,name):
    if type(value) is not int or value<=0:raise ValueError(name+' must be a positive integer')
    return value


def align_up(value,quantum):return ((value+quantum-1)//quantum)*quantum


def parse_superblock(raw,allocated_bytes):
    """Reject malformed geometry; never infer data consistency from this result."""
    if type(raw) is not bytes or len(raw)!=BLOCK_BYTES:raise ValueError('need exact4096-byte superblock')
    exact_positive(allocated_bytes,'allocated_bytes')
    if allocated_bytes%4096 or allocated_bytes<68*1024:raise ValueError('unsupported internal allocation alignment')
    u32=lambda offset:struct.unpack_from('>I',raw,offset)[0]
    i32=lambda offset:struct.unpack_from('>i',raw,offset)[0]
    u64=lambda offset:struct.unpack_from('>Q',raw,offset)[0]
    if u32(60)!=MAGIC:raise ValueError('not the pinned DRBD v09 magic/byte order')
    peers=u32(88);node=i32(92);bitmap=u32(80);stripes=u32(96);stripe4k=u32(100)
    if not 1<=peers<=31 or not -1<=node<=31:raise ValueError('invalid peer slots or node-id')
    if bitmap<4096 or bitmap>1024**2 or bitmap&(bitmap-1):raise ValueError('invalid bitmap granularity')
    al_bytes=stripes*stripe4k*4096
    if stripes<1 or stripe4k<1 or not 32768<=al_bytes<=64*1024**2:raise ValueError('unsupported AL geometry')
    per_slot=align_up((allocated_bytes+bitmap*8-1)//(bitmap*8),8)
    expected_metadata=align_up(per_slot*peers,4096)+al_bytes+4096
    metadata_bytes=u32(64)*512
    if metadata_bytes!=expected_metadata or metadata_bytes>=allocated_bytes:raise ValueError('internal metadata size mismatch')
    if i32(68)!=-(al_bytes//512) or i32(76)!=-(metadata_bytes//512)+8:raise ValueError('internal metadata offset mismatch')
    if u64(0)*512>allocated_bytes-metadata_bytes:raise ValueError('last-agreed size overlaps metadata')
    if u64(48)==0:raise ValueError('missing metadata device UUID')
    return dict(format='v09',node_id=node,device_uuid='0x'+format(u64(48),'016x'),
                superblock_offset=allocated_bytes-4096,metadata_bytes=metadata_bytes,
                al_offset_sectors=i32(68),bitmap_offset_sectors=i32(76),
                profile=dict(peer_slots=peers,al_stripes=stripes,
                             al_stripe_size_kib=stripe4k*4,bitmap_block_kib=bitmap//1024))


def stable_geometry(first,second,allocated_bytes):
    before=parse_superblock(first,allocated_bytes)
    after=parse_superblock(second,allocated_bytes)
    if before!=after:raise ValueError('metadata identity/geometry changed between direct reads')
    return before


def read_direct_block(fd,offset):
    with mmap.mmap(-1,BLOCK_BYTES) as buffer:
        view=memoryview(buffer)
        try:
            os.lseek(fd,offset,os.SEEK_SET)
            got=os.readv(fd,[view])
            if got!=BLOCK_BYTES:raise ValueError('short direct superblock read')
            return bytes(view)
        finally:view.release()


def mapper_uuid(vg_uuid,lv_uuid):
    pattern=r'[A-Za-z0-9]{6}(?:-[A-Za-z0-9]{4}){5}-[A-Za-z0-9]{6}'
    if any(type(v) is not str or not re.fullmatch(pattern,v) for v in [vg_uuid,lv_uuid]):
        raise ValueError('invalid exact LVM UUID')
    return 'LVM-'+vg_uuid.replace('-','')+lv_uuid.replace('-','')


def read_owned_superblock(*,resource,minor,node_id,vg_uuid,lv_uuid,major,device_minor,allocated_bytes):
    """Caller must first join fresh exact pool/disk ownership. Linux block only."""
    if sys.platform!='linux' or not hasattr(os,'O_DIRECT'):raise RuntimeError('native Linux O_DIRECT required')
    if os.geteuid()!=0:raise PermissionError('dedicated guest root required')
    if type(resource) is not str or not re.fullmatch(r'rkls_data_[0-9]{8}_a[0-9]+',resource):raise ValueError('not an owned qualification resource')
    exact_positive(minor,'minor');exact_positive(major,'major');exact_positive(allocated_bytes,'allocated_bytes')
    if type(device_minor) is not int or device_minor<0 or type(node_id) is not int or node_id not in [0,1,2]:raise ValueError('invalid exact node/device minor')
    expected_uuid=mapper_uuid(vg_uuid,lv_uuid)
    sysfs=Path('/sys/dev/block')/(str(major)+':'+str(device_minor))
    if (sysfs/'dm/uuid').read_text().strip()!=expected_uuid:raise ValueError('kernel mapper UUID mismatch')
    path=Path('/dev')/('dm-'+str(device_minor))
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_DIRECT)
    try:
        before=os.fstat(fd)
        if not stat.S_ISBLK(before.st_mode) or before.st_uid!=0:raise ValueError('not a root-owned native block device')
        if (os.major(before.st_rdev),os.minor(before.st_rdev))!=(major,device_minor):raise ValueError('backing block identity mismatch')
        size=bytearray(8);fcntl.ioctl(fd,BLKGETSIZE64,size,True)
        if struct.unpack('=Q',size)[0]!=allocated_bytes:raise ValueError('independent block capacity mismatch')
        if allocated_bytes%4096 or allocated_bytes<68*1024:raise ValueError('unsupported exact allocation')
        raw=[read_direct_block(fd,allocated_bytes-4096) for _ in range(2)]
        geometry=stable_geometry(raw[0],raw[1],allocated_bytes)
        if geometry['node_id']!=node_id:raise ValueError('metadata node-id mismatch')
        after=os.fstat(fd)
        if (after.st_ino,after.st_dev,after.st_rdev,after.st_mode)!=(before.st_ino,before.st_dev,before.st_rdev,before.st_mode):raise ValueError('backing device changed during read')
        if (sysfs/'dm/uuid').read_text().strip()!=expected_uuid:raise ValueError('mapper UUID changed during read')
        fcntl.ioctl(fd,BLKGETSIZE64,size,True)
        if struct.unpack('=Q',size)[0]!=allocated_bytes:raise ValueError('block size changed during read')
        return dict(kind='owned-v09-direct-geometry',source='exact native metadata observation',
                    resource=resource,minor=minor,node_id=node_id,vg_uuid=vg_uuid,lv_uuid=lv_uuid,
                    backing_device=str(path),major=major,device_minor=device_minor,
                    allocated_bytes=allocated_bytes,geometry=geometry,profile=geometry['profile'],
                    raw_superblock_base64=[base64.b64encode(b).decode() for b in raw],
                    raw_superblock_sha256=[hashlib.sha256(b).hexdigest() for b in raw],
                    header_commit=HEADER_COMMIT,utils_commit=UTILS_COMMIT,
                    open_mode='O_RDONLY|O_DIRECT|O_NOFOLLOW',no_metadata_write=True,
                    no_native_tool_or_telemetry_invocation=True,data_consistency_proven=False)
    finally:os.close(fd)


def validate_receipt(receipt,**expected):
    """Reparse raw proof after transport; booleans/profile labels are not proof."""
    if type(receipt) is not dict:raise ValueError('missing metadata proof')
    for key,value in expected.items():
        if receipt.get(key)!=value or type(receipt.get(key)) is not type(value):raise ValueError('metadata binding mismatch: '+key)
    if (receipt.get('kind')!='owned-v09-direct-geometry' or receipt.get('source')!='exact native metadata observation'
            or receipt.get('header_commit')!=HEADER_COMMIT or receipt.get('utils_commit')!=UTILS_COMMIT
            or receipt.get('backing_device')!='/dev/dm-'+str(expected['device_minor'])):
        raise ValueError('wrong metadata evidence producer or device path')
    raw=receipt.get('raw_superblock_base64')
    if type(raw) is not list or len(raw)!=2 or any(type(x) is not str or len(x)>5500 for x in raw):raise ValueError('missing bounded raw superblocks')
    blocks=[base64.b64decode(s,validate=True) for s in raw]
    if [hashlib.sha256(b).hexdigest() for b in blocks]!=receipt.get('raw_superblock_sha256'):raise ValueError('raw proof hash mismatch')
    geometry=stable_geometry(blocks[0],blocks[1],expected['allocated_bytes'])
    if geometry!=receipt.get('geometry') or geometry['profile']!=receipt.get('profile') or geometry['node_id']!=expected['node_id']:raise ValueError('raw proof disagrees with declared metadata')
    return geometry
