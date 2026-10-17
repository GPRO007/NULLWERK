"""General PE import-table editor. Never loads or executes an input binary."""
import hashlib
from pathlib import Path
import struct
import os


class PEError(ValueError):
    pass


class PEFile:
    def __init__(self, data):
        self.data = bytes(data)
        if len(data) < 64 or data[:2] != b'MZ':
            raise PEError('Not a Windows PE file (missing MZ signature).')
        self.pe = self.u32(60)
        if self.slice(self.pe, 4) != b'PE\0\0':
            raise PEError('Invalid PE signature.')
        self.optional = self.pe + 24
        self.optional_size = self.u16(self.pe + 20)
        self.slice(self.optional, self.optional_size)
        magic = self.u16(self.optional)
        if magic == 0x20b:
            self.bits, dd, nc = 64, 112, 108
        elif magic == 0x10b:
            self.bits, dd, nc = 32, 96, 92
        else:
            raise PEError('Only PE32 and PE32+ are supported.')
        if self.optional_size < dd:
            raise PEError('The optional header is truncated.')
        self.directory_count = min(self.u32(self.optional + nc), (self.optional_size-dd)//8, 16)
        self.directory_base = self.optional + dd
        self.headers_size = self.u32(self.optional + 60)
        self.sections = []
        for i in range(self.u16(self.pe + 6)):
            o = self.optional + self.optional_size + 40*i
            self.slice(o, 40)
            vs, va, rs, ro = struct.unpack_from('<IIII', self.data, o+8)
            self.sections.append((va, vs, ro, rs))
        self.imports = []
        self.tables = {}
        self.read_table(1, 'normal', 20, 12)
        self.read_table(13, 'delay', 32, 4)

    def slice(self, offset, size):
        if offset < 0 or size < 0 or offset+size > len(self.data):
            raise PEError('The file is truncated or contains invalid offsets.')
        return self.data[offset:offset+size]

    def u16(self, offset):
        return struct.unpack('<H', self.slice(offset, 2))[0]

    def u32(self, offset):
        return struct.unpack('<I', self.slice(offset, 4))[0]

    def directory(self, index):
        if index >= self.directory_count:
            return (0, 0)
        return struct.unpack('<II', self.slice(self.directory_base+8*index, 8))

    def offset(self, rva, size=1):
        if rva < self.headers_size:
            self.slice(rva, size)
            if rva+size > self.headers_size:
                raise PEError('The RVA extends beyond the headers.')
            return rva
        for va, vs, ro, rs in self.sections:
            if va <= rva < va+max(vs, rs):
                delta = rva-va
                if delta+size > rs:
                    raise PEError('The RVA is outside the stored section data.')
                self.slice(ro+delta, size)
                return ro+delta
        raise PEError('The RVA does not map to a section.')

    def name(self, rva):
        chars = bytearray()
        for i in range(4096):
            value = self.data[self.offset(rva+i)]
            if value == 0:
                return chars.decode('ascii', errors='replace')
            chars.append(value)
        raise PEError('The DLL name is too long or is not null-terminated.')

    def read_table(self, index, kind, stride, name_offset):
        rva, size = self.directory(index)
        if not rva and not size:
            return
        if not rva or size < stride:
            raise PEError('Invalid import directory.')
        records = []
        for i in range(min(size//stride, 8192)):
            o = self.offset(rva+i*stride, stride)
            record = self.slice(o, stride)
            if not any(record):
                self.tables[kind] = dict(index=index, rva=rva, size=size,
                                         stride=stride, records=records)
                return
            if kind == 'delay' and not (struct.unpack_from('<I', record)[0] & 1):
                raise PEError('Legacy VA-based delay imports are not supported.')
            name_rva = struct.unpack_from('<I', record, name_offset)[0]
            entry = dict(key=(kind, i), kind=kind, name=self.name(name_rva), record=record)
            records.append(entry)
            self.imports.append(entry)
        raise PEError('The import directory has no valid terminator.')

    def remove(self, keys):
        keys = set(keys)
        known = {entry['key'] for entry in self.imports}
        if not keys or not keys <= known:
            raise PEError('No valid DLL entries were selected.')
        b = bytearray(self.data)
        removed = [e for e in self.imports if e['key'] in keys]
        for kind, table in self.tables.items():
            if not any(e['key'] in keys for e in table['records']):
                continue
            kept = [e['record'] for e in table['records'] if e['key'] not in keys]
            stride = table['stride']
            contents = b''.join(kept) + bytes(stride)
            span = (len(table['records'])+1)*stride
            for i in range(span//stride):
                o = self.offset(table['rva']+i*stride, stride)
                block = contents[i*stride:(i+1)*stride]
                b[o:o+stride] = block.ljust(stride, b'\0')
            struct.pack_into('<II', b, self.directory_base+8*table['index'],
                             table['rva'] if kept else 0, len(contents) if kept else 0)
        # Bound-import metadata no longer describes the changed import table.
        if self.directory_count > 11:
            struct.pack_into('<II', b, self.directory_base+8*11, 0, 0)
        # Modifying PE bytes invalidates Authenticode. Remove its directory entry;
        # leave the certificate/overlay bytes in place to preserve other offsets.
        if self.directory_count > 4:
            struct.pack_into('<II', b, self.directory_base+8*4, 0, 0)
        checksum_offset = self.optional+64
        struct.pack_into('<I', b, checksum_offset, 0)
        total = 0
        for i in range(0, len(b), 2):
            total += b[i] + (b[i+1]<<8 if i+1<len(b) else 0)
            total = (total & 65535) + (total >> 16)
        total = (total & 65535) + (total >> 16)
        struct.pack_into('<I', b, checksum_offset, (total+len(b)) & 0xffffffff)
        result = bytes(b)
        verified = PEFile(result)
        expected = [(e['kind'], e['name'], e['record']) for e in self.imports if e['key'] not in keys]
        actual = [(e['kind'], e['name'], e['record']) for e in verified.imports]
        if len(result) != len(self.data) or expected != actual:
            raise PEError('The edited import table failed verification.')
        return result, removed


def save_copy(source, destination, result):
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise PEError('The original file must not be overwritten.')
    with destination.open('xb') as target:
        try:
            target.write(result)
            target.flush()
            os.fsync(target.fileno())
        except BaseException:
            target.close()
            destination.unlink(missing_ok=True)
            raise
    if hashlib.sha256(destination.read_bytes()).digest() != hashlib.sha256(result).digest():
        raise PEError('The saved copy failed verification.')
