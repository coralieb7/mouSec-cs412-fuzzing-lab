import struct, zlib

def make_chunk(chunk_type, data):
    c = chunk_type + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

PNG_SIG = b'\x89PNG\r\n\x1a\n'

# Minimal 1x1 white pixel IHDR + IDAT
ihdr = make_chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
raw = b'\x00\xff\xff\xff'  # filter byte + RGB white
idat = make_chunk(b'IDAT', zlib.compress(raw))
iend = make_chunk(b'IEND', b'')

# zTXt chunk: keyword + null + compression method (0) + compressed text
keyword = b'Comment'
text = zlib.compress(b'fuzz')
ztxt_data = keyword + b'\x00\x00' + text
ztxt = make_chunk(b'zTXt', ztxt_data)

# iTXt chunk: keyword + null + compression flag + compression method + language + null + translated keyword + null + text
itxt_data = b'Comment\x00\x00\x00en\x00keyword\x00fuzz'
itxt = make_chunk(b'iTXt', itxt_data)

with open('input/seed_ztxt.png', 'wb') as f:
    f.write(PNG_SIG + ihdr + ztxt + idat + iend)

with open('input/seed_itxt.png', 'wb') as f:
    f.write(PNG_SIG + ihdr + itxt + idat + iend)

print("done")