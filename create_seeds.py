import struct, zlib

def make_chunk(t, data):
    c = t + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

PNG_SIG = b'\x89PNG\r\n\x1a\n'
ihdr = make_chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
idat = make_chunk(b'IDAT', zlib.compress(b'\x00\xff\xff\xff'))
iend = make_chunk(b'IEND', b'')

# iCCP: profile name + null + compression method (0) + compressed dummy profile
iccp_data = b'sRGB\x00\x00' + zlib.compress(b'fakeprofile')
iccp = make_chunk(b'iCCP', iccp_data)

with open('input/seed_iccp.png', 'wb') as f:
    f.write(PNG_SIG + ihdr + iccp + idat + iend)

print("done")
