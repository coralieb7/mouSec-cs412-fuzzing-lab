import struct, zlib

def make_chunk(t, data):
    c = t + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

PNG_SIG = b'\x89PNG\r\n\x1a\n'
iend = make_chunk(b'IEND', b'')

# ── shared base chunks ────────────────────────────────────────────────────────
ihdr_rgb     = make_chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
ihdr_indexed = make_chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 3, 0, 0, 0))
idat_rgb     = make_chunk(b'IDAT', zlib.compress(b'\x00\xff\xff\xff'))
idat_indexed = make_chunk(b'IDAT', zlib.compress(b'\x00\x00'))
plte         = make_chunk(b'PLTE', bytes([255,0,0, 0,255,0, 0,0,255]))

# ── tEXt ─────────────────────────────────────────────────────────────────────
text = make_chunk(b'tEXt', b'Comment\x00fuzz')
with open('input/seed_text.png', 'wb') as f:
    f.write(PNG_SIG + ihdr_rgb + text + idat_rgb + iend)

# ── zTXt ─────────────────────────────────────────────────────────────────────
ztxt = make_chunk(b'zTXt', b'Comment\x00\x00' + zlib.compress(b'fuzz'))
with open('input/seed_ztxt.png', 'wb') as f:
    f.write(PNG_SIG + ihdr_rgb + ztxt + idat_rgb + iend)

# ── iTXt ─────────────────────────────────────────────────────────────────────
itxt = make_chunk(b'iTXt', b'Comment\x00\x00\x00en\x00keyword\x00fuzz')
with open('input/seed_itxt.png', 'wb') as f:
    f.write(PNG_SIG + ihdr_rgb + itxt + idat_rgb + iend)

# ── iCCP ─────────────────────────────────────────────────────────────────────
iccp = make_chunk(b'iCCP', b'sRGB\x00\x00' + zlib.compress(b'fakeprofile'))
with open('input/seed_iccp.png', 'wb') as f:
    f.write(PNG_SIG + ihdr_rgb + iccp + idat_rgb + iend)

# ── PLTE ─────────────────────────────────────────────────────────────────────
with open('input/seed_plte.png', 'wb') as f:
    f.write(PNG_SIG + ihdr_indexed + plte + idat_indexed + iend)

# ── tRNS on indexed PNG ───────────────────────────────────────────────────────
trns_indexed = make_chunk(b'tRNS', bytes([255, 128, 0]))
with open('input/seed_trns.png', 'wb') as f:
    f.write(PNG_SIG + ihdr_indexed + plte + trns_indexed + idat_indexed + iend)

# ── tRNS on RGB PNG ───────────────────────────────────────────────────────────
trns_rgb = make_chunk(b'tRNS', struct.pack('>HHH', 255, 255, 255))
with open('input/seed_trns_rgb.png', 'wb') as f:
    f.write(PNG_SIG + ihdr_rgb + trns_rgb + idat_rgb + iend)

print("done — 7 seeds created in input/")
