"""Generate a small PNG seed corpus. Each seed is a minimal valid PNG
that exercises one chunk type so AFL has something to mutate."""
import os, struct, zlib

OUT = "input"
os.makedirs(OUT, exist_ok=True)

PNG_SIG = b"\x89PNG\r\n\x1a\n"

def chunk(t, data):
    crc = zlib.crc32(t + data) & 0xffffffff
    return struct.pack(">I", len(data)) + t + data + struct.pack(">I", crc)

ihdr_rgb     = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
ihdr_indexed = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 3, 0, 0, 0))
idat_rgb     = chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
idat_indexed = chunk(b"IDAT", zlib.compress(b"\x00\x00"))
iend         = chunk(b"IEND", b"")
plte         = chunk(b"PLTE", bytes([255,0,0, 0,255,0, 0,0,255]))

def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)

# RGB baseline
write("01_rgb.png", PNG_SIG + ihdr_rgb + idat_rgb + iend)

# indexed + palette
write("02_indexed.png", PNG_SIG + ihdr_indexed + plte + idat_indexed + iend)

# tEXt
text = chunk(b"tEXt", b"Comment\x00hello")
write("03_text.png", PNG_SIG + ihdr_rgb + text + idat_rgb + iend)

# zTXt (compressed text)
ztxt = chunk(b"zTXt", b"Comment\x00\x00" + zlib.compress(b"hello"))
write("04_ztxt.png", PNG_SIG + ihdr_rgb + ztxt + idat_rgb + iend)

# iTXt: keyword\0 comp-flag comp-method lang\0 trans-key\0 text
itxt = chunk(b"iTXt", b"Comment\x00\x00\x00en\x00greeting\x00hello")
write("05_itxt.png", PNG_SIG + ihdr_rgb + itxt + idat_rgb + iend)

# iTXt compressed
itxt_z = chunk(b"iTXt", b"Comment\x00\x01\x00en\x00greeting\x00"
                       + zlib.compress(b"hello"))
write("06_itxt_compressed.png", PNG_SIG + ihdr_rgb + itxt_z + idat_rgb + iend)

# tRNS on indexed
trns_i = chunk(b"tRNS", bytes([255, 128, 0]))
write("07_trns_indexed.png",
      PNG_SIG + ihdr_indexed + plte + trns_i + idat_indexed + iend)

# tRNS on RGB
trns_rgb = chunk(b"tRNS", struct.pack(">HHH", 255, 255, 255))
write("08_trns_rgb.png", PNG_SIG + ihdr_rgb + trns_rgb + idat_rgb + iend)

# iCCP (compressed colour profile)
iccp = chunk(b"iCCP", b"sRGB\x00\x00" + zlib.compress(b"fake icc profile"))
write("09_iccp.png", PNG_SIG + ihdr_rgb + iccp + idat_rgb + iend)

print(f"wrote {len(os.listdir(OUT))} seeds to {OUT}/")
