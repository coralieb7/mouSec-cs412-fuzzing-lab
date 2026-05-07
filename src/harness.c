#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

/* ═══════════════════════════════════════════════════════════════════
 * UTILITIES
 * ═══════════════════════════════════════════════════════════════════ */

static unsigned char *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    unsigned char *buf = malloc(sz);
    if (!buf) { fclose(f); return NULL; }
    if ((long)fread(buf, 1, sz, f) != sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

static void free_rows(png_bytepp rows, png_uint_32 count) {
    if (!rows) return;
    for (png_uint_32 i = 0; i < count; i++) free(rows[i]);
    free(rows);
}

/* ═══════════════════════════════════════════════════════════════════
 * PATH 1 — Standard read: ancillary chunks + tRNS/PLTE set path
 *
 * Targets:
 *  - png_handle_tEXt / zTXt / iTXt  → png_set_text_2 (CVE-2016-10087)
 *  - png_set_tRNS                    → tRNS misuse (CVE-2026-33416 family)
 *  - png_set_PLTE                    → PLTE overflow family
 *  - png_handle_iCCP                 → zlib-compressed profile parsing
 *  - png_handle_sPLT / pCAL / hIST   → ancillary chunk bugs
 * ═══════════════════════════════════════════════════════════════════ */
static void path_standard_read(const unsigned char *buf, size_t sz) {
    /* Write buf to a tmp file — libpng 1.2.56 has no memory-read API */
    FILE *fp = tmpfile();
    if (!fp) return;
    fwrite(buf, 1, sz, fp);
    rewind(fp);

    png_structp rp = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!rp) { fclose(fp); return; }
    png_infop ip = png_create_info_struct(rp);
    if (!ip) { png_destroy_read_struct(&rp, NULL, NULL); fclose(fp); return; }

    png_bytepp rows = NULL;
    png_uint_32 height = 0;

    if (setjmp(png_jmpbuf(rp))) {
        free_rows(rows, height);
        png_destroy_read_struct(&rp, &ip, NULL);
        fclose(fp);
        return;
    }

    png_set_user_limits(rp, 1024, 1024);
    png_set_keep_unknown_chunks(rp, PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);
    png_init_io(rp, fp);
    png_read_info(rp, ip);

    /* ── Register all transforms — each exercises distinct decoder code ── */
    png_set_expand(rp);       /* PLTE→RGB: hits CVE-2015-8126 family path   */
    png_set_strip_16(rp);     /* 16→8 bit depth reduction                   */
    png_set_gray_to_rgb(rp);  /* colorspace conversion                      */
    png_set_filler(rp, 0xFF, PNG_FILLER_AFTER); /* alpha handling           */
    png_read_update_info(rp, ip);

    /* ── Extract ALL chunk data while info_ptr is still alive ─────────── */

    /* tEXt/zTXt/iTXt — copy out before destroy (CVE-2016-10087 target) */
    png_textp text_ptr = NULL;
    int num_text = 0;
    png_get_text(rp, ip, &text_ptr, &num_text);
    png_text *text_copy = NULL;
    if (num_text > 0 && text_ptr) {
        text_copy = malloc(num_text * sizeof(png_text));
        if (text_copy)
            memcpy(text_copy, text_ptr, num_text * sizeof(png_text));
        else
            num_text = 0;
    }

    /* tRNS — raw trans values, exercised via png_set_tRNS below */
    png_bytep  trans       = NULL;
    int        num_trans   = 0;
    png_color_16p trans_values = NULL;
    png_get_tRNS(rp, ip, &trans, &num_trans, &trans_values);
    png_byte  trans_copy[256];
    png_color_16 trans_val_copy = {0};
    int num_trans_copy = 0;
    if (num_trans > 0 && trans) {
        int n = num_trans < 256 ? num_trans : 256;
        memcpy(trans_copy, trans, n);
        num_trans_copy = n;
    }
    if (trans_values)
        memcpy(&trans_val_copy, trans_values, sizeof(png_color_16));

    /* PLTE — palette entries for png_set_PLTE round-trip */
    png_colorp palette     = NULL;
    int        num_palette = 0;
    png_get_PLTE(rp, ip, &palette, &num_palette);
    png_color palette_copy[256];
    int num_palette_copy = 0;
    if (num_palette > 0 && palette) {
        int n = num_palette < 256 ? num_palette : 256;
        memcpy(palette_copy, palette, n * sizeof(png_color));
        num_palette_copy = n;
    }

    /* iCCP */
    png_charp  iccp_name = NULL;   int iccp_comp = 0;
    png_bytep  iccp_prof = NULL;   png_uint_32 iccp_len = 0;
    png_get_iCCP(rp, ip, &iccp_name, &iccp_comp, &iccp_prof, &iccp_len);

    /* sPLT */
    png_sPLT_tp splt = NULL;
    int num_splt = png_get_sPLT(rp, ip, &splt);
    (void)num_splt;

    /* ── Read pixel data ─────────────────────────────────────────────── */
    height   = png_get_image_height(rp, ip);
    png_uint_32 rowbytes = png_get_rowbytes(rp, ip);
    rows = malloc(height * sizeof(png_bytep));
    if (rows) {
        png_uint_32 i;
        for (i = 0; i < height; i++) {
            rows[i] = malloc(rowbytes);
            if (!rows[i]) {
                for (png_uint_32 j = 0; j < i; j++) free(rows[j]);
                free(rows); rows = NULL; height = 0;
                break;
            }
        }
        if (rows) {
            png_read_image(rp, rows);
            png_read_end(rp, ip);
            free_rows(rows, height);
            rows = NULL;
        }
    }

    png_destroy_read_struct(&rp, &ip, NULL);
    fclose(fp);

    /* ══ Now feed extracted data into SET functions — libpng does the crash ══ */

    /* ── png_set_text → png_set_text_2 (CVE-2016-10087) ─────────────── */
    if (num_text > 0 && text_copy) {
        png_structp wp = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
        if (wp) {
            png_infop wi = png_create_info_struct(wp);
            if (wi) {
                if (!setjmp(png_jmpbuf(wp)))
                    png_set_text(wp, wi, text_copy, num_text);
            }
            png_destroy_write_struct(&wp, &wi);
        }
        free(text_copy);
    }

    /* ── png_set_tRNS (CVE-2026-33416 family — use-after-free on tRNS) ─ */
    /* Feed the raw tRNS bytes back through png_set_tRNS on a fresh struct */
    if (num_trans_copy > 0) {
        png_structp wp = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
        if (wp) {
            png_infop wi = png_create_info_struct(wp);
            if (wi) {
                if (!setjmp(png_jmpbuf(wp))) {
                    /* Exercises tRNS internal buffer allocation/management */
                    png_set_tRNS(wp, wi,
                                 trans_copy, num_trans_copy,
                                 &trans_val_copy);
                }
            }
            png_destroy_write_struct(&wp, &wi);
        }
    }

    /* ── png_set_PLTE (PLTE overflow family) ─────────────────────────── */
    if (num_palette_copy > 0) {
        png_structp wp = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
        if (wp) {
            png_infop wi = png_create_info_struct(wp);
            if (wi) {
                if (!setjmp(png_jmpbuf(wp))) {
                    /* png_set_PLTE validates num_palette against bit depth —
                       malformed inputs can underflow this check in 1.2.56   */
                    png_set_PLTE(wp, wi, palette_copy, num_palette_copy);
                    /* Round-trip: also call get after set to exercise
                       internal pointer consistency checks                    */
                    png_colorp out_pal = NULL; int out_num = 0;
                    png_get_PLTE(wp, wi, &out_pal, &out_num);
                }
            }
            png_destroy_write_struct(&wp, &wi);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * PATH 2 — Progressive (push) reader
 *
 * Targets:
 *  - png_push_read_chunk  — separate state machine from pull reader
 *  - png_process_data     — chunk-level boundary bugs
 * ═══════════════════════════════════════════════════════════════════ */
static void progressive_info_cb(png_structp p, png_infop i)   { (void)p; (void)i; }
static void progressive_row_cb(png_structp p, png_bytep r,
                                png_uint_32 n, int pass)       { (void)p;(void)r;(void)n;(void)pass; }
static void progressive_end_cb(png_structp p, png_infop i)    { (void)p; (void)i; }

static void path_progressive(const unsigned char *buf, size_t sz) {
    png_structp rp = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!rp) return;
    png_infop ip = png_create_info_struct(rp);
    if (!ip) { png_destroy_read_struct(&rp, NULL, NULL); return; }

    if (setjmp(png_jmpbuf(rp))) {
        png_destroy_read_struct(&rp, &ip, NULL);
        return;
    }

    png_set_user_limits(rp, 1024, 1024);
    png_set_progressive_read_fn(rp, NULL,
        progressive_info_cb, progressive_row_cb, progressive_end_cb);

    /* Feed in 64-byte chunks to stress the push parser state machine */
    const size_t CHUNK = 64;
    for (size_t off = 0; off < sz; off += CHUNK) {
        size_t n = (off + CHUNK <= sz) ? CHUNK : sz - off;
        png_process_data(rp, ip, (png_bytep)(buf + off), n);
    }

    png_destroy_read_struct(&rp, &ip, NULL);
}

/* ═══════════════════════════════════════════════════════════════════
 * PATH 3 — Encoder round-trip
 *
 * Targets:
 *  - png_write_chunk_*    — write path chunk serialisation
 *  - deflate integration  — zlib stream construction
 *  - png_write_PLTE       — PLTE write-side validation
 * ═══════════════════════════════════════════════════════════════════ */
static void path_encoder(const unsigned char *buf, size_t sz) {
    FILE *fp = tmpfile();
    if (!fp) return;
    fwrite(buf, 1, sz, fp);
    rewind(fp);

    /* Read first */
    png_structp rp = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!rp) { fclose(fp); return; }
    png_infop ri = png_create_info_struct(rp);
    if (!ri) { png_destroy_read_struct(&rp, NULL, NULL); fclose(fp); return; }

    if (setjmp(png_jmpbuf(rp))) {
        png_destroy_read_struct(&rp, &ri, NULL);
        fclose(fp);
        return;
    }

    /* Tighter limit for encoder path — keeps runtime bounded */
    png_set_user_limits(rp, 64, 64);
    png_init_io(rp, fp);
    png_read_png(rp, ri,
        PNG_TRANSFORM_EXPAND | PNG_TRANSFORM_STRIP_16, NULL);

    png_bytepp rows = png_get_rows(rp, ri);
    if (!rows) {
        png_destroy_read_struct(&rp, &ri, NULL);
        fclose(fp);
        return;
    }

    /* Write to /dev/null — only the write code path matters */
    FILE *dn = fopen("/dev/null", "wb");
    if (!dn) {
        png_destroy_read_struct(&rp, &ri, NULL);
        fclose(fp);
        return;
    }

    png_structp wp = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!wp) {
        png_destroy_read_struct(&rp, &ri, NULL);
        fclose(fp); fclose(dn);
        return;
    }
    png_infop wi = png_create_info_struct(wp);
    if (!wi) {
        png_destroy_write_struct(&wp, NULL);
        png_destroy_read_struct(&rp, &ri, NULL);
        fclose(fp); fclose(dn);
        return;
    }

    if (setjmp(png_jmpbuf(wp))) {
        png_destroy_write_struct(&wp, &wi);
        png_destroy_read_struct(&rp, &ri, NULL);
        fclose(fp); fclose(dn);
        return;
    }

    png_init_io(wp, dn);
    png_write_png(wp, ri, PNG_TRANSFORM_IDENTITY, NULL);

    png_destroy_write_struct(&wp, &wi);
    png_destroy_read_struct(&rp, &ri, NULL);
    fclose(fp);
    fclose(dn);
}

/* ═══════════════════════════════════════════════════════════════════
 * ENTRY POINT — all three paths on every input
 * ═══════════════════════════════════════════════════════════════════ */
int main(int argc, char **argv) {
    if (argc < 2) return 0;

    size_t sz = 0;
    unsigned char *buf = read_file(argv[1], &sz);
    if (!buf || sz == 0) { free(buf); return 0; }

    path_standard_read(buf, sz);   /* ancillary chunks + SET functions */
    path_progressive(buf, sz);     /* push parser                      */
    path_encoder(buf, sz);         /* write pipeline                   */

    free(buf);
    return 0;
}
