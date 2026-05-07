
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

/* ── Progressive reader state ───────────────────────────────────────────── */
typedef struct {
    const unsigned char *data;
    size_t size;
    size_t pos;
} buf_state_t;

static void progressive_row_cb(png_structp png_ptr, png_bytep row,
                                png_uint_32 rownum, int pass) {
    (void)png_ptr; (void)row; (void)rownum; (void)pass;
}

static void progressive_end_cb(png_structp png_ptr, png_infop info_ptr) {
    (void)png_ptr; (void)info_ptr;
}

static void progressive_info_cb(png_structp png_ptr, png_infop info_ptr) {
    (void)png_ptr; (void)info_ptr;
}

/* ── Unknown chunk callback (exercises png_push_read_chunk internals) ────── */
static int unknown_chunk_cb(png_structp png_ptr, png_unknown_chunkp chunk) {
    (void)png_ptr; (void)chunk;
    return 0; /* let libpng handle it */
}

/* ════════════════════════════════════════════════════════════════════════════
 * PATH 1 — Standard read path: exercises every ancillary chunk type
 * ════════════════════════════════════════════════════════════════════════════ */
static void run_standard_read(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return;

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                                  NULL, NULL, NULL);
    if (!png_ptr) { fclose(fp); return; }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        fclose(fp);
        return;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        return;
    }

    png_set_user_limits(png_ptr, 1024, 1024);

    /* Keep ALL unknown chunks — exercises png_set_unknown_chunks internally */
    png_set_keep_unknown_chunks(png_ptr, PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);
    png_set_read_user_chunk_fn(png_ptr, NULL, unknown_chunk_cb);

    png_init_io(png_ptr, fp);
    png_read_info(png_ptr, info_ptr);

    /* ── tEXt / zTXt / iTXt ─────────────────────────────────────────────── */
    /* CVE-2016-10087: NULL deref in png_set_text_2() */
    png_textp text_ptr = NULL;
    int num_text = 0;
    png_get_text(png_ptr, info_ptr, &text_ptr, &num_text);

    /* ── iCCP (ICC color profile) ────────────────────────────────────────── */
    /* Historically buggy: complex zlib-compressed blob with no length check */
    png_charp iccp_name = NULL;
    int iccp_compression = 0;
    png_bytep iccp_profile = NULL;
    png_uint_32 iccp_proflen = 0;
    png_get_iCCP(png_ptr, info_ptr,
                 &iccp_name, &iccp_compression,
                 &iccp_profile, &iccp_proflen);

    /* ── sPLT (suggested palette) ────────────────────────────────────────── */
    /* Multiple entries, each with name + depth + RGBA samples */
    png_sPLT_tp splt_ptr = NULL;
    int num_splt = png_get_sPLT(png_ptr, info_ptr, &splt_ptr);
    (void)num_splt;

    /* ── hIST (histogram) ────────────────────────────────────────────────── */
    png_uint_16p hist = NULL;
    png_get_hIST(png_ptr, info_ptr, &hist);

    /* ── pCAL (physical calibration) ─────────────────────────────────────── */
    png_charp pcal_purpose = NULL, pcal_units = NULL;
    png_charpp pcal_params = NULL;
    png_int_32 pcal_X0, pcal_X1;
    int pcal_type, pcal_nparams;
    png_get_pCAL(png_ptr, info_ptr, &pcal_purpose, &pcal_X0, &pcal_X1,
                 &pcal_type, &pcal_nparams, &pcal_units, &pcal_params);

    /* ── Read pixel data ─────────────────────────────────────────────────── */
    png_uint_32 height   = png_get_image_height(png_ptr, info_ptr);
    png_uint_32 rowbytes = png_get_rowbytes(png_ptr, info_ptr);

    png_bytepp rows = (png_bytepp)malloc(height * sizeof(png_bytep));
    if (!rows) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        return;
    }
    for (png_uint_32 i = 0; i < height; i++) {
        rows[i] = (png_bytep)malloc(rowbytes);
        if (!rows[i]) {
            for (png_uint_32 j = 0; j < i; j++) free(rows[j]);
            free(rows);
            png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
            fclose(fp);
            return;
        }
    }

    png_read_image(png_ptr, rows);
    png_read_end(png_ptr, info_ptr);

    for (png_uint_32 i = 0; i < height; i++) free(rows[i]);
    free(rows);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    fclose(fp);

    /* ── Feed text chunks through png_set_text() on a write struct ───────── */
    /* CVE-2016-10087 target */
    if (num_text > 0 && text_ptr != NULL) {
        png_structp wptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,
                                                    NULL, NULL, NULL);
        if (wptr) {
            png_infop winfo = png_create_info_struct(wptr);
            if (winfo) {
                if (!setjmp(png_jmpbuf(wptr)))
                    png_set_text(wptr, winfo, text_ptr, num_text);
            }
            png_destroy_write_struct(&wptr, &winfo);
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * PATH 2 — Progressive (push) reader
 * Exercises png_push_read_chunk / png_process_data — a completely separate
 * C stack from the pull reader; bugs here are often not reachable via PATH 1
 * ════════════════════════════════════════════════════════════════════════════ */
static void run_progressive_read(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);
    if (fsize <= 0) { fclose(fp); return; }

    unsigned char *buf = (unsigned char *)malloc(fsize);
    if (!buf) { fclose(fp); return; }
    if ((long)fread(buf, 1, fsize, fp) != fsize) {
        free(buf); fclose(fp); return;
    }
    fclose(fp);

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                                  NULL, NULL, NULL);
    if (!png_ptr) { free(buf); return; }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        free(buf);
        return;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        free(buf);
        return;
    }

    png_set_user_limits(png_ptr, 1024, 1024);
    png_set_progressive_read_fn(png_ptr, NULL,
                                 progressive_info_cb,
                                 progressive_row_cb,
                                 progressive_end_cb);

    /* Feed in small chunks — forces the push parser state machine */
    const size_t CHUNK = 64;
    for (size_t off = 0; off < (size_t)fsize; off += CHUNK) {
        size_t n = (off + CHUNK <= (size_t)fsize) ? CHUNK : (size_t)fsize - off;
        png_process_data(png_ptr, info_ptr, buf + off, n);
    }

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    free(buf);
}

/* ════════════════════════════════════════════════════════════════════════════
 * PATH 3 — Encoder path
 * Feeds parsed pixel data back through the write pipeline with random
 * transforms; bugs in png_write_chunk_* and deflate integration live here
 * ════════════════════════════════════════════════════════════════════════════ */
static void run_encoder(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return;

    png_structp rptr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                               NULL, NULL, NULL);
    if (!rptr) { fclose(fp); return; }

    png_infop rinfo = png_create_info_struct(rptr);
    if (!rinfo) {
        png_destroy_read_struct(&rptr, NULL, NULL);
        fclose(fp);
        return;
    }

    if (setjmp(png_jmpbuf(rptr))) {
        png_destroy_read_struct(&rptr, &rinfo, NULL);
        fclose(fp);
        return;
    }

    png_set_user_limits(rptr, 64, 64); /* tighter limit for encoder path */
    png_init_io(rptr, fp);
    png_read_png(rptr, rinfo, PNG_TRANSFORM_EXPAND | PNG_TRANSFORM_STRIP_16, NULL);

    png_bytepp rows = png_get_rows(rptr, rinfo);
    if (!rows) {
        png_destroy_read_struct(&rptr, &rinfo, NULL);
        fclose(fp);
        return;
    }

    /* Write to /dev/null — we only care about the encoder code paths */
    FILE *dev_null = fopen("/dev/null", "wb");
    if (!dev_null) {
        png_destroy_read_struct(&rptr, &rinfo, NULL);
        fclose(fp);
        return;
    }

    png_structp wptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,
                                                NULL, NULL, NULL);
    if (!wptr) {
        png_destroy_read_struct(&rptr, &rinfo, NULL);
        fclose(fp);
        fclose(dev_null);
        return;
    }

    png_infop winfo = png_create_info_struct(wptr);
    if (!winfo) {
        png_destroy_write_struct(&wptr, NULL);
        png_destroy_read_struct(&rptr, &rinfo, NULL);
        fclose(fp);
        fclose(dev_null);
        return;
    }

    if (setjmp(png_jmpbuf(wptr))) {
        png_destroy_write_struct(&wptr, &winfo);
        png_destroy_read_struct(&rptr, &rinfo, NULL);
        fclose(fp);
        fclose(dev_null);
        return;
    }

    png_init_io(wptr, dev_null);
    png_write_png(wptr, rinfo, PNG_TRANSFORM_IDENTITY, NULL);

    png_destroy_write_struct(&wptr, &winfo);
    png_destroy_read_struct(&rptr, &rinfo, NULL);
    fclose(dev_null);
    fclose(fp);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Entry point — all three paths run on every input
 * ════════════════════════════════════════════════════════════════════════════ */
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    run_standard_read(argv[1]);
    run_progressive_read(argv[1]);
    run_encoder(argv[1]);
    return 0;
}