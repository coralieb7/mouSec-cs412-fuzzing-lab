/* Persistent-mode version of harness.c. Same decoding pipeline, but
   AFL feeds the input in memory and loops in-process. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

__AFL_FUZZ_INIT();

static void decode_once(const unsigned char *buf, size_t sz) {
    if (sz == 0) return;

    /* libpng 1.2.56 has no memory-read API, dump the buffer to a tmpfile */
    FILE *fp = tmpfile();
    if (!fp) return;
    fwrite(buf, 1, sz, fp);
    rewind(fp);

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                             NULL, NULL, NULL);
    if (!png) { fclose(fp); return; }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_read_struct(&png, NULL, NULL);
        fclose(fp);
        return;
    }

    png_bytepp rows = NULL;
    png_uint_32 height = 0;

    if (setjmp(png_jmpbuf(png))) {
        if (rows) {
            for (png_uint_32 i = 0; i < height; i++) free(rows[i]);
            free(rows);
        }
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return;
    }

    png_set_user_limits(png, 1024, 1024);
    png_set_keep_unknown_chunks(png, PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);
    png_init_io(png, fp);
    png_read_info(png, info);

    png_set_expand(png);
    png_set_strip_16(png);
    png_set_gray_to_rgb(png);
    png_set_filler(png, 0xFF, PNG_FILLER_AFTER);
    png_read_update_info(png, info);

    height = png_get_image_height(png, info);
    png_uint_32 rowbytes = png_get_rowbytes(png, info);
    rows = malloc(height * sizeof(png_bytep));
    if (rows) {
        for (png_uint_32 i = 0; i < height; i++) {
            rows[i] = malloc(rowbytes);
            if (!rows[i]) {
                for (png_uint_32 j = 0; j < i; j++) free(rows[j]);
                free(rows);
                rows = NULL;
                height = 0;
                break;
            }
        }
        if (rows) {
            png_read_image(png, rows);
            png_read_end(png, info);
        }
    }

    if (rows) {
        for (png_uint_32 i = 0; i < height; i++) free(rows[i]);
        free(rows);
    }
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len > 0) decode_once(buf, (size_t)len);
    }
    return 0;
}
