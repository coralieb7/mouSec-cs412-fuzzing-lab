/* Same as harness.c but with a synthetic off-by-one heap overflow
   to prove the AFL + ASan setup actually catches bugs (lab Q5). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 0;

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                             NULL, NULL, NULL);
    if (!png) { fclose(fp); return 0; }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_read_struct(&png, NULL, NULL);
        fclose(fp);
        return 0;
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
        return 0;
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

    height   = png_get_image_height(png, info);
    png_uint_32 width    = png_get_image_width(png, info);
    png_uint_32 rowbytes = png_get_rowbytes(png, info);

    /* SYNTHETIC BUG: under-allocate by one byte, but only for widths > 1.
       Keeps the 1x1 seeds non-crashing for AFL's dry run; any mutation
       that bumps the width triggers a heap-buffer-overflow in png_read_image. */
    png_uint_32 alloc = (width > 1) ? rowbytes - 1 : rowbytes;

    rows = malloc(height * sizeof(png_bytep));
    if (rows) {
        for (png_uint_32 i = 0; i < height; i++) {
            rows[i] = malloc(alloc);
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
    return 0;
}
