#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 0;

    // --- READ STRUCT SETUP ---
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) { fclose(fp); return 0; }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        fclose(fp);
        return 0;
    }

    // setjmp covers ALL libpng errors in this read pipeline
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        return 0;
    }

    png_set_user_limits(png_ptr, 1024, 1024);
    png_init_io(png_ptr, fp);

    // --- PHASE 1: Read header/chunks only (not pixel data yet) ---
    // PNG_INFO_ALL tells libpng to parse all ancillary chunks (tEXt, zTXt, iTXt, etc.)
    png_read_info(png_ptr, info_ptr);

    // --- PHASE 2: Extract text chunks the file gave us ---
    // This is the untrusted data AFL++ will mutate: keywords, text, language tags, etc.
    png_textp text_ptr = NULL;
    int num_text = 0;
    png_get_text(png_ptr, info_ptr, &text_ptr, &num_text);

    // --- PHASE 3: Read pixel data (exercises the decoder path as before) ---
    png_read_image(png_ptr,
        // png_read_image needs row pointers; we allocate them here
        // We discard pixel data immediately — we only care about code coverage
        ({
            png_uint_32 height = png_get_image_height(png_ptr, info_ptr);
            png_uint_32 rowbytes = png_get_rowbytes(png_ptr, info_ptr);
            png_bytepp rows = (png_bytepp)malloc(height * sizeof(png_bytep));
            if (!rows) {
                png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
                fclose(fp);
                return 0;
            }
            for (png_uint_32 i = 0; i < height; i++) {
                rows[i] = (png_bytep)malloc(rowbytes);
                if (!rows[i]) {
                    // free what we allocated so far
                    for (png_uint_32 j = 0; j < i; j++) free(rows[j]);
                    free(rows);
                    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
                    fclose(fp);
                    return 0;
                }
            }
            rows; // "return" from compound literal
        })
    );

    // Note: we intentionally leak the row buffers here.
    // AFL++ forks a fresh process for every run, so this is acceptable and
    // avoids the complexity of tracking them outside the compound statement.

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    fclose(fp);

    // --- PHASE 4: Feed text chunks into png_set_text() ---
    // This is the primary target: png_set_text() calls png_set_text_2() internally,
    // where CVE-2016-10087 lives (NULL deref on malformed keyword/compression fields).
    if (num_text > 0 && text_ptr != NULL) {
        // We need a write struct to call png_set_text() on
        png_structp write_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
        if (write_ptr) {
            png_infop write_info = png_create_info_struct(write_ptr);
            if (write_info) {
                // setjmp for the write path errors (e.g. bad compression type in text chunk)
                if (!setjmp(png_jmpbuf(write_ptr))) {
                    // This is the vulnerable call: internally invokes png_set_text_2()
                    // with whatever keyword/text/language the fuzz input injected
                    png_set_text(write_ptr, write_info, text_ptr, num_text);
                }
            }
            png_destroy_write_struct(&write_ptr, &write_info);
        }
    }

    return 0;
}