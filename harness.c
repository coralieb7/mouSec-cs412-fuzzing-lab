#include <stdio.h>
#include <stdlib.h>
#include <png.h>

int main(int argc, char **argv) {
    // 1. Check for input file from AFL++
    if (argc < 2) {
        return 0; 
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        return 0;
    }

    // 2. Initialize libpng core structures
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        fclose(fp);
        return 0;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        fclose(fp);
        return 0;
    }

    // 3. AFL++ Error Handling Bridge
    // libpng doesn't use standard return codes for errors; it uses setjmp/longjmp.
    // If a mutated PNG is invalid, libpng will "jump" back to this if-statement.
    if (setjmp(png_jmpbuf(png_ptr))) {
        // We catch the error, clean up memory, and exit with code 0.
        // If we didn't do this, AFL++ would record every broken PNG as a "crash"!
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        return 0;
    }

    // 4.  Prevent OOM, False Positives
    // AFL++ will inevitably try to set the PNG width/height to 65535x65535.
    // Without this limit, ASAN will crash trying to allocate gigabytes of RAM.
    png_set_user_limits(png_ptr, 1024, 1024);

    // 5. Feed the file to libpng
    png_init_io(png_ptr, fp);

    // 6. Read and Transform
    // We use png_read_png because it automatically handles memory allocation/deallocation,
    // meaning it won't accidentally introduce memory leaks in your harness.
    png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_EXPAND | PNG_TRANSFORM_STRIP_ALPHA, NULL);

    // 7. Clean up cleanly for the next AFL++ execution
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    fclose(fp);

    return 0;
}
