/*
 * CS-412 Fuzzing Lab - Example Harness
 * 
 * This is a simple harness that reads input from a file and processes it.
 * Replace this with your actual target library/function for the assignment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_INPUT_SIZE 4096

/*
 * Example vulnerable function - REPLACE THIS with your actual target
 * This simulates a simple parser with various bugs for demonstration
 */
int parse_input(const uint8_t *data, size_t len) {
    if (len < 4) {
        return -1;  // Too short
    }

    // Example vulnerability 1: Buffer overflow
    char buffer[16];
    if (data[0] == 'B' && data[1] == 'U' && data[2] == 'F') {
        // BUG: No bounds checking
        memcpy(buffer, data + 3, len - 3);
    }

    // Example vulnerability 2: Integer overflow
    if (data[0] == 'I' && data[1] == 'N' && data[2] == 'T') {
        uint32_t size = *(uint32_t*)(data + 3);
        char *alloc = malloc(size + 1);  // BUG: size + 1 can overflow
        if (alloc) {
            memcpy(alloc, data + 7, size);
            free(alloc);
        }
    }

    // Example vulnerability 3: Null pointer dereference
    if (data[0] == 'N' && data[1] == 'U' && data[2] == 'L') {
        char *ptr = NULL;
        if (len > 10 && data[10] == 'X') {
            *ptr = 'A';  // BUG: Null deref
        }
    }

    // Example vulnerability 4: Use after free
    if (data[0] == 'U' && data[1] == 'A' && data[2] == 'F') {
        char *ptr = malloc(32);
        free(ptr);
        if (len > 3 && data[3] == 'X') {
            ptr[0] = 'A';  // BUG: Use after free
        }
    }

    // Example crash condition: Division by zero
    if (len >= 8 && 
        data[0] == 'C' && data[1] == 'R' && 
        data[2] == 'A' && data[3] == 'S' &&
        data[4] == 'H') {
        int divisor = data[5] - '0';
        int result = 100 / divisor;  // BUG: Divide by zero if data[5] == '0'
        printf("Result: %d\n", result);
    }

    return 0;
}

/*
 * Main harness function
 * Reads input from file (passed as argument) and feeds it to the target
 */
int main(int argc, char **argv) {
    FILE *fp;
    uint8_t *buffer;
    size_t len;

    // Check for input file argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        fprintf(stderr, "This harness reads from a file (use @@ in AFL)\n");
        return 1;
    }

    // Open input file
    fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Limit input size
    if (len > MAX_INPUT_SIZE) {
        len = MAX_INPUT_SIZE;
    }

    // Read input
    buffer = (uint8_t *)malloc(len);
    if (!buffer) {
        fclose(fp);
        return 1;
    }

    size_t bytes_read = fread(buffer, 1, len, fp);
    fclose(fp);

    if (bytes_read != len) {
        free(buffer);
        return 1;
    }

    // Process input with target function
    int result = parse_input(buffer, len);

    // Cleanup
    free(buffer);

    return result;
}
