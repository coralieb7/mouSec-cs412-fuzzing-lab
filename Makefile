# CS-412 Fuzzing Lab Makefile - mouSec

CC_INSTRUMENTED = afl-clang-fast
CC_QEMU = gcc

# Library paths
LIBPNG_DIR = /fuzzing/libpng-1.2.56
LIBPNG_INSTRUMENTED = $(LIBPNG_DIR)/build_out
LIBPNG_VANILLA = $(LIBPNG_DIR)/install_vanilla

# Flags
CFLAGS_COMMON = -g -O1
CFLAGS_ASAN = -fsanitize=address -fno-omit-frame-pointer
INCLUDES_INSTRUMENTED = -I$(LIBPNG_INSTRUMENTED)/include
LIBS_INSTRUMENTED = -L$(LIBPNG_INSTRUMENTED)/lib -lpng12 -lz -lm
INCLUDES_VANILLA = -I$(LIBPNG_VANILLA)/include
LIBS_VANILLA = -L$(LIBPNG_VANILLA)/lib -lpng12 -lz -lm

# Directories
SRC_DIR = src
INPUT_DIR = input
FINDINGS_DIR = findings
FINDINGS_QEMU_DIR = findings-qemu
PLOT_DIR = plot_output
PLOT_QEMU_DIR = plot_output_qemu
DICT_FILE = dictionary.txt

.PHONY: all build build-instrumented build-qemu fuzz-instrumented fuzz-qemu plot clean

all: build

build: build-instrumented build-qemu

# White-box: instrumented libpng + ASan
build-instrumented: $(SRC_DIR)/harness.c
	$(CC_INSTRUMENTED) $(CFLAGS_COMMON) $(CFLAGS_ASAN) \
		$(INCLUDES_INSTRUMENTED) \
		$(SRC_DIR)/harness.c \
		$(LIBS_INSTRUMENTED) \
		-o png_fuzz
	@echo "Built png_fuzz (instrumented)"

# Black-box: vanilla libpng, no sanitizers
build-qemu: $(SRC_DIR)/harness.c
	$(CC_QEMU) $(CFLAGS_COMMON) \
		$(INCLUDES_VANILLA) \
		$(SRC_DIR)/harness.c \
		$(LIBS_VANILLA) \
		-o png_fuzz_qemu
	@echo "Built png_fuzz_qemu (vanilla)"

fuzz-instrumented: build-instrumented
	mkdir -p $(FINDINGS_DIR)
	afl-fuzz -m none -t 1000+ \
		-i $(INPUT_DIR) \
		-o $(FINDINGS_DIR) \
		-x $(DICT_FILE) \
		-- ./png_fuzz @@

fuzz-qemu: build-qemu
	mkdir -p $(FINDINGS_QEMU_DIR)
	afl-fuzz -Q -m none -t 1000+ \
		-i $(INPUT_DIR) \
		-o $(FINDINGS_QEMU_DIR) \
		-x $(DICT_FILE) \
		-- ./png_fuzz_qemu @@

plot:
	@if [ -d "$(FINDINGS_DIR)/default" ]; then \
		mkdir -p $(PLOT_DIR); \
		afl-plot $(FINDINGS_DIR)/default $(PLOT_DIR); \
	fi
	@if [ -d "$(FINDINGS_QEMU_DIR)/default" ]; then \
		mkdir -p $(PLOT_QEMU_DIR); \
		afl-plot $(FINDINGS_QEMU_DIR)/default $(PLOT_QEMU_DIR); \
	fi

clean:
	rm -f png_fuzz png_fuzz_qemu
	rm -rf $(FINDINGS_DIR) $(FINDINGS_QEMU_DIR) $(PLOT_DIR) $(PLOT_QEMU_DIR)