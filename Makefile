# libpng 1.2.56 fuzzing lab

CC_INSTRUMENTED = afl-clang-fast
CC_VANILLA      = gcc

LIBPNG_DIR          = /fuzzing/libpng-1.2.56
LIBPNG_INSTRUMENTED = $(LIBPNG_DIR)/build_out
LIBPNG_VANILLA      = $(LIBPNG_DIR)/install_vanilla

CFLAGS_COMMON = -g -O1
CFLAGS_ASAN   = -fsanitize=address -fno-omit-frame-pointer

INC_INSTR  = -I$(LIBPNG_INSTRUMENTED)/include
LIB_INSTR  = -L$(LIBPNG_INSTRUMENTED)/lib  -lpng12 -lz -lm
INC_VAN    = -I$(LIBPNG_VANILLA)/include
LIB_VAN    = -L$(LIBPNG_VANILLA)/lib       -lpng12 -lz -lm

SEEDS  = input
DICT   = dictionary.txt

.PHONY: all build build-fork build-persistent build-qemu build-synthetic \
        seeds fuzz fuzz-persistent fuzz-qemu fuzz-synthetic plot clean

all: build

build: build-fork build-persistent build-qemu

seeds:
	python3 src/make_seeds.py

# instrumented + ASan, fork mode
build-fork: src/harness.c
	$(CC_INSTRUMENTED) $(CFLAGS_COMMON) $(CFLAGS_ASAN) \
	    $(INC_INSTR) src/harness.c $(LIB_INSTR) -o png_fuzz

# instrumented + ASan, persistent mode
build-persistent: src/harness_persistent.c
	$(CC_INSTRUMENTED) $(CFLAGS_COMMON) $(CFLAGS_ASAN) \
	    $(INC_INSTR) src/harness_persistent.c $(LIB_INSTR) \
	    -o png_fuzz_persistent

# uninstrumented vanilla build for QEMU mode
build-qemu: src/harness.c
	$(CC_VANILLA) $(CFLAGS_COMMON) \
	    $(INC_VAN) src/harness.c $(LIB_VAN) -o png_fuzz_qemu

# instrumented + ASan, fork mode, with synthetic off-by-one (Q5)
build-synthetic: src/harness_synthetic.c
	$(CC_INSTRUMENTED) $(CFLAGS_COMMON) $(CFLAGS_ASAN) \
	    $(INC_INSTR) src/harness_synthetic.c $(LIB_INSTR) -o png_fuzz_synthetic

fuzz-synthetic: build-synthetic
	mkdir -p findings-synthetic
	timeout 60 afl-fuzz -m none -t 2000+ \
	    -i $(SEEDS) -o findings-synthetic -x $(DICT) -- ./png_fuzz_synthetic @@ || true

fuzz: build-fork
	mkdir -p findings
	afl-fuzz -m none -t 2000+ \
	    -i $(SEEDS) -o findings -x $(DICT) -- ./png_fuzz @@

fuzz-persistent: build-persistent
	mkdir -p findings-persistent
	afl-fuzz -m none -t 2000+ \
	    -i $(SEEDS) -o findings-persistent -x $(DICT) \
	    -- ./png_fuzz_persistent

fuzz-qemu: build-qemu
	mkdir -p findings-qemu
	afl-fuzz -Q -m none -t 2000+ \
	    -i $(SEEDS) -o findings-qemu -x $(DICT) -- ./png_fuzz_qemu @@

plot:
	@[ -d findings/default ]            && afl-plot findings/default            plot_output      || true
	@[ -d findings-qemu/default ]       && afl-plot findings-qemu/default       plot_output_qemu || true
	@[ -d findings-persistent/default ] && afl-plot findings-persistent/default plot_output_persistent || true

clean:
	rm -f png_fuzz png_fuzz_persistent png_fuzz_qemu png_fuzz_synthetic
	rm -rf findings findings-qemu findings-persistent findings-synthetic \
	       plot_output plot_output_qemu plot_output_persistent
