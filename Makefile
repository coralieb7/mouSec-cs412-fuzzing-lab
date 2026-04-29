# CS-412 Fuzzing Lab Makefile - mouSec
# Targets: build, run/fuzz, clean

# Compiler and flags
CC_INSTRUMENTED = afl-clang-fast
CC_QEMU = gcc
CFLAGS = -g -O0 -Wall -Wextra
SANITIZER_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer

# Directories
SRC_DIR = src
INPUT_DIR = input
FINDINGS_DIR = findings
FINDINGS_QEMU_DIR = findings-qemu
PLOT_DIR = plot_output
PLOT_QEMU_DIR = plot_output_qemu

# Targets
HARNESS_INSTRUMENTED = harness_instrumented
HARNESS_QEMU = harness_qemu
TARGET_LIB = target_lib.a

# AFL++ Options
AFL_OPTS = -m none -t 1000+
DICT_FILE = dictionary.txt

.PHONY: all build build-instrumented build-qemu run fuzz fuzz-instrumented fuzz-qemu plot clean help

# Default target
all: build

help:
	@echo "CS-412 Fuzzing Lab Makefile"
	@echo "==========================="
	@echo "Available targets:"
	@echo "  build              - Build both instrumented and QEMU binaries"
	@echo "  build-instrumented - Build AFL++-instrumented harness with sanitizers"
	@echo "  build-qemu         - Build non-instrumented harness for QEMU mode"
	@echo "  run / fuzz         - Run both fuzzing campaigns"
	@echo "  fuzz-instrumented  - Run AFL++ with instrumentation"
	@echo "  fuzz-qemu          - Run AFL++ in QEMU mode (no instrumentation)"
	@echo "  plot               - Generate coverage plots from fuzzing results"
	@echo "  clean              - Remove all build artifacts and fuzzing results"
	@echo "  clean-findings     - Remove only fuzzing results (keep binaries)"
	@echo ""
	@echo "Example workflow:"
	@echo "  make build"
	@echo "  make fuzz-instrumented  # Run for hours/overnight"
	@echo "  make fuzz-qemu          # Run for comparison"
	@echo "  make plot"

# Build all targets
build: build-instrumented build-qemu
	@echo "✓ Build complete: $(HARNESS_INSTRUMENTED) and $(HARNESS_QEMU)"

# Build with AFL++ instrumentation and sanitizers
build-instrumented: $(SRC_DIR)/harness.c
	@echo "Building instrumented harness with AFL++ and sanitizers..."
	$(CC_INSTRUMENTED) $(CFLAGS) $(SANITIZER_FLAGS) \
		-o $(HARNESS_INSTRUMENTED) $(SRC_DIR)/harness.c
	@echo "✓ Instrumented harness built: $(HARNESS_INSTRUMENTED)"

# Build without instrumentation for QEMU mode
build-qemu: $(SRC_DIR)/harness.c
	@echo "Building non-instrumented harness for QEMU mode..."
	$(CC_QEMU) $(CFLAGS) \
		-o $(HARNESS_QEMU) $(SRC_DIR)/harness.c
	@echo "✓ QEMU harness built: $(HARNESS_QEMU)"

# Run both fuzzing campaigns
run fuzz: fuzz-instrumented fuzz-qemu plot

# Fuzzing with instrumentation (recommended)
fuzz-instrumented: build-instrumented
	@echo "Starting AFL++ fuzzing with instrumentation..."
	@echo "Press Ctrl+C to stop fuzzing"
	@mkdir -p $(FINDINGS_DIR)
	afl-fuzz $(AFL_OPTS) \
		-i $(INPUT_DIR) \
		-o $(FINDINGS_DIR) \
		$(if $(wildcard $(DICT_FILE)),-x $(DICT_FILE),) \
		-- ./$(HARNESS_INSTRUMENTED) @@

# Fuzzing in QEMU mode (no source code instrumentation)
fuzz-qemu: build-qemu
	@echo "Starting AFL++ fuzzing in QEMU mode..."
	@echo "Press Ctrl+C to stop fuzzing"
	@mkdir -p $(FINDINGS_QEMU_DIR)
	afl-fuzz -Q $(AFL_OPTS) \
		-i $(INPUT_DIR) \
		-o $(FINDINGS_QEMU_DIR) \
		$(if $(wildcard $(DICT_FILE)),-x $(DICT_FILE),) \
		-- ./$(HARNESS_QEMU) @@

# Generate plots from fuzzing results
plot:
	@echo "Generating coverage plots..."
	@if [ -d "$(FINDINGS_DIR)/default" ]; then \
		mkdir -p $(PLOT_DIR); \
		afl-plot $(FINDINGS_DIR)/default $(PLOT_DIR); \
		echo "✓ Instrumented plots: $(PLOT_DIR)/index.html"; \
	else \
		echo "⚠ No instrumented findings found. Run 'make fuzz-instrumented' first."; \
	fi
	@if [ -d "$(FINDINGS_QEMU_DIR)/default" ]; then \
		mkdir -p $(PLOT_QEMU_DIR); \
		afl-plot $(FINDINGS_QEMU_DIR)/default $(PLOT_QEMU_DIR); \
		echo "✓ QEMU plots: $(PLOT_QEMU_DIR)/index.html"; \
	else \
		echo "⚠ No QEMU findings found. Run 'make fuzz-qemu' first."; \
	fi

# Clean all build artifacts and fuzzing results
clean: clean-findings
	@echo "Cleaning build artifacts..."
	rm -f $(HARNESS_INSTRUMENTED) $(HARNESS_QEMU) $(TARGET_LIB)
	rm -f *.o *.a
	@echo "✓ Clean complete"

# Clean only fuzzing results (keep binaries)
clean-findings:
	@echo "Cleaning fuzzing results..."
	rm -rf $(FINDINGS_DIR) $(FINDINGS_QEMU_DIR)
	rm -rf $(PLOT_DIR) $(PLOT_QEMU_DIR)
	@echo "✓ Fuzzing results cleaned"

# Verify environment setup
check-env:
	@echo "Checking AFL++ installation..."
	@which afl-fuzz > /dev/null || (echo "❌ AFL++ not found" && exit 1)
	@which afl-clang-fast > /dev/null || (echo "❌ afl-clang-fast not found" && exit 1)
	@echo "✓ AFL++ toolchain ready"
	@echo "AFL++ version:"
	@afl-fuzz -h | head -n 3 || true
