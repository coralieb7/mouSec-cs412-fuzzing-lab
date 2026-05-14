# mouSec-cs412-fuzzing-lab

Coverage-guided fuzzing campaign using AFL++ against libpng 1.2.56 (CS-412, EPFL Spring 2026).

---

## Prerequisites

- Docker (or OrbStack on macOS)

All fuzzing tools (AFL++, afl-clang-fast, afl-plot, QEMU mode) are installed inside the container. You do not need them on your host machine.

---

## Getting started

### 1. Build the Docker image

```bash
docker build -t cs412-fuzzing .
```

This installs AFL++ (stable branch), builds QEMU support, and sets up the environment. The first build takes several minutes.

### 2. Start the container

```bash
docker run --rm -it -v $(pwd):/fuzzing cs412-fuzzing
```

The `-v $(pwd):/fuzzing` flag mounts your local repository into the container. Any file you edit locally is immediately visible inside the container, and any findings or build artifacts written by the container appear in your local directory. You do not need to rebuild the image after editing source files.


---

## Repository layout

```
.
├── Dockerfile
├── Makefile
├── dictionary.txt          # AFL++ PNG token dictionary
├── patches/
│   └── libpng-nocrc.patch  # disables CRC validation in libpng
├── src/
│   ├── harness.c           # fork-mode harness (white-box and QEMU campaigns)
│   ├── harness_persistent.c# persistent-mode harness
│   └── harness_synthetic.c # harness with injected off-by-one bug (Q5)
├── input/                  # seed corpus (9 minimal PNGs)
├── findings/               # instrumented fork-mode campaign output
├── findings-persistent/    # persistent-mode campaign output
├── findings-qemu/          # QEMU-mode campaign output
├── findings-synthetic/     # synthetic-bug campaign output
├── plot_output/            # afl-plot graphs for the fork-mode campaign
└── libpng-1.2.56/          # patched libpng source (built inside the container)
```

---

## Makefile targets

All targets are meant to be run **inside the container** (`/fuzzing` is the working directory).

| Target | Description |
|---|---|
| `make build` | Build all three harness binaries (fork, persistent, QEMU) |
| `make build-fork` | Build `png_fuzz` (instrumented + ASan, fork mode) |
| `make build-persistent` | Build `png_fuzz_persistent` (instrumented + ASan, persistent mode) |
| `make build-qemu` | Build `png_fuzz_qemu` (vanilla gcc, no instrumentation, no ASan) |
| `make build-synthetic` | Build `png_fuzz_synthetic` (fork mode with injected off-by-one bug) |
| `make fuzz` | Run the fork-mode campaign (outputs to `findings/`) |
| `make fuzz-persistent` | Run the persistent-mode campaign (outputs to `findings-persistent/`) |
| `make fuzz-qemu` | Run the QEMU-mode campaign (outputs to `findings-qemu/`) |
| `make fuzz-synthetic` | Run the synthetic-bug campaign for 60 s (outputs to `findings-synthetic/`) |
| `make plot` | Run `afl-plot` on all available findings directories |
| `make clean` | Remove all compiled binaries and findings directories |

### Quick sanity check after building

```bash
make build-fork
./png_fuzz input/01_rgb.png
echo $?   # should be 0
```

---

## Running a fuzzing campaign

### White-box (instrumented, fork mode)

```bash
make fuzz
```

Launches `afl-fuzz` with the seed corpus in `input/`, the dictionary in `dictionary.txt`, and writes results to `findings/`. Press `Ctrl-C` to stop. Run for at least 30 minutes for meaningful coverage data.

### White-box (instrumented, persistent mode)

```bash
make fuzz-persistent
```

Same as above but uses the persistent-mode harness. Typically 10-15x faster than fork mode because AFL++ loops inside the same process instead of forking for every input.

### Black-box (QEMU mode)

```bash
make fuzz-qemu
```

Runs AFL++ with `-Q` against the uninstrumented `png_fuzz_qemu` binary. Coverage is collected by QEMU's JIT translator at runtime instead of compile-time instrumentation. Expect roughly 5-10x lower exec speed compared to the instrumented build. Results go to `findings-qemu/`.

### Synthetic bug (Q5 validation)

```bash
make fuzz-synthetic
```

Runs for 60 seconds against a harness with a deliberate off-by-one heap overflow (width > 1 triggers an under-allocated row buffer). Used to verify that the AFL++ + ASan setup catches real bugs.

---

## Plotting results

```bash
make plot
```

Generates `afl-plot` HTML reports and PNG graphs in `plot_output/` (fork mode) and `plot_output_persistent/` (persistent mode). Open `plot_output/index.html` in a browser to view the edges and exec-speed curves.

---

## Crash triage

Crashes are saved to `findings/default/crashes/`. To triage one:

```bash
# Reproduce
./png_fuzz findings/default/crashes/id:000000,sig:11,...

# Minimize
afl-tmin -i findings/default/crashes/id:000000,sig:11,... -o minimized.png -- ./png_fuzz @@

# Get ASan stack trace
ASAN_OPTIONS=symbolize=1 ./png_fuzz minimized.png
```

---

## Notes on the libpng build

libpng 1.2.56 is built inside the container during the first `make build` call. Two separate builds are produced:

- `libpng-1.2.56/build_out/` — compiled with `afl-clang-fast`, `-fsanitize=address`, `-g -O1`. Used by all instrumented harnesses.
- `libpng-1.2.56/install_vanilla/` — compiled with plain `gcc`, no sanitizers. Used by the QEMU harness.

Both builds have the CRC patch applied (`patches/libpng-nocrc.patch`), which disables CRC-32 validation so that AFL++ mutations to chunk contents are not rejected before reaching the parsing code.
