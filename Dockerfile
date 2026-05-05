# CS-412 Software Security - Fuzzing Lab Environment - mouSec
# Based on Ubuntu 22.04 LTS
FROM ubuntu:22.04
 
# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
 
# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    clang \
    llvm \
    lld \
    python3 \
    python3-pip \
    gnuplot \
    vim \
    nano \
    gdb \
    valgrind \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    cmake \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*
 
# Install AFL++ from the official repository
WORKDIR /opt
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git && \
    cd AFLplusplus && \
    git checkout stable && \
    make distrib && \
    make install && \
    cd qemu_mode && \
    ./build_qemu_support.sh || true
 
# Set up AFL++ environment variables
ENV AFL_PATH=/opt/AFLplusplus
ENV PATH="${AFL_PATH}:${PATH}"
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
 
# Create working directory
WORKDIR /fuzzing
 
# Copy the project files (only required files)
COPY Makefile /fuzzing/
COPY src/ /fuzzing/src/
COPY input/ /fuzzing/input/
COPY dictionary.txt /fuzzing/
 
# Create patches directory (for optional use later)
RUN mkdir -p /fuzzing/patches
 
# Set default shell
SHELL ["/bin/bash", "-c"]
 
# Default command: start interactive bash
CMD ["/bin/bash"]
