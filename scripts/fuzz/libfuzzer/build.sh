#!/bin/bash
# Builds lib-swoole with clang + ASAN + UBSAN + libFuzzer coverage and links the parser harness.
# usage: build.sh [build_dir]   (default /tmp/lf_build)
# Use a dedicated clean worktree as the source tree: it needs config.h (from ./configure) and cmake writes lib/ into it.
set -e
SRC=$(cd "$(dirname "$0")/../../.." && pwd)
BUILD=${1:-/tmp/lf_build}
FLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -O1 -g"
mkdir -p "$BUILD" && cd "$BUILD"
[ -f Makefile ] || CC=clang-14 CXX=clang++-14 cmake "$SRC" -DCMAKE_BUILD_TYPE=Debug -Denable_thread=1 \
    -DCMAKE_C_FLAGS="$FLAGS" -DCMAKE_CXX_FLAGS="$FLAGS"
make -j"$(nproc)" lib-swoole
clang++-14 -std=c++14 $FLAGS -fsanitize=fuzzer -I"$SRC" -I"$SRC/include" -I"$SRC/thirdparty" \
    "$SRC/scripts/fuzz/libfuzzer/parsers.cc" -L"$SRC/lib" -lswoole -Wl,-rpath,"$SRC/lib" -lssl -lcrypto -lpthread \
    -o "$BUILD/parsers_fuzz"
