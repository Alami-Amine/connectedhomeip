#!/usr/bin/env bash
#
# Copyright (c) 2026 Project CHIP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds a chip::Optional / DataModel::Nullable-aware clang-tidy.
#
# clang-tidy's bundled `bugprone-unchecked-optional-access` dataflow model only
# understands std/absl/bsl optional. chip-optional-model.patch teaches it about
# chip::Optional and chip::app::DataModel::Nullable. We build clang-tidy from the
# exact LLVM commit the Pigweed clang on PATH was built from, so the result is
# behaviour-compatible with the toolchain that compiles the tree.
#
# Idempotent: if the output binary already exists (e.g. restored from CI cache),
# this is a fast no-op. Prints the binary path as the last line of stdout.
#
# Prerequisites: Pigweed clang on PATH (source scripts/activate.sh /
# scripts/run_in_build_env.sh), plus cmake + ninja + git (in chip-build image).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$HERE/chip-optional-model.patch"

# Output + work locations. Default under the workspace so CI `actions/cache` can
# persist OUT_BIN keyed on the patch hash + toolchain image.
OUT_DIR="${CHIP_OPTIONAL_CLANG_TIDY_DIR:-$PWD/.cache/chip-optional-clang-tidy}"
OUT_BIN="$OUT_DIR/clang-tidy"
SRC_DIR="$OUT_DIR/llvm-project"
BUILD_DIR="$OUT_DIR/build"

mkdir -p "$OUT_DIR"

log() { echo ">>> $*" >&2; }

# Fast path: cache hit.
if [[ -x "$OUT_BIN" ]]; then
    log "patched clang-tidy already present, skipping build"
    "$OUT_BIN" --version | sed -n '1,2p' >&2
    echo "$OUT_BIN"
    exit 0
fi

[[ -f "$PATCH" ]] || {
    echo "ERROR: patch not found: $PATCH" >&2
    exit 1
}

PW_CLANG="$(command -v clang || true)"
[[ -x "$PW_CLANG" ]] || {
    echo "ERROR: clang not on PATH (run scripts/run_in_build_env.sh / activate.sh)" >&2
    exit 1
}

# The Pigweed/Fuchsia clang embeds its 40-char LLVM commit in --version. Build
# from that exact commit so the patched clang-tidy matches the toolchain.
LLVM_COMMIT="$("$PW_CLANG" --version | grep -oE '[0-9a-f]{40}' | head -1 || true)"
[[ -n "$LLVM_COMMIT" ]] || {
    echo "ERROR: could not read LLVM commit from 'clang --version'" >&2
    "$PW_CLANG" --version >&2
    exit 1
}
log "toolchain LLVM commit: $LLVM_COMMIT"

# Shallow-fetch just that commit.
if [[ ! -d "$SRC_DIR/.git" ]]; then
    git init -q "$SRC_DIR"
    git -C "$SRC_DIR" remote add origin https://llvm.googlesource.com/llvm-project
fi
log "fetching llvm-project @ $LLVM_COMMIT (shallow)"
git -C "$SRC_DIR" fetch --depth 1 origin "$LLVM_COMMIT"
git -C "$SRC_DIR" checkout -q --force FETCH_HEAD

# Apply the model patch to a pristine tree (checkout --force above ensures clean).
log "applying $PATCH"
git -C "$SRC_DIR" apply --verbose "$PATCH"

# Build a single static Release clang-tidy (one cacheable binary, no shared libs).
# X86 host target only; lld + ccache to keep the build cheap/low-RAM.
log "configuring + building clang-tidy (this is the slow, cached step)"
cmake -G Ninja -S "$SRC_DIR/llvm" -B "$BUILD_DIR" \
    -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_ASSERTIONS=OFF \
    -DLLVM_TARGETS_TO_BUILD=X86 \
    -DLLVM_USE_LINKER=lld \
    -DLLVM_CCACHE_BUILD=ON \
    -DLLVM_PARALLEL_LINK_JOBS=2 \
    -DLLVM_OPTIMIZED_TABLEGEN=ON \
    -DLLVM_ENABLE_WERROR=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DLLVM_INCLUDE_EXAMPLES=OFF \
    -DLLVM_INCLUDE_BENCHMARKS=OFF \
    -DCLANG_INCLUDE_TESTS=OFF
ninja -C "$BUILD_DIR" clang-tidy

cp "$BUILD_DIR/bin/clang-tidy" "$OUT_BIN"
log "built: $OUT_BIN"
"$OUT_BIN" --version | sed -n '1,2p' >&2

# Last stdout line = the binary path (callers capture this).
echo "$OUT_BIN"
