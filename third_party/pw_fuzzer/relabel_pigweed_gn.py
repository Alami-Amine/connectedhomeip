#!/usr/bin/env python3
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

"""Import Pigweed-layout FuzzTest and Abseil GN wrappers into this directory.

The source is any tree laid out like Pigweed's `third_party/{fuzztest,abseil-cpp}`:
a Pigweed checkout from before the removal (c14c119c5), or the output of
Pigweed's `pw_build/py/pw_build/bazel_to_gn.py` run against newer FuzzTest and
Abseil releases. Only the label roots and the two source-directory build args
are renamed; the files are otherwise copied unchanged.
"""

import argparse
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
LIBRARIES = ("fuzztest", "abseil-cpp")
SUBSTITUTIONS = [
    (re.compile(r"\$pw_external_fuzztest\b"), "//third_party/pw_fuzzer/fuzztest"),
    (re.compile(r"\$pw_external_abseil_cpp\b"), "//third_party/pw_fuzzer/abseil-cpp"),
    (re.compile(r"\bdir_pw_third_party_fuzztest\b"), "chip_fuzztest_dir"),
    (re.compile(r"\bdir_pw_third_party_abseil_cpp\b"), "chip_abseil_cpp_dir"),
]
UNSUBSTITUTED = re.compile(r"pw_external_(fuzztest|abseil_cpp)|dir_pw_third_party_(fuzztest|abseil_cpp)")


def relabel(source_root: pathlib.Path) -> list[pathlib.Path]:
    """Replace ./fuzztest and ./abseil-cpp with relabelled copies from source_root."""
    written = []
    for lib in LIBRARIES:
        src_dir = source_root / "third_party" / lib
        dst_dir = HERE / lib
        if not src_dir.is_dir():
            sys.exit(f"{src_dir} not found")
        shutil.rmtree(dst_dir, ignore_errors=True)
        for src in sorted(src_dir.rglob("*.gn*")):
            text = src.read_text()
            for pattern, replacement in SUBSTITUTIONS:
                text = pattern.sub(replacement, text)
            if UNSUBSTITUTED.search(text):
                sys.exit(f"{src}: unhandled Pigweed label or build arg")
            dst = dst_dir / src.relative_to(src_dir)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(text)
            written.append(dst)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pigweed", type=pathlib.Path, default=HERE.parent / "pigweed" / "repo",
                        help="root of a Pigweed-layout tree (default: the pigweed submodule)")
    args = parser.parse_args()
    written = relabel(args.pigweed.resolve())
    subprocess.run(["gn", "format", *map(str, written)], check=True, stdout=subprocess.DEVNULL)
    print(f"wrote {len(written)} files under {HERE}")


if __name__ == "__main__":
    main()
