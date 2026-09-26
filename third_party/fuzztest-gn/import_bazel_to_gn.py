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

"""Import generated FuzzTest and Abseil BUILD.gn files into this directory.

The source is any tree laid out like Pigweed's `third_party/{fuzztest,abseil-cpp}`:
a Pigweed checkout from before its GN FuzzTest support was removed (c14c119c5),
or the output of Pigweed's `pw_build/py/pw_build/bazel_to_gn.py` run against
newer FuzzTest and Abseil releases. Only BUILD.gn files are imported; the
templates in fuzztest.gni and abseil-cpp.gni and the googletest build are
maintained here. Labels are rewritten so nothing refers to Pigweed.
"""

import argparse
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
LIBRARIES = ("fuzztest", "abseil-cpp")
SUBSTITUTIONS = [
    (re.compile(r'import\("//build_overrides/pigweed\.gni"\)\n\n'), ""),
    (re.compile(r"\$pw_external_fuzztest\b"), "//third_party/fuzztest-gn/fuzztest"),
    (re.compile(r"\$pw_external_abseil_cpp\b"), "//third_party/fuzztest-gn/abseil-cpp"),
    (re.compile(r"\$pw_external_googletest\b"), "//third_party/fuzztest-gn/googletest"),
    (re.compile(r"\bdir_pw_third_party_fuzztest\b"), "chip_fuzztest_dir"),
    (re.compile(r"\bdir_pw_third_party_abseil_cpp\b"), "chip_abseil_cpp_dir"),
]
PIGWEED_REFERENCE = re.compile(r"\$dir_pw|\$pw_|dir_pw_third_party|pigweed\.gni")


def import_build_files(source_root: pathlib.Path) -> list[pathlib.Path]:
    """Replace the BUILD.gn files under ./fuzztest and ./abseil-cpp with rewritten copies."""
    written = []
    for lib in LIBRARIES:
        src_dir = source_root / "third_party" / lib
        dst_dir = HERE / lib
        if not src_dir.is_dir():
            sys.exit(f"{src_dir} not found")
        for stale in dst_dir.rglob("BUILD.gn"):
            stale.unlink()
        for src in sorted(src_dir.rglob("BUILD.gn")):
            text = src.read_text()
            for pattern, replacement in SUBSTITUTIONS:
                text = pattern.sub(replacement, text)
            if PIGWEED_REFERENCE.search(text):
                sys.exit(f"{src}: unhandled Pigweed reference")
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
    written = import_build_files(args.pigweed.resolve())
    subprocess.run(["gn", "format", *map(str, written)], check=True, stdout=subprocess.DEVNULL)
    print(f"wrote {len(written)} files under {HERE}")


if __name__ == "__main__":
    main()
