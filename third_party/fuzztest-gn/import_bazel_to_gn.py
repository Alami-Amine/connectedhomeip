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

To move to new FuzzTest / Abseil releases:
  1. Set the versions in bazel_to_gn/workspace/MODULE.bazel, and move the
     third_party/fuzztest and third_party/abseil-cpp/src submodules to match.
  2. Generate (needs bazelisk on PATH):
       python3 bazel_to_gn/bazel_to_gn.py -r bazel_to_gn/workspace fuzztest
  3. Import: python3 import_bazel_to_gn.py

bazel_to_gn/ holds Pigweed's generator (pw_build/py/pw_build) with Bazel 8
canonical-label support added. Only generated BUILD.gn files are imported;
the top-level BUILD.gn of each library, the .gni templates and googletest/
are maintained here. Labels are rewritten so nothing refers to Pigweed.
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
# Bazel resolves copts for the host that ran the generator (e.g. -maes on
# x86_64), so only warning suppressions are kept; the configs here set the rest.
GENERATED_CFLAGS = re.compile(r"(?ms)^  cflags = \[\n(.*?)^  \]\n|^  cflags = \[([^\n]*)\]\n")


def keep_warning_suppressions(match: re.Match) -> str:
    flags = [f for f in re.findall(r'"([^"]+)"', match.group(1) or match.group(2)) if f.startswith("-Wno-")]
    if not flags:
        return ""
    quoted = ", ".join('"' + f + '"' for f in flags)
    return "  cflags = [ " + quoted + " ]\n"


def import_build_files(source_root: pathlib.Path) -> list[pathlib.Path]:
    """Replace the BUILD.gn files under ./fuzztest and ./abseil-cpp with rewritten copies."""
    written = []
    for lib in LIBRARIES:
        src_dir = source_root / "third_party" / lib
        dst_dir = HERE / lib
        if not src_dir.is_dir():
            sys.exit(f"{src_dir} not found")
        for stale in dst_dir.rglob("BUILD.gn"):
            if stale.parent != dst_dir:
                stale.unlink()
        for src in sorted(src_dir.rglob("BUILD.gn")):
            if src.parent == src_dir:
                continue
            text = src.read_text()
            for pattern, replacement in SUBSTITUTIONS:
                text = pattern.sub(replacement, text)
            text = GENERATED_CFLAGS.sub(keep_warning_suppressions, text)
            if PIGWEED_REFERENCE.search(text):
                sys.exit(f"{src}: unhandled Pigweed reference")
            dst = dst_dir / src.relative_to(src_dir)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(text)
            written.append(dst)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=pathlib.Path, default=HERE / "bazel_to_gn" / "workspace",
                        help="bazel_to_gn.py root holding third_party/{fuzztest,abseil-cpp} (default: %(default)s)")
    args = parser.parse_args()
    written = import_build_files(args.source.resolve())
    subprocess.run(["gn", "format", *map(str, written)], check=True, stdout=subprocess.DEVNULL)
    print(f"wrote {len(written)} files under {HERE}")


if __name__ == "__main__":
    main()
