# FuzzTest GN build

GN build for [Google FuzzTest](https://github.com/google/fuzztest) and [Abseil](https://github.com/abseil/abseil-cpp), used by the FuzzTest toolchain (`//build/toolchain/pw_fuzzer:chip_pw_fuzztest`). Pigweed used to provide these files and dropped them in pigweed `0b14c78f6`. Nothing here depends on Pigweed.

| Path | Contents |
| --- | --- |
| `repo/` | FuzzTest submodule |
| `fuzztest/`, `common/` | Generated `BUILD.gn` files (do not edit) |
| `BUILD.gn`, `fuzztest.gni` | Maintained by hand |
| `googletest/` | GoogleTest for the FuzzTest toolchain |
| `bazel_to_gn/` | The generator (from Pigweed's `pw_build`) and the Bazel workspace it queries |
| `import_bazel_to_gn.py` | Copies the generated files into place and rewrites their labels |
| `../abseil-cpp/` | Abseil: `src/` submodule, generated `absl/**/BUILD.gn`, hand-maintained `BUILD.gn` and `abseil-cpp.gni` |

## Updating FuzzTest and Abseil

The generated files list source files explicitly, so they must match the submodule revisions.

1. Set the new versions in `bazel_to_gn/workspace/MODULE.bazel`.
2. Move the `repo/` and `../abseil-cpp/src` submodules to the same releases.
3. From this directory, with `bazelisk` on `PATH`:
   ```
   python3 bazel_to_gn/bazel_to_gn.py -r bazel_to_gn/workspace fuzztest
   python3 import_bazel_to_gn.py
   ```
4. Build `linux-x64-tests-clang-pw-fuzztest-ossfuzz` and run the fuzz tests.

If Bazel reports an Abseil compatibility-level conflict, add `single_version_override(module_name = "abseil-cpp", version = "<version>")` to `MODULE.bazel`.

Generated compiler flags other than `-Wno-*` are dropped on import, because Bazel resolves them for the machine that ran the generator.

## What still comes from Pigweed

FuzzTest itself uses nothing from Pigweed. The fuzz binaries still link Pigweed through the rest of Matter: `pw_unit_test` (Matter's test helpers), `pw_log` and `pw_assert` (`src/pw_backends`), and `pw_string`. The toolchain points `pw_unit_test` at `googletest/`, so each binary links a single GoogleTest.
