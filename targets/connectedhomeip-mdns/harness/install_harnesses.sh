#!/usr/bin/env bash
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# Installs the raw-byte libFuzzer mDNS harnesses into a connectedhomeip
# checkout and wires them into GN. Append-based and idempotent, so it tolerates
# the exact surrounding lines of the upstream BUILD.gn files changing across
# commits.
#
#   usage: install_harnesses.sh <chip_root> <harness_dir>
set -euo pipefail

CHIP_ROOT="${1:?chip_root required}"
HARNESS_DIR="${2:?harness_dir required}"

MINMDNS_TESTS="$CHIP_ROOT/src/lib/dnssd/minimal_mdns/tests"
DNSSD_TESTS="$CHIP_ROOT/src/lib/dnssd/tests"

cp "$HARNESS_DIR/VpFuzzMdnsParsers.cpp" "$MINMDNS_TESTS/VpFuzzMdnsParsers.cpp"
cp "$HARNESS_DIR/VpFuzzTxtFields.cpp" "$DNSSD_TESTS/VpFuzzTxtFields.cpp"
cp "$HARNESS_DIR/VpFuzzMdnsResolver.cpp" "$DNSSD_TESTS/VpFuzzMdnsResolver.cpp"

# minimal_mdns/tests already imports fuzz_test.gni (it ships the upstream
# fuzz-minmdns-packet-parsing target), so only the stanza is appended.
if ! grep -q 'vp-fuzz-minmdns-parsers' "$MINMDNS_TESTS/BUILD.gn"; then
  cat >> "$MINMDNS_TESTS/BUILD.gn" <<'GN'

if (enable_fuzz_test_targets) {
  chip_fuzz_target("vp-fuzz-minmdns-parsers") {
    sources = [ "VpFuzzMdnsParsers.cpp" ]
    public_deps = [
      "${chip_root}/src/lib/dnssd/minimal_mdns",
      "${chip_root}/src/platform/logging:default",
    ]
  }
}
GN
fi

# dnssd/tests does not import fuzz_test.gni upstream; add the import once
# (import precedes its use, so appending it ahead of the stanzas is valid GN).
if ! grep -q 'build/chip/fuzz_test.gni' "$DNSSD_TESTS/BUILD.gn"; then
  printf '\nimport("${chip_root}/build/chip/fuzz_test.gni")\n' >> "$DNSSD_TESTS/BUILD.gn"
fi
if ! grep -q 'vp-fuzz-dnssd-txt-fields' "$DNSSD_TESTS/BUILD.gn"; then
  cat >> "$DNSSD_TESTS/BUILD.gn" <<'GN'

if (enable_fuzz_test_targets) {
  chip_fuzz_target("vp-fuzz-dnssd-txt-fields") {
    sources = [ "VpFuzzTxtFields.cpp" ]
    public_deps = [
      "${chip_root}/src/lib/dnssd",
      "${chip_root}/src/platform/logging:default",
    ]
  }
}
GN
fi
if ! grep -q 'vp-fuzz-mdns-resolver' "$DNSSD_TESTS/BUILD.gn"; then
  cat >> "$DNSSD_TESTS/BUILD.gn" <<'GN'

if (enable_fuzz_test_targets) {
  chip_fuzz_target("vp-fuzz-mdns-resolver") {
    sources = [ "VpFuzzMdnsResolver.cpp" ]
    public_deps = [
      "${chip_root}/src/lib/dnssd",
      "${chip_root}/src/lib/dnssd/minimal_mdns",
      "${chip_root}/src/platform/logging:default",
    ]
  }
}
GN
fi

echo "harnesses installed"
