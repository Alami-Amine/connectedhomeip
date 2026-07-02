# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# ASAN + libFuzzer build of connectedhomeip's minimal mDNS wire parsers.
# Heavy: the chip-build base + the in-tree pigweed/cipd bootstrap (clang, gn,
# ninja) and submodule checkout pull several GB and take 20-40 min on a cold
# build. The resulting binaries are plain libFuzzer executables that replay a
# single input file (./binary <file>) under AddressSanitizer — exactly the
# pipeline's contract.

# chip-build version pinned by the target commit
# (integrations/docker/images/base/chip-build/version == 202).
FROM ghcr.io/project-chip/chip-build:202

# Pin exactly what was tested. d27ba35548 lives on the fork branch
# AA/msan-fuzz-fixes; the minimal_mdns parsers it builds are unchanged from
# upstream project-chip/connectedhomeip. Override with --build-arg to retarget.
ARG CHIP_REPO=https://github.com/Alami-Amine/connectedhomeip
ARG CHIP_COMMIT=d27ba35548f6c18f55c37d6393ade53dd18d0b20

# Agent tooling for crafting inputs (gdb + python3 ship in chip-build).
RUN apt-get update && \
    apt-get install -y --no-install-recommends xxd file && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
RUN git clone --filter=blob:none "${CHIP_REPO}" /work/connectedhomeip && \
    cd /work/connectedhomeip && \
    git checkout "${CHIP_COMMIT}" && \
    scripts/checkout_submodules.py --shallow --platform linux

# Drop the raw-byte harnesses in and wire them into GN.
COPY harness /harness
RUN bash /harness/install_harnesses.sh /work/connectedhomeip /harness

# Bootstrap the in-tree env (cipd: clang/gn/ninja) and build only our two
# fuzz targets. enable_fuzz_test_targets is implied by is_libfuzzer.
RUN cd /work/connectedhomeip && \
    bash -c "source scripts/activate.sh && \
      gn gen out/fuzz --args='is_libfuzzer=true is_clang=true chip_build_tests=true' && \
      ninja -C out/fuzz \
        src/lib/dnssd/minimal_mdns/tests:vp-fuzz-minmdns-parsers \
        src/lib/dnssd/tests:vp-fuzz-dnssd-txt-fields \
        src/lib/dnssd/tests:vp-fuzz-mdns-resolver"

# Primary entry: the combined wire-parser harness (packet + qname + records).
# The TXT-fields binary lives alongside it at
#   out/fuzz/tests/vp-fuzz-dnssd-txt-fields
RUN ln -s /work/connectedhomeip/out/fuzz/tests/vp-fuzz-minmdns-parsers /work/entry

CMD ["/bin/bash"]
