# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# Thin sibling of the connectedhomeip-mdns target: reuses the heavy image and
# repoints the entry symlink at the IncrementalResolver lifecycle harness.
# Build the primary target first so vuln-pipeline-chip-mdns:latest exists.
FROM vuln-pipeline-chip-mdns:latest

RUN rm -f /work/entry && \
    ln -s /work/connectedhomeip/out/fuzz/tests/vp-fuzz-mdns-resolver /work/entry

CMD ["/bin/bash"]
