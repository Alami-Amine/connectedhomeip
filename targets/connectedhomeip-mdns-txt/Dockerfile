# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# Thin sibling of the connectedhomeip-mdns target: reuses the heavy image built
# there and just repoints the entry symlink at the TXT-fields harness. Build
# the primary target first so vuln-pipeline-chip-mdns:latest exists.
FROM vuln-pipeline-chip-mdns:latest

RUN rm -f /work/entry && \
    ln -s /work/connectedhomeip/out/fuzz/tests/vp-fuzz-dnssd-txt-fields /work/entry

CMD ["/bin/bash"]
