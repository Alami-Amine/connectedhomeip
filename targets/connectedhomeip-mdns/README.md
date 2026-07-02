# connectedhomeip-mdns

Execution-verified fuzzing target for **Matter (connectedhomeip)** minimal mDNS
wire parsing — the DNS-SD discovery path that any host on the local link can
drive with unauthenticated mDNS replies, before any PASE/CASE session exists.
One of the earliest-reachable untrusted-input surfaces on a Matter device.

## Why a harness and not the app

connectedhomeip is a network daemon, not a file parser. The pipeline's contract
is `binary <file>` → parse raw bytes → ASAN abort. So this target does **not**
run a Matter app; it builds thin **raw-byte libFuzzer harnesses** that feed a
file straight into the same parse entry points the network receive path uses.
A crafted file on disk is a crafted mDNS packet on the wire.

These are the pipeline-native siblings of the FuzzTest (`pw_fuzzer`) harnesses
on the `AA/NewFuzzersV2` branch. FuzzTest binaries deserialize their input
through a typed-domain corpus encoding, so a `-compat` binary would not see a
crafted file as a raw packet — the find-agent's whole mental model is raw
bytes, so we reuse the *parse functions*, not the FuzzTest wrappers. The
FuzzTest invariant oracles (`ASSERT_*`) are intentionally dropped: this target
hunts memory-safety crashes (the ASAN floor), which is what the pipeline
verifies.

## Surfaces

| Binary | Sibling target | Entry points | Input |
|---|---|---|---|
| `vp-fuzz-minmdns-parsers` (primary, `/work/entry`) | — | `ParsePacket` (⊃ SRV/A/AAAA/PTR), `SerializedQNameIterator` swept from every offset, `ParseTxtRecord` | raw mDNS packet |
| `vp-fuzz-dnssd-txt-fields` | `connectedhomeip-mdns-txt` | `FillNodeDataFromTxt` (numeric clamps, rotating-id hex, fixed-buffer copies) | `[keylen:1][key][value]` |
| `vp-fuzz-mdns-resolver` | `connectedhomeip-mdns-resolver` | `IncrementalResolver` lifecycle SRV→TXT→A/AAAA into NodeData fill sinks | flat buffer split into typed args |

All three binaries are built into the **one** image; each sibling target just
repoints `/work/entry`.

## Running

```bash
# Primary (packet + qname + records). Heavy first build: ~20-40 min, multi-GB
# image (chip-build base + in-tree cipd/pigweed bootstrap + submodules).
vuln-pipeline run targets/connectedhomeip-mdns --runs 3 --parallel --stream --model <m>

# TXT-fields / resolver surfaces (build the primary image first — siblings FROM it).
vuln-pipeline run targets/connectedhomeip-mdns-txt --runs 3 --parallel --stream --model <m>
vuln-pipeline run targets/connectedhomeip-mdns-resolver --runs 3 --parallel --stream --model <m>
```

## Pinning

Pinned to `Alami-Amine/connectedhomeip@d27ba35548` (branch `AA/msan-fuzz-fixes`)
— the exact tree the harnesses were verified against. The minimal_mdns parsers
there are unchanged from upstream `project-chip/connectedhomeip`. Retarget with
`--build-arg CHIP_REPO=… --build-arg CHIP_COMMIT=…`.

## How it was built

`harness/install_harnesses.sh` copies the two `.cpp` files into the chip tree
and appends `chip_fuzz_target` stanzas to the two `BUILD.gn` files (append-based
and idempotent, so it tolerates upstream line changes). The Dockerfile then
`gn gen --args='is_libfuzzer=true is_clang=true chip_build_tests=true'` and
`ninja`s just the three targets. The resolver harness ports the FuzzTest
record-builder scaffolding (`WireRecord` / `QNameHolder`) and fronts it with a
small self-contained byte splitter (no `FuzzedDataProvider` dependency).
Verified locally at ~63k exec/s (parsers), ~235k exec/s (txt-fields), and
~15k exec/s (resolver), ASAN live, no harness-side crashes.
