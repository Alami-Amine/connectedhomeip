// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0
//
// Raw-byte libFuzzer harness for FillNodeDataFromTxt — the DNS-SD TXT
// key/value parser that populates CommonResolutionData / CommissionNodeData
// during operational and commissionable-node discovery. Reachable from any
// mDNS responder on the local link, so every byte is attacker-controlled.
//
// Pipeline-native sibling of the FuzzTest harness FuzzTxtFieldsPW (which uses
// two typed string domains). Here a single flat input is split into a (key,
// value) pair with the framing the libFuzzer original used:
//
//     [keylen : 1 byte][key : keylen bytes][value : remaining bytes]
//
// so a crafted file maps directly to one parse. The numeric parsers
// (strtoul + range clamps), the rotating-device-id hex decode (a length-bound
// OOB-write canary), and the fixed-size deviceName / pairingInstruction copies
// are the crash sinks this stresses. ASAN/UBSan no-crash is the floor; the
// FuzzTest invariant oracles are intentionally not ported here.

#include <cstddef>
#include <cstdint>

#include <lib/dnssd/Resolver.h>
#include <lib/dnssd/TxtFields.h>
#include <lib/dnssd/Types.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/Span.h>

namespace {

using namespace chip;
using namespace chip::Dnssd;

void EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    (void) sInitialized;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    if (len == 0)
    {
        return 0;
    }

    EnsureInitialized();

    // [keylen][key][value]. keylen is clamped to what is actually available so
    // a short buffer still yields a well-formed (possibly empty-value) pair.
    size_t keyLen           = data[0];
    const uint8_t * rest    = data + 1;
    const size_t restLen    = len - 1;
    keyLen                  = (keyLen <= restLen) ? keyLen : restLen;
    const ByteSpan key      = ByteSpan(rest, keyLen);
    const ByteSpan value    = ByteSpan(rest + keyLen, restLen - keyLen);

    // Both overloads: the common (operational) path and the commission path,
    // which also reaches the commission-only arms (D/VP/CM/DT/DN/RI/PI/...).
    {
        CommonResolutionData common;
        FillNodeDataFromTxt(key, value, common);
    }
    {
        CommissionNodeData commission;
        FillNodeDataFromTxt(key, value, commission);
    }

    return 0;
}
